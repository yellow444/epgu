"""Тесты мастера настройки: почта и источники сертификатов."""

import importlib

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture()
def modules(tmp_path, monkeypatch):
    monkeypatch.setenv("MAIL_INBOX_DIR", str(tmp_path / "mail"))
    monkeypatch.setenv("CERT_INBOX_DIR", str(tmp_path / "mail"))
    monkeypatch.delenv("MAIL_IMAP_HOST", raising=False)
    monkeypatch.delenv("MAIL_SMTP_HOST", raising=False)
    monkeypatch.delenv("MAIL_USER", raising=False)
    monkeypatch.setenv("MAIL_PASSWORD", "app-password-should-never-leak")
    monkeypatch.setenv("SECRET_PROVIDER", "env")

    import secret_store
    import mailbox
    import certsources
    import setup_api

    for module in (secret_store, mailbox, certsources, setup_api):
        importlib.reload(module)
    return secret_store, mailbox, certsources, setup_api


@pytest.fixture()
def client(modules):
    _, _, _, setup_api = modules
    app = FastAPI()
    app.include_router(setup_api.setup_router())
    with TestClient(app) as test_client:
        yield test_client


def test_config_never_returns_the_password(client):
    response = client.get("/mail/config")
    assert response.status_code == 200
    body = response.text
    assert "app-password-should-never-leak" not in body
    payload = response.json()
    assert payload["password"]["configured"] is True
    assert payload["password"]["length"] == len("app-password-should-never-leak")
    assert "value" not in payload["password"]


def test_secret_description_hides_the_value(modules):
    secret_store, _, _, _ = modules
    described = secret_store.describe("MAIL_PASSWORD")
    assert described["configured"] is True
    assert "app-password-should-never-leak" not in str(described)


def test_runtime_secret_overrides_environment_and_can_be_cleared(modules):
    secret_store, _, _, _ = modules
    secret_store.set_runtime_secret("MAIL_PASSWORD", "typed-in-ui")
    assert secret_store.get_secret("MAIL_PASSWORD") == "typed-in-ui"
    assert secret_store.describe("MAIL_PASSWORD")["source"] == "память процесса"
    secret_store.clear_runtime_secrets()
    assert secret_store.get_secret("MAIL_PASSWORD") == "app-password-should-never-leak"


def test_check_without_configuration_is_rejected(client):
    assert client.post("/mail/check").status_code == 400


def test_send_without_smtp_reports_upstream_failure(client):
    response = client.post(
        "/mail/send",
        json={"to": "sd@sc.digital.gov.ru", "subject": "Тест", "body": "Текст"},
    )
    assert response.status_code == 502
    assert "SMTP" in response.json()["detail"]


def test_attachment_names_cannot_escape_the_folder(modules):
    _, mailbox, _, _ = modules
    # От пути остаётся только имя файла, каталоги отбрасываются целиком.
    assert mailbox.safe_attachment_name("../../etc/passwd", 0) == "passwd"
    assert mailbox.safe_attachment_name("C:\\Windows\\system32\\evil.dll", 1).endswith("evil.dll")
    assert mailbox.safe_attachment_name(None, 3) == "attachment-3"
    assert "/" not in mailbox.safe_attachment_name("a/b/c.cer", 0)


def test_network_errors_name_the_actual_reason(modules):
    _, mailbox, _, _ = modules
    import socket
    import ssl

    dns = mailbox.describe_network_error(socket.gaierror(-2, "nope"), "imap.wrong.ru", 993)
    assert "не разрешается" in dns and "imap.wrong.ru" in dns

    refused = mailbox.describe_network_error(ConnectionRefusedError(), "mail.ru", 993)
    assert "отклонил соединение" in refused and "993" in refused

    timed_out = mailbox.describe_network_error(socket.timeout(), "mail.ru", 993)
    assert "не ответил" in timed_out

    tls = mailbox.describe_network_error(ssl.SSLError(), "mail.ru", 143)
    assert "TLS" in tls

    # Ни в одном тексте нет ни логина, ни пароля: только хост и порт.
    for text in (dns, refused, timed_out, tls):
        assert "@" not in text


def test_watched_addresses_cover_the_support_domains(modules):
    _, mailbox, _, _ = modules
    assert "sc.digital.gov.ru" in mailbox.WATCHED_DOMAINS
    assert "gosuslugi.ru" in mailbox.WATCHED_DOMAINS


def test_folder_scan_reports_missing_directory(client):
    payload = client.get("/certsources").json()
    assert payload["folder"]["exists"] is False
    assert payload["folder"]["files"] == []
    assert isinstance(payload["usb_guide"], list) and payload["usb_guide"]


def test_folder_scan_lists_certificates_and_containers(client, modules, tmp_path):
    _, _, certsources, _ = modules
    folder = certsources.cert_dir()
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "org.cer").write_bytes(b"cert-bytes")
    container = folder / "keys.000"
    container.mkdir()
    (container / "header.key").write_bytes(b"")

    payload = client.get("/certsources").json()["folder"]
    assert [item["name"] for item in payload["files"]] == ["org.cer"]
    assert payload["containers"][0]["name"] == "keys.000"
    assert payload["containers"][0]["empty"] is True


def test_import_outside_the_folder_is_refused(client, tmp_path):
    outsider = tmp_path / "outside.cer"
    outsider.write_bytes(b"cert")
    response = client.post(
        "/certsources/import", json={"path": str(outsider), "store": "uMy"}
    )
    assert response.status_code == 400
    assert "каталога сертификатов" in response.json()["detail"]


def test_import_rejects_unknown_store(client, modules):
    _, _, certsources, _ = modules
    folder = certsources.cert_dir()
    folder.mkdir(parents=True, exist_ok=True)
    target = folder / "org.cer"
    target.write_bytes(b"cert")
    response = client.post(
        "/certsources/import", json={"path": str(target), "store": "../../etc"}
    )
    assert response.status_code in {400, 503}


# ---------- Вложения писем одним списком ----------


def configure_mail(modules, monkeypatch, attachments_by_letter):
    """Ящик, который отвечает заранее заданными письмами."""
    _, mailbox, _, _ = modules
    monkeypatch.setenv("MAIL_IMAP_HOST", "imap.example.org")
    monkeypatch.setenv("MAIL_SMTP_HOST", "smtp.example.org")
    monkeypatch.setenv("MAIL_USER", "smev@example.org")

    def fake_fetch(config, **kwargs):
        return {"messages": attachments_by_letter, "total": len(attachments_by_letter)}

    monkeypatch.setattr(mailbox, "fetch_messages", fake_fetch)


LETTER = {
    "uid": "42",
    "ticket": "6451421",
    "subject": "Запрос тестового сертификата для ИС TESTEP",
    "from": "sd@sc.digital.gov.ru",
    "received_at": "2026-08-20T17:32:10",
    "attachments": [
        {"index": 0, "name": "org.cer", "size": 900, "content_type": "application/x-x509-ca-cert", "too_large": False},
        {"index": 1, "name": "keys.zip", "size": 4000, "content_type": "application/zip", "too_large": False},
        {"index": 2, "name": "instrukciya.pdf", "size": 120000, "content_type": "application/pdf", "too_large": False},
    ],
}


def test_attachments_are_listed_with_their_letter(client, modules, monkeypatch):
    configure_mail(modules, monkeypatch, [LETTER])

    payload = client.get("/mail/attachments").json()

    assert payload["configured"] is True
    names = [item["name"] for item in payload["attachments"]]
    assert names == ["org.cer", "keys.zip", "instrukciya.pdf"]
    kinds = [item["kind"] for item in payload["attachments"]]
    assert kinds == ["certificate", "archive", "pdf"]
    assert all(item["ticket"] == "6451421" for item in payload["attachments"])
    assert all(item["uid"] == "42" for item in payload["attachments"])


def test_already_saved_attachments_are_marked(client, modules, monkeypatch):
    _, _, certsources, _ = modules
    configure_mail(modules, monkeypatch, [LETTER])
    certsources.cert_dir().mkdir(parents=True, exist_ok=True)
    (certsources.cert_dir() / "org.cer").write_bytes(b"cert")

    payload = client.get("/mail/attachments").json()["attachments"]

    assert [item["saved"] for item in payload] == [True, False, False]


def test_attachments_without_mailbox_do_not_fail(client):
    payload = client.get("/mail/attachments").json()
    assert payload == {"configured": False, "attachments": []}


def test_collect_takes_documents_too_but_not_junk(client, modules, monkeypatch):
    _, mailbox, certsources, _ = modules
    letter = dict(LETTER)
    letter["attachments"] = LETTER["attachments"] + [
        {"index": 3, "name": "logo.png", "size": 900, "content_type": "image/png", "too_large": False}
    ]
    configure_mail(modules, monkeypatch, [letter])
    saved_calls = []

    def fake_save(config, *, uid, index, target_dir=None):
        saved_calls.append((uid, index, str(target_dir) if target_dir else ""))
        return {"saved": True, "name": "file-%d" % index, "path": "/tmp/file", "size": 10}

    monkeypatch.setattr(mailbox, "save_attachment", fake_save)

    payload = client.post("/mail/attachments/collect").json()

    # Инструкцию в PDF забираем: ключевой контейнер присылают внутри неё.
    assert [call[1] for call in saved_calls] == [0, 1, 2]
    assert len(payload["saved"]) == 3
    assert any("logo.png" in line for line in payload["skipped"])


def test_key_container_goes_to_the_keys_folder(client, modules, monkeypatch):
    _, mailbox, certsources, _ = modules
    letter = dict(LETTER)
    letter["attachments"] = [
        {"index": 0, "name": "primary.key", "size": 100, "content_type": "application/octet-stream", "too_large": False}
    ]
    configure_mail(modules, monkeypatch, [letter])
    targets = []

    def fake_save(config, *, uid, index, target_dir=None):
        targets.append(str(target_dir) if target_dir else "")
        return {"saved": True, "name": "primary.key", "path": "/tmp/primary.key", "size": 100}

    monkeypatch.setattr(mailbox, "save_attachment", fake_save)

    client.post("/mail/attachments/collect")

    assert targets == [str(certsources.keys_dir())]


def test_saving_one_attachment_honours_the_target(client, modules, monkeypatch):
    _, mailbox, certsources, _ = modules
    configure_mail(modules, monkeypatch, [LETTER])
    seen = {}

    def fake_save(config, *, uid, index, target_dir=None):
        seen["target"] = str(target_dir) if target_dir else ""
        return {"saved": True, "name": "primary.key", "path": "/tmp/x", "size": 1}

    monkeypatch.setattr(mailbox, "save_attachment", fake_save)

    body = client.post("/mail/messages/42/attachments/0/save?target=keys").json()

    assert seen["target"] == str(certsources.keys_dir())
    assert body["target"] == "keys"


def test_unknown_target_is_refused(client, modules, monkeypatch):
    configure_mail(modules, monkeypatch, [LETTER])
    assert client.post("/mail/messages/42/attachments/0/save?target=/etc").status_code == 422


# ---------- Имена вложений, ответы, просмотр ----------


def test_cyrillic_attachment_keeps_its_extension(modules):
    _, mailbox, _, _ = modules

    name = mailbox.safe_attachment_name("Инструкция по получению.pdf", 0)

    assert name.endswith(".pdf")
    assert name.lower().startswith("instrukciya")


def test_attachment_name_without_extension_still_has_a_name(modules):
    _, mailbox, _, _ = modules

    assert mailbox.safe_attachment_name("", 3) == "attachment-3"
    assert mailbox.safe_attachment_name("...", 1) == "attachment-1"


def test_reply_keeps_the_subject_untouched(modules):
    _, mailbox, _, _ = modules

    subject = "Запрос SCR#6451421 выполнен"

    # Робот просит тему не менять: по ней сшивается тикет.
    assert mailbox.reply_subject(subject) == subject
    assert mailbox.reply_subject("Re: " + subject) == "Re: " + subject


def test_quote_goes_under_our_text(modules):
    _, mailbox, _, _ = modules

    quoted = mailbox.quote_original({"from": "sd@sc.digital.gov.ru", "body": "Строка\nВторая"})

    assert quoted.startswith("sd@sc.digital.gov.ru пишет:")
    assert "> Строка" in quoted and "> Вторая" in quoted


def test_noreply_sender_is_replaced_with_support(modules):
    _, mailbox, _, _ = modules

    assert mailbox.reply_address("", "Центр <noreply@sc.digital.gov.ru>") == mailbox.SUPPORT_ADDRESS
    assert mailbox.reply_address("sd@sc.digital.gov.ru", "noreply@x") == "sd@sc.digital.gov.ru"
    assert mailbox.reply_address("", "sd@sc.digital.gov.ru") == "sd@sc.digital.gov.ru"


def test_reply_draft_shows_where_the_answer_goes(client, modules, monkeypatch):
    _, mailbox, _, _ = modules
    configure_mail(modules, monkeypatch, [LETTER])
    monkeypatch.setattr(
        mailbox,
        "fetch_message",
        lambda config, *, uid: {
            "uid": uid,
            "from": "Центр <noreply@sc.digital.gov.ru>",
            "reply_to": mailbox.SUPPORT_ADDRESS,
            "reply_to_replaced": True,
            "subject": "Запрос SCR#6451421 выполнен",
            "body": "Просим подтвердить решение",
            "ticket": "6451421",
            "message_id": "<1@sc>",
            "received_at": "2026-08-20T17:31:05",
        },
    )

    payload = client.get("/mail/messages/42/reply").json()

    assert payload["to"] == mailbox.SUPPORT_ADDRESS
    assert payload["to_replaced"] is True
    assert payload["subject"] == "Запрос SCR#6451421 выполнен"
    assert "Просим подтвердить" in payload["quote"]


def test_reply_is_sent_into_the_same_thread(client, modules, monkeypatch):
    _, mailbox, _, _ = modules
    configure_mail(modules, monkeypatch, [LETTER])
    sent = {}
    monkeypatch.setattr(
        mailbox,
        "fetch_message",
        lambda config, *, uid: {
            "uid": uid,
            "from": "noreply@sc.digital.gov.ru",
            "reply_to": mailbox.SUPPORT_ADDRESS,
            "subject": "Запрос SCR#6451421 выполнен",
            "body": "Текст робота",
            "ticket": "6451421",
            "message_id": "<1@sc>",
            "references": "<0@sc>",
            "received_at": "2026-08-20T17:31:05",
        },
    )

    def fake_send(config, **kwargs):
        sent.update(kwargs)
        return {"sent": True, "recipients": [kwargs["to"]], "subject": kwargs["subject"]}

    monkeypatch.setattr(mailbox, "send_letter", fake_send)

    body = client.post(
        "/mail/reply", json={"uid": "42", "body": "Подтверждаем решение", "quote": True}
    ).json()

    assert sent["to"] == mailbox.SUPPORT_ADDRESS
    assert sent["subject"] == "Запрос SCR#6451421 выполнен"
    assert sent["in_reply_to"] == "<1@sc>"
    assert sent["references"] == "<0@sc>"
    assert "Подтверждаем решение" in sent["body"]
    assert "> Текст робота" in sent["body"]
    assert body["ticket"] == "6451421"


def test_reply_refuses_a_file_outside_the_folder(client, modules, monkeypatch):
    _, mailbox, _, _ = modules
    configure_mail(modules, monkeypatch, [LETTER])
    monkeypatch.setattr(
        mailbox,
        "fetch_message",
        lambda config, *, uid: {
            "uid": uid, "from": "sd@sc.digital.gov.ru", "reply_to": "sd@sc.digital.gov.ru",
            "subject": "Тема", "body": "", "ticket": "1", "message_id": "", "references": "",
            "received_at": "",
        },
    )
    response = client.post(
        "/mail/reply",
        json={"uid": "42", "body": "Текст", "attach": ["../../etc/passwd"]},
    )
    assert response.status_code == 400


def test_attachment_preview_reads_without_saving(client, modules, monkeypatch, tmp_path):
    _, mailbox, certsources, _ = modules
    configure_mail(modules, monkeypatch, [LETTER])
    monkeypatch.setattr(
        mailbox,
        "read_attachment",
        lambda config, *, uid, index: {
            "name": "spisok.zip",
            "content_type": "application/zip",
            "data": _zip_bytes(),
        },
    )

    payload = client.get("/mail/messages/42/attachments/0/preview").json()

    assert payload["kind"] == "archive"
    assert [item["name"] for item in payload["entries"]] == ["org.cer"]
    # Ничего не сохранили: каталог как был.
    assert not list(certsources.cert_dir().glob("spisok.zip"))


def _zip_bytes():
    import io
    import zipfile

    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("org.cer", "cert")
    return buffer.getvalue()


def test_attachment_raw_is_served_inline(client, modules, monkeypatch):
    _, mailbox, _, _ = modules
    configure_mail(modules, monkeypatch, [LETTER])
    monkeypatch.setattr(
        mailbox,
        "read_attachment",
        lambda config, *, uid, index: {
            "name": "instrukciya.pdf",
            "content_type": "application/pdf",
            "data": b"%PDF-1.4 test",
        },
    )

    response = client.get("/mail/messages/42/attachments/0/raw")

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/pdf")
    assert response.headers["content-disposition"].startswith("inline")


def test_folder_shows_documents_not_only_certificates(client, modules):
    _, _, certsources, _ = modules
    folder = certsources.cert_dir()
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "instrukciya.pdf").write_bytes(b"%PDF-1.4 hello")
    (folder / "org.cer").write_bytes(b"cert")

    files = client.get("/certsources").json()["folder"]["files"]

    names = {item["name"]: item["kind"] for item in files}
    assert names["instrukciya.pdf"] == "pdf"
    assert "org.cer" in names


def test_file_route_refuses_paths_outside_the_folder(client, tmp_path):
    outsider = tmp_path / "secret.txt"
    outsider.write_text("нельзя", encoding="utf-8")
    assert client.get("/certsources/file", params={"path": str(outsider)}).status_code == 400


# ---------- Отдача файлов и ручная загрузка ----------


def test_html_attachment_is_never_shown_inline(client, modules, monkeypatch):
    _, mailbox, _, _ = modules
    configure_mail(modules, monkeypatch, [LETTER])
    monkeypatch.setattr(
        mailbox,
        "read_attachment",
        lambda config, *, uid, index: {
            "name": "page.html",
            "content_type": "text/html",
            "data": b"<script>alert(1)</script>",
        },
    )

    response = client.get("/mail/messages/42/attachments/0/raw")

    # Чужая страница не должна исполняться в origin приложения.
    assert response.headers["content-type"].startswith("application/octet-stream")
    assert response.headers["content-disposition"].startswith("attachment")
    assert response.headers["x-content-type-options"] == "nosniff"


def test_pdf_attachment_is_shown_inline(client, modules, monkeypatch):
    _, mailbox, _, _ = modules
    configure_mail(modules, monkeypatch, [LETTER])
    monkeypatch.setattr(
        mailbox,
        "read_attachment",
        lambda config, *, uid, index: {
            "name": "doc.pdf",
            "content_type": "application/pdf",
            "data": b"%PDF-1.4",
        },
    )

    response = client.get("/mail/messages/42/attachments/0/raw")

    assert response.headers["content-disposition"].startswith("inline")
    response = client.get("/mail/messages/42/attachments/0/raw", params={"download": True})
    assert response.headers["content-disposition"].startswith("attachment")


def test_upload_refuses_to_overwrite_settings(client, modules):
    _, _, certsources, _ = modules
    certsources.cert_dir().mkdir(parents=True, exist_ok=True)
    settings = certsources.cert_dir() / "settings.env"
    settings.write_text("MAIL_PASSWORD=секрет", encoding="utf-8")

    response = client.post(
        "/certsources/upload",
        files={"files": ("settings.env", "подмена".encode(), "text/plain")},
        data={"target": "certs"},
    )

    assert response.status_code == 400
    assert settings.read_text(encoding="utf-8") == "MAIL_PASSWORD=секрет"


def test_upload_does_not_overwrite_an_existing_file(client, modules):
    _, _, certsources, _ = modules
    certsources.cert_dir().mkdir(parents=True, exist_ok=True)
    existing = certsources.cert_dir() / "org.cer"
    existing.write_bytes("первый".encode())

    response = client.post(
        "/certsources/upload",
        files={"files": ("org.cer", "второй".encode(), "application/x-x509-ca-cert")},
        data={"target": "certs"},
    )

    assert response.status_code == 200
    assert existing.read_bytes() == "первый".encode()
    assert (certsources.cert_dir() / "org-1.cer").read_bytes() == "второй".encode()


def test_partial_settings_do_not_reset_the_rest(client, modules):
    _, _, _, setup_api = modules
    client.post("/mail/auto", json={"enabled": True, "collect": True})

    client.post("/mail/auto", json={"confirm": True})

    state = client.get("/mail/auto").json()
    assert state["enabled"] is True
    assert state["confirm"] is True
