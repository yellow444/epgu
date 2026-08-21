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
