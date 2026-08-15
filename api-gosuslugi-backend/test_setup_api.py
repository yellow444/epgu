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
