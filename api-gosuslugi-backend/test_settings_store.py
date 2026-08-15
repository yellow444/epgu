"""Тесты настроек, сохранённых из интерфейса."""

import importlib
import stat
import sys

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient


@pytest.fixture()
def modules(tmp_path, monkeypatch):
    monkeypatch.setenv("SETTINGS_FILE", str(tmp_path / "settings.env"))
    monkeypatch.setenv("MAIL_INBOX_DIR", str(tmp_path / "mail"))
    monkeypatch.setenv("CERT_INBOX_DIR", str(tmp_path / "mail"))
    monkeypatch.setenv("MAIL_IMAP_HOST", "imap.from-environment.ru")
    monkeypatch.setenv("MAIL_PASSWORD", "password-from-environment")
    monkeypatch.setenv("SECRET_PROVIDER", "env")

    import settings_store
    import secret_store
    import mailbox
    import certsources
    import setup_api

    for module in (settings_store, secret_store, mailbox, certsources, setup_api):
        importlib.reload(module)
    return settings_store, secret_store, mailbox, setup_api


@pytest.fixture()
def client(modules):
    _, _, _, setup_api = modules
    app = FastAPI()
    app.include_router(setup_api.setup_router())
    with TestClient(app) as test_client:
        yield test_client


def test_saved_settings_win_over_environment(client, modules):
    settings_store, _, mailbox, _ = modules
    assert mailbox.load_config().imap_host == "imap.from-environment.ru"

    response = client.post(
        "/mail/settings",
        json={
            "imap_host": "imap.saved-from-ui.ru",
            "imap_port": "993",
            "smtp_host": "smtp.saved-from-ui.ru",
            "smtp_port": "465",
            "user": "smev@example.ru",
            "sender": "",
            "use_ssl": True,
            "password": "typed-in-the-browser",
        },
    )
    assert response.status_code == 200
    assert mailbox.load_config().imap_host == "imap.saved-from-ui.ru"
    assert settings_store.get("MAIL_USER") == "smev@example.ru"


def test_saved_password_is_used_but_never_returned(client, modules):
    _, secret_store, _, _ = modules
    response = client.post(
        "/mail/settings",
        json={
            "imap_host": "imap.example.ru",
            "smtp_host": "smtp.example.ru",
            "user": "smev@example.ru",
            "password": "typed-in-the-browser",
        },
    )
    assert response.status_code == 200
    assert "typed-in-the-browser" not in response.text
    assert secret_store.get_secret("MAIL_PASSWORD") == "typed-in-the-browser"
    assert client.get("/mail/config").text.count("typed-in-the-browser") == 0


def test_empty_password_keeps_the_saved_one(client, modules):
    _, secret_store, _, _ = modules
    client.post("/mail/settings", json={"user": "a@b.ru", "password": "first-password"})
    client.post("/mail/settings", json={"user": "changed@b.ru", "password": ""})
    assert secret_store.get_secret("MAIL_PASSWORD") == "first-password"
    assert client.get("/mail/config").json()["user"] == "changed@b.ru"


def test_dotenv_fragment_does_not_carry_the_password(client):
    response = client.post(
        "/mail/settings",
        json={"imap_host": "imap.example.ru", "user": "a@b.ru", "password": "secret-value"},
    )
    dotenv = response.json()["dotenv"]
    assert "MAIL_IMAP_HOST=imap.example.ru" in dotenv
    assert "secret-value" not in dotenv
    assert "MAIL_PASSWORD=" in dotenv


def test_password_source_is_named_honestly(client, modules):
    _, secret_store, _, _ = modules
    # Пока ничего не сохраняли, пароль берётся из окружения.
    assert secret_store.describe("MAIL_PASSWORD")["source"] == "окружение"

    client.post("/mail/settings", json={"user": "a@b.ru", "password": "saved-from-ui"})
    described = secret_store.describe("MAIL_PASSWORD")
    assert described["source"] == "сохранено из интерфейса"
    assert described["length"] == len("saved-from-ui")

    secret_store.set_runtime_secret("MAIL_PASSWORD", "typed-now")
    assert secret_store.describe("MAIL_PASSWORD")["source"] == "память процесса"
    secret_store.clear_runtime_secrets()


def test_unknown_keys_are_refused(modules):
    settings_store, _, _, _ = modules
    with pytest.raises(ValueError):
        settings_store.save({"esia_host": "https://evil.example"})


def test_port_must_be_a_number(client):
    # Короткое значение проходит проверку длины и доходит до нашей проверки.
    response = client.post("/mail/settings", json={"imap_port": "abc"})
    assert response.status_code == 400
    assert "число" in response.json()["detail"]


def test_too_long_port_is_refused_by_validation(client):
    response = client.post("/mail/settings", json={"imap_port": "9" * 10})
    assert response.status_code == 422


@pytest.mark.skipif(sys.platform == "win32", reason="права файлов проверяются на POSIX")
def test_settings_file_is_not_world_readable(client, modules):
    settings_store, _, _, _ = modules
    client.post("/mail/settings", json={"user": "a@b.ru", "password": "secret"})
    mode = settings_store.settings_path().stat().st_mode
    assert not mode & stat.S_IROTH
    assert not mode & stat.S_IRGRP
