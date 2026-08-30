"""Отдача Госпочты наружу: закрыта по умолчанию, читает только том."""

from __future__ import annotations

import importlib
import xml.etree.ElementTree as ET

import pytest
from fastapi.testclient import TestClient

MESSAGE = "91160bbb-f997-11ef-8080-808080808080"
THREAD = "6c7a5efd-2a8c-11f0-8080-808080808080"
ATTACHMENT = "61d94a0a-66ce-11ef-8080-808080808080"
SECRET = "b8f1c0de-secret"


def brief(message_uuid=MESSAGE, **changes):
    item = {
        "threadUuid": THREAD,
        "messageUuid": message_uuid,
        "sender": "ФССП",
        "subject": "Извещение",
        "isRead": False,
        "createDate": "2026-08-15T10:20:00+03:00",
    }
    item.update(changes)
    return item


def detail(message_uuid=MESSAGE):
    return {
        "threadUuid": THREAD,
        "messageUuid": message_uuid,
        "sender": "ФССП",
        "subject": "Извещение",
        "isRead": True,
        "createDate": "2026-08-15T10:20:00+03:00",
        "html": "<div class=\"mail\"><p>Возбуждено производство</p><br><b>Срок</b> 5 дней</div>",
        "params": {"uin": "42"},
        "attachments": [
            {
                "attachmentUuid": ATTACHMENT,
                "fileName": "postanovlenie.pdf",
                "fileSize": 8,
                "mimeType": "application/pdf",
                "signed": True,
                "status": "READY",
                "statusDescription": "Доступен",
                "downloadable": True,
            }
        ],
        "statuses": [{"mnemonic": "READ", "description": "Прочитано"}],
    }


@pytest.fixture()
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("GEPS_STORE_DIR", str(tmp_path / "geps"))
    for name in ("OUTBOUND_TOKEN", "OUTBOUND_ALLOW_NETS", "OUTBOUND_TRUSTED_PROXIES"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("OUTBOUND_RATE_PER_MINUTE", "6000")
    monkeypatch.setenv("OUTBOUND_RATE_BURST", "1000")
    monkeypatch.setenv("OUTBOUND_RATE_GLOBAL_PER_MINUTE", "6000")

    import geps_store
    import inbound_guard

    importlib.reload(geps_store)
    importlib.reload(inbound_guard)
    inbound_guard.reset()
    geps_store.save_messages("job-1", [brief()])
    geps_store.save_detail(MESSAGE, detail())
    return geps_store


@pytest.fixture()
def closed(store):
    import outbound

    importlib.reload(outbound)
    with TestClient(outbound.app, client=("10.1.2.3", 44444)) as client:
        yield client


@pytest.fixture()
def client(store, monkeypatch):
    monkeypatch.setenv("OUTBOUND_TOKEN", SECRET)

    import outbound

    importlib.reload(outbound)
    with TestClient(outbound.app, client=("10.1.2.3", 44444)) as value:
        value.headers.update({"X-Outbound-Token": SECRET})
        value.store = store
        yield value


# --- закрыто по умолчанию ------------------------------------------------


def test_data_is_not_served_until_something_is_configured(closed):
    """Приёмник обязан принимать всё, а отдача - наоборот, молчать."""
    assert closed.get("/messages").status_code == 503
    assert closed.get("/letters").status_code == 503
    assert closed.get(f"/messages/{MESSAGE}").status_code == 503

    body = closed.get("/messages").json()
    assert "OUTBOUND_TOKEN" in body["message"]


def test_health_answers_even_when_closed(closed):
    body = closed.get("/health").json()
    assert body["status"] == "Ok"
    assert body["configured"] is False


def test_secret_is_checked(client):
    # Секрет только латиницей: кириллицу заголовок HTTP не перенесёт.
    assert client.get("/messages", headers={"X-Outbound-Token": "ne-tot"}).status_code == 401
    assert client.get("/messages", headers={"X-Outbound-Token": ""}).status_code == 401
    assert client.get("/messages").status_code == 200


def test_allow_list_closes_the_door(store, monkeypatch):
    monkeypatch.setenv("OUTBOUND_ALLOW_NETS", "192.168.0.0/16")

    import inbound_guard
    import outbound

    importlib.reload(outbound)
    inbound_guard.reset()
    with TestClient(outbound.app, client=("10.1.2.3", 44444)) as stranger:
        assert stranger.get("/messages").status_code == 403

    with TestClient(outbound.app, client=("192.168.1.7", 44444)) as allowed:
        assert allowed.get("/messages").status_code == 200


def test_flood_is_cut_off(client, monkeypatch):
    import inbound_guard

    monkeypatch.setenv("OUTBOUND_RATE_PER_MINUTE", "60")
    monkeypatch.setenv("OUTBOUND_RATE_BURST", "3")
    inbound_guard.reset()

    codes = [client.get("/messages").status_code for _ in range(6)]
    assert codes[:3] == [200, 200, 200]
    assert codes[3:] == [429, 429, 429]


# --- данные --------------------------------------------------------------


def test_messages_are_served_without_local_paths(client):
    body = client.get("/messages").json()

    assert body["total"] == 1
    item = body["messages"][0]
    assert item["messageUuid"] == MESSAGE
    assert item["sender"] == "ФССП"
    assert item["attachments"][0]["available"] is False
    # Пути на нашем диске наружу не отдаём.
    assert "saved_path" not in str(item)
    assert "/var/lib" not in str(item)


def test_single_message_carries_text_without_markup(client):
    body = client.get(f"/messages/{MESSAGE}").json()

    assert "Возбуждено производство" in body["text"]
    assert "<div" not in body["text"]
    assert body["params"]["uin"] == "42"
    assert body["statuses"][0]["mnemonic"] == "READ"
    # Разметку тоже отдаём: пусть потребитель решает сам.
    assert body["html"].startswith("<div")


def test_unknown_message_is_404(client):
    assert client.get("/messages/нет-такого").status_code == 404


def test_since_filter_returns_only_new(client):
    client.store.save_messages(
        "job-2",
        [brief("aaaaaaaa-0000-11f0-8080-808080808080", createDate="2026-08-01T10:00:00+03:00")],
    )

    assert client.get("/messages").json()["total"] == 2
    fresh = client.get("/messages", params={"since": "2026-08-10"}).json()
    assert fresh["total"] == 1
    assert fresh["messages"][0]["messageUuid"] == MESSAGE


# --- формат Letters ------------------------------------------------------


def test_letters_xml_matches_the_gospochta_shape(client):
    response = client.get("/letters", params={"request_id": "REQ-1"})

    assert response.status_code == 200
    assert response.headers["content-type"].startswith("application/xml")
    root = ET.fromstring(response.content)
    assert root.tag == "Letters"
    assert root.attrib["RequestID"] == "REQ-1"

    letter = root.find("Letter")
    # Порядок элементов задан схемой Госпочты, и менять его нельзя: чужая
    # интеграция читает документ последовательно.
    assert [child.tag for child in letter] == [
        "Date",
        "Sender",
        "Subject",
        "Text",
        "Ref",
        "DocType",
        "BodyJSON",
        "Files",
    ]
    assert letter.findtext("Sender") == "ФССП"
    assert letter.findtext("Subject") == "Извещение"
    assert "Возбуждено производство" in letter.findtext("Text")
    assert letter.findtext("Ref") == MESSAGE
    assert letter.findtext("DocType") == "READ"
    assert letter.find("Files").findtext("FileName") == "postanovlenie.pdf"


def test_letters_escape_markup_instead_of_breaking_the_document(client):
    client.store.save_detail(
        MESSAGE,
        {**detail(), "html": "<p>Иванов &amp; Сыновья <b>«АБВ»</b> 5 &lt; 6</p>"},
    )

    root = ET.fromstring(client.get("/letters").content)
    text = root.find("Letter").findtext("Text")

    assert "Иванов & Сыновья «АБВ» 5 < 6" in text


# --- вложения ------------------------------------------------------------


def test_attachment_is_served_only_after_the_operator_downloaded_it(client):
    """За файлом в ЕПГУ этот процесс не пойдёт: чтение запускает сроки."""
    response = client.get(f"/messages/{MESSAGE}/attachments/{ATTACHMENT}")
    assert response.status_code == 409
    assert "не скачан" in response.json()["message"]

    client.store.save_attachment(MESSAGE, ATTACHMENT, b"%PDF-1.4", "postanovlenie.pdf")

    ready = client.get(f"/messages/{MESSAGE}/attachments/{ATTACHMENT}")
    assert ready.status_code == 200
    assert ready.content == b"%PDF-1.4"
    assert "postanovlenie.pdf" in ready.headers["content-disposition"]

    listed = client.get("/messages").json()["messages"][0]
    assert listed["attachments"][0]["available"] is True


def test_signature_is_served_separately(client):
    client.store.save_attachment(MESSAGE, ATTACHMENT, b"SIG", "postanovlenie.pdf", signature=True)

    response = client.get(
        f"/messages/{MESSAGE}/attachments/{ATTACHMENT}", params={"signature": True}
    )
    assert response.status_code == 200
    assert response.content == b"SIG"


def test_file_outside_the_store_is_never_served(client, tmp_path):
    """Запись могли подправить руками, отдавать что попало нельзя."""
    outsider = tmp_path / "secret.txt"
    outsider.write_text("секрет", encoding="utf-8")

    record = client.store.get_message(MESSAGE)
    record["attachments"][0]["saved_path"] = str(outsider)
    import json

    client.store.messages_path().write_text(
        json.dumps({MESSAGE: record}, ensure_ascii=False), encoding="utf-8"
    )

    assert client.get(f"/messages/{MESSAGE}/attachments/{ATTACHMENT}").status_code == 404


def test_unknown_attachment_is_404(client):
    assert client.get(f"/messages/{MESSAGE}/attachments/нет").status_code == 404


# --- что процесс вообще умеет -------------------------------------------


def test_outbound_has_no_operator_methods(client):
    for path in ("/geps/scheduler", "/geps/search", "/inbound/messages", "/get_certificates"):
        assert client.get(path).status_code in (404, 405)


def test_outbound_never_calls_epgu(client, monkeypatch):
    """Обращение к ГЭПС запускает сроки, поэтому чужой запрос его не вызывает."""
    import httpx

    def explode(*args, **kwargs):
        raise AssertionError("отдача полезла в сеть")

    # TestClient itself inherits from the synchronous httpx.Client. Patching
    # that class would block the three local calls below instead of detecting
    # an accidental upstream request made by the application.
    monkeypatch.setattr(httpx.AsyncClient, "request", explode)
    monkeypatch.setattr(httpx.AsyncClient, "send", explode)

    assert client.get("/messages").status_code == 200
    assert client.get(f"/messages/{MESSAGE}").status_code == 200
    assert client.get("/letters").status_code == 200
