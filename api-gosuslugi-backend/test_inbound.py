"""Тесты публичного приёмника входящих запросов."""

import importlib
import json

import pytest
from fastapi.testclient import TestClient


@pytest.fixture()
def client(tmp_path, monkeypatch):
    journal = tmp_path / "messages.jsonl"
    monkeypatch.setenv("INBOUND_JOURNAL", str(journal))
    monkeypatch.setenv("IS_MNEMONIC", "TESTIS01")
    monkeypatch.setenv("INBOUND_MAX_BODY", "64")
    monkeypatch.setenv("INBOUND_PUBLIC_IDENTITY", "1")
    # Проверки отправителя включаются в отдельных тестах, здесь они не мешают.
    for name in ("INBOUND_ALLOW_NETS", "INBOUND_TOKEN", "INBOUND_TRUSTED_PROXIES"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("INBOUND_RATE_PER_MINUTE", "6000")
    monkeypatch.setenv("INBOUND_RATE_BURST", "1000")
    monkeypatch.setenv("INBOUND_RATE_GLOBAL_PER_MINUTE", "6000")

    import inbound_guard
    import inbound_store
    import inbound

    importlib.reload(inbound_guard)
    importlib.reload(inbound_store)
    importlib.reload(inbound)
    inbound_guard.reset()
    # Без явного адреса TestClient представляется словом "testclient", и
    # проверки по сетям проверять нечем.
    with TestClient(inbound.app, client=("127.0.0.1", 44444)) as test_client:
        test_client.journal = journal
        yield test_client


def read_journal(path):
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def test_system_url_reports_mnemonic(client):
    response = client.get("/is")
    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "ok"
    assert body["mnemonic"] == "TESTIS01"
    assert body["endpoints"]["push"] == "/push"


def test_push_is_accepted_and_journaled(client):
    payload = {"orderId": 123, "status": "DONE"}
    response = client.post("/push", json=payload)

    assert response.status_code == 200
    assert response.json()["code"] == "OK"

    records = read_journal(client.journal)
    assert len(records) == 1
    assert records[0]["path"] == "/push"
    assert records[0]["method"] == "POST"
    assert json.loads(records[0]["body_text"]) == payload
    assert records[0]["mnemonic"] == "TESTIS01"


def test_unknown_path_is_also_journaled(client):
    response = client.post("/api/notifications/status", content=b"<xml/>")

    assert response.status_code == 200
    records = read_journal(client.journal)
    assert records[0]["path"] == "/api/notifications/status"
    assert records[0]["body_text"] == "<xml/>"


def test_secrets_are_not_written_to_the_journal(client):
    client.post(
        "/push",
        content=b"{}",
        headers={"Authorization": "Bearer super-secret-token", "X-Api-Key": "guid"},
    )

    records = read_journal(client.journal)
    headers = {name.lower(): value for name, value in records[0]["headers"].items()}
    assert "super-secret-token" not in json.dumps(records[0], ensure_ascii=False)
    assert headers["authorization"].startswith("скрыто")
    assert headers["x-api-key"].startswith("скрыто")


def test_body_without_declared_length_is_truncated_but_accepted(client):
    """Тело без Content-Length режем по лимиту, но запрос принимаем.

    Отправитель прислал больше, чем мы готовы хранить: обрыв связи ему ничего
    не объяснит, а в журнале видно и обрезку, и настоящий размер.
    """
    response = client.post("/push", content=iter([b"x" * 500]))

    assert response.status_code == 200
    records = read_journal(client.journal)
    assert records[0]["truncated"] is True
    assert records[0]["size"] == 64


def test_probe_methods_answer_without_data(client):
    assert client.get("/push").json()["code"] == "OK"
    assert client.head("/push").status_code == 200
    assert client.get("/health").json()["status"] == "Ok"
    assert read_journal(client.journal) == []


def test_identity_hides_registration_details_by_default(tmp_path, monkeypatch):
    """Мнемоника и адрес системы - не то, что стоит показывать сканеру."""
    monkeypatch.setenv("INBOUND_JOURNAL", str(tmp_path / "messages.jsonl"))
    monkeypatch.setenv("IS_MNEMONIC", "TESTIS01")
    monkeypatch.delenv("INBOUND_PUBLIC_IDENTITY", raising=False)

    import inbound_guard
    import inbound_store
    import inbound

    importlib.reload(inbound_guard)
    importlib.reload(inbound_store)
    importlib.reload(inbound)
    with TestClient(inbound.app) as probe:
        body = probe.get("/is").json()

    assert body["status"] == "ok"
    assert "TESTIS01" not in json.dumps(body, ensure_ascii=False)
    assert body["endpoints"]["push"] == "/push"


def test_too_big_body_is_refused_before_reading(client):
    response = client.post("/push", content=b"x" * 500, headers={"Content-Length": "500"})

    assert response.status_code == 413
    assert response.json()["limit"] == 64
    # Отказ в журнал не идёт: иначе мусором можно вытеснить настоящие письма.
    assert read_journal(client.journal) == []


def test_journal_keeps_only_the_head_of_a_large_body(client, monkeypatch):
    monkeypatch.setenv("INBOUND_MAX_BODY", "4096")
    monkeypatch.setenv("INBOUND_JOURNAL_BODY_MAX", "100")

    client.post("/push", content=b"a" * 1000)

    record = read_journal(client.journal)[0]
    assert record["size"] == 1000
    assert record["body_stored"] == 100
    assert record["body_shortened"] is True
    assert len(record["body_text"]) == 100
    # Хэш считается по всему телу, поэтому обрезка проверяема.
    import hashlib

    assert record["body_sha256"] == hashlib.sha256(b"a" * 1000).hexdigest()


def test_flood_from_one_sender_is_cut_off(client, monkeypatch):
    import inbound_guard

    monkeypatch.setenv("INBOUND_RATE_PER_MINUTE", "60")
    monkeypatch.setenv("INBOUND_RATE_BURST", "5")
    inbound_guard.reset()

    codes = [client.post("/push", content=b"{}").status_code for _ in range(8)]

    assert codes[:5] == [200] * 5
    assert codes[5:] == [429] * 3
    assert len(read_journal(client.journal)) == 5


def test_allow_list_closes_the_door_for_strangers(client, monkeypatch):
    import inbound_guard

    monkeypatch.setenv("INBOUND_ALLOW_NETS", "10.0.0.0/8, 192.168.1.5")
    inbound_guard.reset()

    # TestClient приходит с 127.0.0.1, значит в список не попадает.
    assert client.post("/push", content=b"{}").status_code == 403
    assert read_journal(client.journal) == []

    monkeypatch.setenv("INBOUND_ALLOW_NETS", "127.0.0.0/8")
    assert client.post("/push", content=b"{}").status_code == 200


def test_shared_secret_is_checked_when_set(client, monkeypatch):
    import inbound_guard

    # Секрет только латиницей: заголовки HTTP не переносят кириллицу.
    monkeypatch.setenv("INBOUND_TOKEN", "b8f1c0de-secret")
    inbound_guard.reset()

    assert client.post("/push", content=b"{}").status_code == 401
    assert client.post(
        "/push", content=b"{}", headers={"X-Inbound-Token": "ne-tot"}
    ).status_code == 401
    assert client.post(
        "/push", content=b"{}", headers={"X-Inbound-Token": "b8f1c0de-secret"}
    ).status_code == 200
    assert len(read_journal(client.journal)) == 1


def test_forwarded_address_is_believed_only_from_our_proxy(client, monkeypatch):
    import inbound_guard

    inbound_guard.reset()
    client.post("/push", content=b"{}", headers={"X-Forwarded-For": "8.8.8.8"})
    assert read_journal(client.journal)[0]["client"] == "127.0.0.1"

    monkeypatch.setenv("INBOUND_TRUSTED_PROXIES", "127.0.0.1")
    client.post("/push", content=b"{}", headers={"X-Forwarded-For": "8.8.8.8"})
    assert read_journal(client.journal)[-1]["client"] == "8.8.8.8"


# ---------- Проверка внешнего адреса ----------


def operator_client(monkeypatch, tmp_path):
    """Операторский роутер журнала входящих, без публичного приёмника."""
    import importlib

    monkeypatch.setenv("INBOUND_JOURNAL", str(tmp_path / "messages.jsonl"))
    import inbound_store
    import inbound_api

    importlib.reload(inbound_store)
    importlib.reload(inbound_api)
    from fastapi import FastAPI
    from fastapi.testclient import TestClient

    app = FastAPI()
    app.include_router(inbound_api.inbound_router())
    return TestClient(app), inbound_api


def test_public_check_needs_an_address(monkeypatch, tmp_path):
    monkeypatch.delenv("INBOUND_PUBLIC_URL", raising=False)
    client, _ = operator_client(monkeypatch, tmp_path)

    assert client.post("/inbound/check-public").status_code == 400


def test_public_check_refuses_a_bare_host(monkeypatch, tmp_path):
    client, _ = operator_client(monkeypatch, tmp_path)

    response = client.post("/inbound/check-public", params={"url": "smev.example.ru"})

    assert response.status_code == 400


def test_public_check_recognises_our_own_receiver(monkeypatch, tmp_path):
    client, _ = operator_client(monkeypatch, tmp_path)

    class FakeResponse:
        status = 200

        def __init__(self, payload):
            self.payload = payload

        def read(self, limit=None):
            return self.payload

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    import urllib.request

    def fake_open(request, timeout=15):
        url = request.full_url if hasattr(request, "full_url") else str(request)
        body = b'{"status":"ok","endpoints":{}}' if url.endswith("/is") else b'{"code":"OK"}'
        return FakeResponse(body)

    monkeypatch.setattr(urllib.request, "urlopen", fake_open)

    payload = client.post(
        "/inbound/check-public", params={"url": "https://smev.example.ru/"}
    ).json()

    assert payload["reachable"] is True
    assert [item["path"] for item in payload["checks"]] == ["/is", "/push"]
    assert any("техпортале" in hint for hint in payload["hints"])


def test_public_check_reports_a_foreign_answer(monkeypatch, tmp_path):
    client, _ = operator_client(monkeypatch, tmp_path)

    class FakeResponse:
        status = 200

        def read(self, limit=None):
            return b"<html>nginx default page</html>"

        def __enter__(self):
            return self

        def __exit__(self, *args):
            return False

    import urllib.request

    monkeypatch.setattr(urllib.request, "urlopen", lambda request, timeout=15: FakeResponse())

    payload = client.post(
        "/inbound/check-public", params={"url": "https://smev.example.ru"}
    ).json()

    # Прокси ответил своей страницей: адрес занят, но ведёт не к нам.
    assert payload["reachable"] is False
    assert any("не привёл" in hint for hint in payload["hints"])
