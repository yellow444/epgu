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

    import inbound_store
    import inbound

    importlib.reload(inbound_store)
    importlib.reload(inbound)
    with TestClient(inbound.app) as test_client:
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


def test_oversized_body_is_truncated_but_accepted(client):
    response = client.post("/push", content=b"x" * 500)

    assert response.status_code == 200
    records = read_journal(client.journal)
    assert records[0]["truncated"] is True
    assert records[0]["size"] == 64


def test_probe_methods_answer_without_data(client):
    assert client.get("/push").json()["code"] == "OK"
    assert client.head("/push").status_code == 200
    assert client.get("/health").json()["status"] == "Ok"
    assert read_journal(client.journal) == []
