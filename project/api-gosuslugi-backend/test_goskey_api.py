"""Backend integration tests for the reusable typed Goskey SDK."""

from __future__ import annotations

import io
import json
import time
import zipfile
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from epgu.services.goskey import TransportDecision, TransportMode
from fastapi.testclient import TestClient

import app as app_module


def _payload(**changes):
    values = {
        "serviceCode": "10000000374",
        "region": "45000000000",
        "variant": "unep",
        "recipientType": "individual",
        "snils": "000-729-729 38",
        "signExpiration": (
            datetime.now(timezone(timedelta(hours=3))) + timedelta(hours=1)
        ).isoformat(timespec="seconds"),
        "description": "Заявление на отпуск",
        "orgName": "ООО Ромашка",
        "orgInn": "6950199530",
        "backlink": "https://www.gosuslugi.ru/",
    }
    values.update(changes)
    return values


class GoskeyUpstream:
    def __init__(self, order_id=77):
        self.order_id = order_id
        self.calls = []

    async def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return httpx.Response(
            200,
            json={"orderId": self.order_id},
            request=httpx.Request("POST", url),
        )


def _override_client(recording):
    async def dependency():
        yield recording

    app_module.app.dependency_overrides[app_module.get_async_client] = dependency


@pytest.fixture(autouse=True)
def clear_overrides():
    yield
    app_module.app.dependency_overrides.clear()


@pytest.fixture()
def client(monkeypatch):
    # Старт приложения перечитывает хранилище сертификатов и гасит сессию
    # оператора, поэтому маркер ставим уже после входа в контекст.
    monkeypatch.setattr(app_module, "load_certificates", lambda: [])
    with TestClient(app_module.app) as value:
        monkeypatch.setattr(app_module, "ACCESS_TKN_ESIA", "test-bearer")
        monkeypatch.setattr(app_module, "ACCESS_TKN_EXP", int(time.time()) + 3600)
        yield value


def test_capabilities_publish_three_verified_and_two_reference_variants(client):
    response = client.get("/goskey/capabilities")
    assert response.status_code == 200
    capabilities = response.json()
    assert len(capabilities) == 5
    assert sum(item["state"] == "verified" for item in capabilities) == 3
    assert sum(item["state"] == "reference" for item in capabilities) == 2
    assert {item["service_code"] for item in capabilities} == {
        "10000000374",
        "60025907",
        "60079416",
        "60080470",
    }


def test_preview_builds_xml_but_reference_variant_fails_closed(client):
    response = client.post("/goskey/preview", json=_payload())
    assert response.status_code == 200
    body = response.json()
    assert body["fileName"] == "req.xml"
    assert body["requiresDetachedSignature"] is True
    assert 'xmlns="urn://mpkey.gosuslugi.ru/sign_document/1.0.0"' in body["xml"]
    assert "000-729-729 38" in body["xml"]

    response = client.post("/goskey/preview", json=_payload(variant="ukep"))
    assert response.status_code == 409
    assert "publishes only the UNEP" in response.json()["detail"]


def test_preview_rejects_wrong_recipient_shape(client):
    response = client.post(
        "/goskey/preview",
        json=_payload(recipientType="foreign-legal"),
    )
    assert response.status_code == 400
    assert "individual recipient" in response.json()["detail"]


@pytest.mark.parametrize("region", ["", "1", "123456789012", "77-00"])
def test_goskey_requires_numeric_okato_region(client, region):
    response = client.post("/goskey/preview", json=_payload(region=region))
    assert response.status_code == 422


def test_goskey_accepts_official_two_digit_region_example(client):
    response = client.post("/goskey/preview", json=_payload(region="36"))

    assert response.status_code == 200, response.text
    assert response.json()["fileName"] == "req.xml"


def test_submit_requires_licensed_crypto_runtime(client, monkeypatch):
    monkeypatch.setattr(app_module, "pycades", None)
    response = client.post(
        "/goskey/submit",
        data={"request": json.dumps(_payload())},
        files={"documents": ("document.pdf", b"PDF", "application/pdf")},
    )
    assert response.status_code == 503
    assert "CryptoPro" in response.json()["detail"]


def test_submit_refuses_without_access_token_and_does_not_sign(client, monkeypatch):
    """Без маркера доступа отправлять некуда, и подписывать тоже незачем."""
    monkeypatch.setattr(app_module, "pycades", object())
    monkeypatch.setattr(app_module, "ACCESS_TKN_ESIA", "")
    signed = []
    monkeypatch.setattr(
        app_module,
        "_sign_cades_detached",
        lambda data: signed.append(data) or b"SIGNATURE",
    )
    upstream = GoskeyUpstream()
    _override_client(upstream)

    response = client.post(
        "/goskey/submit",
        data={"request": json.dumps(_payload())},
        files={"documents": ("document.pdf", b"PDF", "application/pdf")},
    )

    assert response.status_code == 401
    assert signed == []
    assert upstream.calls == []


def test_submit_reuses_sdk_signs_every_file_and_uses_direct_push(client, monkeypatch):
    monkeypatch.setattr(app_module, "pycades", object())
    monkeypatch.setattr(app_module, "_sign_cades_detached", lambda data: b"SIG:" + data[:8])
    upstream = GoskeyUpstream()
    _override_client(upstream)

    response = client.post(
        "/goskey/submit",
        data={"request": json.dumps(_payload())},
        files={"documents": ("document.pdf", b"PDF-CONTENT", "application/pdf")},
    )

    assert response.status_code == 200, response.text
    assert response.json() == {
        "orderId": "77",
        "serviceCode": "10000000374",
        "transport": "push",
        "archiveSize": response.json()["archiveSize"],
        "chunks": 1,
        "signedFiles": 2,
    }
    assert len(upstream.calls) == 1
    url, kwargs = upstream.calls[0]
    assert url.endswith("/api/gusmev/push")
    outgoing = kwargs["files"]
    assert json.loads(outgoing["meta"][1]) == {
        "region": "45000000000",
        "serviceCode": "10000000374",
        "targetCode": "-10000000374",
    }
    with zipfile.ZipFile(io.BytesIO(outgoing["file"][1])) as archive:
        assert set(archive.namelist()) == {
            "req.xml",
            "req.xml.sig",
            "document.pdf",
            "document.pdf.sig",
        }
        assert archive.read("document.pdf") == b"PDF-CONTENT"
        assert archive.read("req.xml.sig").startswith(b"SIG:")


def test_submit_can_reserve_and_use_chunked_transport(client, monkeypatch):
    monkeypatch.setattr(app_module, "pycades", object())
    monkeypatch.setattr(app_module, "_sign_cades_detached", lambda data: b"SIGNATURE")
    monkeypatch.setattr(
        app_module,
        "select_transport",
        lambda archive_size, order_id: TransportDecision(
            TransportMode.ORDER_CHUNKED,
            "/api/gusmev/push/chunked",
            True,
            None,
        ),
    )
    upstream = GoskeyUpstream(order_id=88)
    _override_client(upstream)

    response = client.post(
        "/goskey/submit",
        data={"request": json.dumps(_payload())},
        files={"documents": ("document.pdf", b"PDF", "application/pdf")},
    )

    assert response.status_code == 200, response.text
    assert response.json()["orderId"] == "88"
    assert response.json()["transport"] == "order+chunked"
    assert [call[0].rsplit("/", 1)[-1] for call in upstream.calls] == ["order", "chunked"]
    chunk_files = upstream.calls[1][1]["files"]
    assert chunk_files["file"][0] == "goskey.zip"
    assert "chunk" not in chunk_files and "chunks" not in chunk_files
    assert 0 < upstream.calls[1][1]["timeout"] <= app_module.CHUNK_UPLOAD_DEADLINE_SECONDS
