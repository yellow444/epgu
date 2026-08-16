"""Smoke tests that run both with and without proprietary CryptoPro bindings."""

from datetime import datetime, timezone

import httpx
import pytest
from fastapi.testclient import TestClient

import app as app_module
from app import app, services_dict
from config import ENVIRONMENTS


@pytest.fixture(scope="module")
def client():
    with TestClient(app) as test_client:
        yield test_client


def test_crypto_status_is_explicit(client):
    status = client.get("/status")
    health = client.get("/hc")
    if app_module.pycades is None:
        assert status.status_code == 503
        assert health.status_code == 503
        assert health.json() == {"status": "Degraded", "pycades": False}
    else:
        assert status.status_code == 200
        assert "Version" in status.json()
        assert "ModuleVersion" in status.json()
        assert health.status_code == 200
        assert health.json() == {"status": "Ok"}


def test_version_route(client):
    response = client.get("/version")
    assert response.status_code == 200
    body = response.json()
    assert body["spec_version"] == "1.14"
    assert body["environment"] in {"test", "prod", "test-beta", "custom"}
    assert "esia_host" in body["hosts"]
    assert "svcdev_host" in body["hosts"]
    assert body["services_count"] == 21
    assert isinstance(body["runtime"]["allowed_origins"], list)
    assert "has_access_tkn" in body["runtime"]
    assert "access_tkn_exp" in body["runtime"]


def test_cors_is_centralized_and_never_enables_cookie_credentials(client):
    response = client.post(
        "/get_certificates",
        headers={"Origin": "http://localhost:50080"},
    )
    assert response.status_code == 200
    assert "access-control-allow-origin" in response.headers
    assert "access-control-allow-credentials" not in response.headers


def test_cross_origin_browser_mutation_is_rejected_before_handler(client):
    response = client.post(
        "/accessTkn_esia",
        json={"api_key": "example"},
        headers={"Origin": "https://evil.example"},
    )
    assert response.status_code == 403
    assert "Cross-origin" in response.json()["detail"]


def test_same_origin_browser_mutation_reaches_handler(client):
    response = client.post(
        "/accessTkn_esia",
        json={"api_key": ""},
        headers={"Origin": "http://localhost:50080"},
    )
    assert response.status_code == 400


def test_generic_xml_validation_rejects_doctype():
    with pytest.raises(app_module.HTTPException, match="DOCTYPE"):
        app_module.validate_xml_content(b"<!DOCTYPE request><request/>")


@pytest.mark.parametrize("path", ["/order/0", "/order/not-a-number", "/order/-1/cancel"])
def test_order_path_rejects_non_positive_or_non_numeric_id(client, path):
    response = client.post(
        path,
        json={"region": "45000000000", "serviceCode": "60010153", "targetCode": "-60010153"},
    )
    assert response.status_code == 422


def test_environments_route(client):
    response = client.get("/environments")
    assert response.status_code == 200
    envs = response.json()
    assert set(envs) == set(ENVIRONMENTS)
    for env_data in envs.values():
        assert env_data["esia_host"].startswith("https://")
        assert env_data["svcdev_host"].startswith("https://")


@pytest.mark.skipif(app_module.pycades is None, reason="CryptoPro CSP не установлен")
def test_get_and_select_certificate(client):
    response = client.post("/get_certificates")
    assert response.status_code == 200
    certificates = response.json()
    assert certificates
    cert_id = certificates[0]["id"]
    assert isinstance(cert_id, str)
    assert isinstance(certificates[0]["subject"], str)

    response = client.post("/set_current_certificate", params={"cert_id": cert_id})
    assert response.status_code == 200
    response = client.post("/get_current_certificate")
    assert response.status_code == 200
    assert response.json()["certId"] == cert_id


def test_certificate_loading_never_selects_first_store_entry(client, monkeypatch):
    class FakeCertificate:
        def __init__(self, thumbprint, subject):
            self.Thumbprint = thumbprint
            self.SubjectName = subject
            self.ValidFromDate = datetime(2026, 1, 2, tzinfo=timezone.utc)
            self.ValidToDate = datetime(2027, 1, 2, tzinfo=timezone.utc)

    certificates = [
        FakeCertificate("thumb-a", "CN=Alice, O=Example Org, SN=Operator"),
        FakeCertificate("thumb-b", "CN=Bob, O=Example Org, SN=Operator"),
    ]

    class FakeCollection:
        Count = len(certificates)

        @staticmethod
        def Item(index):
            return certificates[index - 1]

    class FakeStore:
        Certificates = FakeCollection()

        @staticmethod
        def Open(*_args):
            return None

    class FakePycades:
        CADESCOM_CONTAINER_STORE = 1
        CAPICOM_MY_STORE = 2
        CAPICOM_STORE_OPEN_MAXIMUM_ALLOWED = 3

        @staticmethod
        def Store():
            return FakeStore()

    monkeypatch.setattr(app_module, "pycades", FakePycades())
    monkeypatch.setattr(app_module, "CERTIFICATES", {"old": object()})
    monkeypatch.setattr(app_module, "CURRENT_CERT_ID", "old")

    assert app_module.load_certificates() == ["thumb-a", "thumb-b"]
    assert app_module.CURRENT_CERT_ID is None
    assert client.post("/get_current_certificate").status_code == 400

    response = client.post("/get_certificates")
    assert response.status_code == 200
    assert response.json()[0] == {
        "id": "thumb-a",
        "subject": "Alice",
        "common_name": "Alice",
        "organization": "Example Org",
        "valid_from": "2026-01-02T00:00:00+00:00",
        "valid_to": "2027-01-02T00:00:00+00:00",
        "selected": False,
    }

    assert client.post(
        "/set_current_certificate", params={"cert_id": "thumb-b"}
    ).status_code == 200
    assert client.post("/get_current_certificate").json()["certId"] == "thumb-b"
    assert client.post("/get_certificates").json()[1]["selected"] is True

    # Reloading the provider revokes even a previous explicit choice.
    app_module.load_certificates()
    assert app_module.CURRENT_CERT_ID is None


def test_signing_fails_closed_without_explicit_certificate(monkeypatch):
    class UnexpectedCryptoCall:
        @staticmethod
        def Signer():
            raise AssertionError("Crypto provider must not be reached")

    monkeypatch.setattr(app_module, "pycades", UnexpectedCryptoCall())
    monkeypatch.setattr(app_module, "CERTIFICATES", {"thumb-a": object()})
    monkeypatch.setattr(app_module, "CURRENT_CERT_ID", None)

    with pytest.raises(app_module.HTTPException) as caught:
        app_module._sign_cades_detached(b"payload")

    assert caught.value.status_code == 409
    assert caught.value.detail == "Сертификат подписи не выбран"


def test_access_token_rejects_empty_api_key(client):
    response = client.post("/accessTkn_esia", json={"api_key": ""})
    assert response.status_code == 400


def test_signkey_uses_unpadded_base64url(monkeypatch):
    monkeypatch.setattr(app_module, "_sign_cades_detached", lambda _payload: b"a")
    assert app_module.signkey("key") == "YQ"


def test_access_token_quotes_key_and_redacts_failed_signed_request(client, monkeypatch, caplog):
    api_key = "SENSITIVE/key?value"
    signature = "SENSITIVE-SIGNATURE"

    class RejectingClient:
        async def get(self, url, **kwargs):
            assert url.endswith("/SENSITIVE%2Fkey%3Fvalue/tkn")
            request = httpx.Request("GET", url, params=kwargs["params"])
            return httpx.Response(401, request=request)

    async def dependency():
        yield RejectingClient()

    monkeypatch.setattr(app_module, "signkey", lambda _value: signature)
    app_module.app.dependency_overrides[app_module.get_async_client] = dependency
    caplog.clear()
    try:
        response = client.post("/accessTkn_esia", json={"api_key": api_key})
    finally:
        app_module.app.dependency_overrides.clear()

    assert response.status_code == 401
    assert response.json() == {"detail": "ЕСИА отклонила запрос маркера"}
    combined = response.text + caplog.text
    assert api_key not in combined
    assert signature not in combined


@pytest.mark.parametrize("response_kind", ["not-json", "list", "missing", "blank"])
def test_access_token_rejects_malformed_success_without_retaining_old_token(
    client, monkeypatch, caplog, response_kind
):
    sentinel = "SENSITIVE-UPSTREAM-BODY"

    class MalformedTokenClient:
        async def get(self, url, **_kwargs):
            request = httpx.Request("GET", url)
            if response_kind == "not-json":
                return httpx.Response(200, content=sentinel, request=request)
            if response_kind == "list":
                return httpx.Response(200, json=[sentinel], request=request)
            if response_kind == "missing":
                return httpx.Response(200, json={"error": sentinel}, request=request)
            return httpx.Response(200, json={"accessTkn": " ", "error": sentinel}, request=request)

    async def dependency():
        yield MalformedTokenClient()

    monkeypatch.setattr(app_module, "signkey", lambda _value: "safe-signature")
    monkeypatch.setattr(app_module, "ACCESS_TKN_ESIA", "old-token")
    monkeypatch.setattr(app_module, "ACCESS_TKN_EXP", 123)
    app_module.app.dependency_overrides[app_module.get_async_client] = dependency
    caplog.clear()
    try:
        response = client.post("/accessTkn_esia", json={"api_key": "example"})
    finally:
        app_module.app.dependency_overrides.clear()

    assert response.status_code == 502
    assert response.json() == {"detail": "ЕСИА вернула некорректный ответ маркера"}
    assert sentinel not in response.text + caplog.text
    assert app_module.ACCESS_TKN_ESIA == ""
    assert app_module.ACCESS_TKN_EXP == 0


def test_session_clear_revokes_token_and_certificate(client, monkeypatch):
    token = "e30.eyJleHAiOjIwMDAwMDAwMDB9.signature"

    class SelectedCertificate:
        SubjectName = "CN=Operator"

    class SuccessfulTokenClient:
        async def get(self, url, **_kwargs):
            return httpx.Response(
                200,
                json={"accessTkn": token},
                request=httpx.Request("GET", url),
            )

    async def dependency():
        yield SuccessfulTokenClient()

    monkeypatch.setattr(app_module, "signkey", lambda _value: "safe-signature")
    monkeypatch.setattr(
        app_module,
        "CERTIFICATES",
        {"thumb-a": SelectedCertificate()},
    )
    monkeypatch.setattr(app_module, "CURRENT_CERT_ID", "thumb-a")
    app_module.app.dependency_overrides[app_module.get_async_client] = dependency
    try:
        acquired = client.post("/accessTkn_esia", json={"api_key": "example"})
    finally:
        app_module.app.dependency_overrides.clear()

    assert acquired.status_code == 200
    assert client.get("/version").json()["runtime"]["has_access_tkn"] is True
    assert client.post("/get_current_certificate").status_code == 200

    cleared = client.post("/session/clear")

    assert cleared.status_code == 200
    assert cleared.json() == {"cleared": True}
    runtime = client.get("/version").json()["runtime"]
    assert runtime["has_access_tkn"] is False
    assert runtime["access_tkn_exp"] == 0
    assert app_module.CURRENT_CERT_ID is None
    assert client.post("/get_current_certificate").status_code == 400


def test_session_clear_is_csrf_protected(client, monkeypatch):
    monkeypatch.setattr(app_module, "ACCESS_TKN_ESIA", "old-token")
    monkeypatch.setattr(app_module, "ACCESS_TKN_EXP", 123)
    monkeypatch.setattr(app_module, "CURRENT_CERT_ID", "thumb-a")

    response = client.post(
        "/session/clear",
        headers={"Origin": "https://evil.example"},
    )

    assert response.status_code == 403
    assert app_module.ACCESS_TKN_ESIA == "old-token"
    assert app_module.ACCESS_TKN_EXP == 123
    assert app_module.CURRENT_CERT_ID == "thumb-a"


def test_services_catalog_is_full_and_capability_aware(client):
    response = client.get("/services")
    assert response.status_code == 200
    catalog = response.json()
    assert len(catalog) == 21
    for entry in catalog:
        assert entry["serviceCode"]
        assert entry["description"]
        assert entry["status"] in {"verified", "reference", "disabled"}
        assert isinstance(entry["available"], bool)
        assert entry["spec"]["source"].startswith("https://gu-st.ru/")
        assert entry["submission"]["documents"]


def test_service_by_code_known(client):
    sample_code = next(iter(services_dict))
    response = client.get(f"/services/{sample_code}")
    assert response.status_code == 200
    assert response.json()["serviceCode"] == sample_code


def test_service_by_code_unknown_is_404(client):
    response = client.get("/services/nonexistent-code-zz")
    assert response.status_code == 404


def test_xml_unknown_service_is_400(client):
    response = client.get("/xml", params={"service": "nonexistent"})
    assert response.status_code == 400
    assert "не зарегистрирована" in response.json()["detail"]


def test_xml_reference_profile_is_visible_but_not_executable(client):
    response = client.get("/xml", params={"service": "60079416"})
    assert response.status_code == 409
    assert "только для справки" in response.json()["detail"]


def test_xml_fssp_demo_profile_is_reference_only(client):
    response = client.get("/xml", params={"service": "60010153"})
    assert response.status_code == 409
    assert "демонстрационные данны" in response.json()["detail"]


def test_goskey_generated_profile_has_no_borrowed_xml_template(client):
    response = client.get("/xml", params={"service": "10000000374"})
    assert response.status_code == 200
    body = response.json()
    assert body["files"] == []
    assert body["service"]["submission"]["documents"][0]["generator"] == "goskey"
    assert [item["state"] for item in body["service"]["capabilities"]] == [
        "verified",
        "reference",
    ]
