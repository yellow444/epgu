import pytest
from pytest_mock import MockerFixture
from fastapi.testclient import TestClient
from app import app


@pytest.fixture(scope="session")
def event_loop():
    import asyncio
    loop = asyncio.get_event_loop()
    yield loop
    loop.close()


with TestClient(app) as client:
    app.router.startup()
    # 1. Тест рендера главных эндпоинтов API

    def test_home_route():
        response = client.get("/status")
        assert response.status_code == 200
        assert "Version" in response.json()
        assert "ModuleVersion" in response.json()

    def test_health_check():
        response = client.get("/hc")
        assert response.status_code == 200
        assert response.json() == {"status": "Ok"}

    # 2. Тест загрузки сертификатов (мокаем pycades)

    def test_get_certificates():
        response = client.post("/get_certificates")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list), "Ответ API должен быть списком"
        assert len(data) > 0
        if len(data) > 0:
            assert "id" in data[0], "Каждый сертификат должен содержать 'id'"
            assert "subject" in data[0], "Каждый сертификат должен содержать 'subject'"
            assert isinstance(data[0]["id"], str), "'id' должен быть строкой"
            assert isinstance(data[0]["subject"],
                              str), "'subject' должен быть строкой"

    # 3. Тест получения текущего сертификата

    def test_get_current_certificate():
        response = client.post("/get_certificates")
        assert response.status_code == 200
        certificates = response.json()
        assert len(certificates) > 0, "Не найдено ни одного сертификата"
        cert_id = certificates[0]["id"]
        response = client.post("/set_current_certificate",
                               params={"cert_id": str(cert_id)})
        assert response.status_code == 200
        response = client.post("/get_current_certificate")
        assert response.status_code == 200
        data = response.json()
        assert "certId" in data, "Ответ должен содержать 'certId'"
        assert "subject" in data, "Ответ должен содержать 'subject'"
        assert data["certId"] == cert_id, "ID текущего сертификата должен совпадать с установленным"

    # 4. Тест обработки невалидного API-ключа

    def test_access_tkn_esia_invalid_api_key():
        response = client.post("/accessTkn_esia", json={"api_key": ""})
        assert response.status_code >= 400
