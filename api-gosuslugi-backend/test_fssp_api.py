"""Заявления ФССП по форме: предпросмотр, проверка, отправка."""

from __future__ import annotations

import io
import json
import time
import zipfile
from datetime import datetime, timezone

import httpx
import pytest
from fastapi.testclient import TestClient
from lxml import etree

import app as app_module
import fssp_api

NS_REQUEST = "http://www.fssprus.ru/namespace/incoming/2019/1"
NS_TRANSPORT = "urn://x-artifacts-fssp-ru/mvv/smev3/epgu/1.0.1"


class RecordingClient:
    """Подмена клиента ЕПГУ: резерв номера и приём частей архива."""

    def __init__(self, order_id: int = 3500290327):
        self.calls = []
        self.order_id = order_id

    async def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return httpx.Response(
            200, json={"orderId": self.order_id}, request=httpx.Request("POST", url)
        )


@pytest.fixture(autouse=True)
def operator_session(monkeypatch):
    monkeypatch.setattr(app_module, "load_certificates", lambda: [])
    monkeypatch.setattr(app_module, "ACCESS_TKN_ESIA", "test-bearer")
    monkeypatch.setattr(app_module, "ACCESS_TKN_EXP", int(time.time()) + 3600)


@pytest.fixture()
def recording():
    client = RecordingClient()

    async def dependency():
        yield client

    app_module.app.dependency_overrides[app_module.get_async_client] = dependency
    yield client
    app_module.app.dependency_overrides.clear()


def payload(**changes):
    body = {
        "serviceCode": "60010153",
        "region": "45000000000",
        "side": "1",
        "representation": "organization",
        "applicant": {
            "fullName": "Петров Пётр Петрович",
            "gender": "1",
            "birthDate": "1985-03-04",
            "snils": "112-233-445 95",
        },
        "organization": {
            "name": "ООО «Ромашка»",
            "address": "101000, г. Москва, ул. Примерная, д. 1",
            "inn": "7700000016",
            "ogrn": "1027700000019",
        },
        "includeClosed": True,
    }
    body.update(changes)
    return body


def find(xml: str, name: str, namespace: str = NS_REQUEST) -> str:
    return etree.fromstring(xml.encode("utf-8")).find(".//{%s}%s" % (namespace, name)).text


def test_preview_builds_both_files_that_pass_the_official_schema():
    with TestClient(app_module.app) as client:
        response = client.post("/fssp/preview", json=payload())
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["environment"] == "SVCDEV"  # тестовый контур svcdev-gostapi
    documents = body["documents"]
    assert set(documents) == {"req.xml", "piev_epgu.xml"}
    assert find(documents["piev_epgu.xml"], "ExternalKey") == "1"
    assert find(documents["piev_epgu.xml"], "TrusteeDoctype") == "07"
    assert find(documents["req.xml"], "ReceiverID", NS_TRANSPORT) == "FSSP10"
    # Предпросмотр ничего не отправляет и маркер не требует.
    schema = fssp_api.schema_path().read_bytes()
    fssp_api.validate_xml(documents["piev_epgu.xml"].encode("utf-8"), schema)


def test_demo_values_and_bad_fields_are_listed_by_field():
    bad = payload(
        applicant={
            "fullName": "Иванов Леонид Иванович",
            "gender": "1",
            "birthDate": "2090-01-01",
            "snils": "72297105196",
        },
        organization={
            "name": "ООО «Ромашка»",
            "address": "0",
            "inn": "7705717",
            "ogrn": "1027700000018",
        },
    )
    with TestClient(app_module.app) as client:
        response = client.post("/fssp/preview", json=bad)
    assert response.status_code == 422
    fields = {item["field"] for item in response.json()["detail"]["errors"]}
    assert fields == {
        "applicant.fullName",
        "applicant.birthDate",
        "applicant.snils",
        "organization.address",
        "organization.inn",
        "organization.ogrn",
    }


def test_submit_reserves_an_order_and_sends_the_archive_with_that_number(recording):
    with TestClient(app_module.app) as client:
        response = client.post("/fssp/submit", json=payload())
    assert response.status_code == 200, response.text
    assert response.json()["orderId"] == "3500290327"

    (order_url, order_call), (push_url, push_call) = recording.calls
    assert order_url.endswith("/api/gusmev/order")
    assert order_call["json"] == {
        "region": "45000000000",
        "serviceCode": "60010153",
        "targetCode": "-60010153",
    }
    assert order_call["headers"]["Authorization"] == "Bearer test-bearer"
    assert push_url.endswith("/api/gusmev/push/chunked")
    files = push_call["files"]
    assert files["file"][0] == "3500290327-archive.zip"
    assert files["orderId"][1] == "3500290327"
    with zipfile.ZipFile(io.BytesIO(files["file"][1])) as archive:
        assert sorted(archive.namelist()) == ["piev_epgu.xml", "req.xml"]
        transport = archive.read("req.xml").decode("utf-8")
        request = archive.read("piev_epgu.xml").decode("utf-8")
    assert find(transport, "OrderId", NS_TRANSPORT) == "3500290327"
    assert find(request, "ExternalKey") == "3500290327"
    assert etree.fromstring(transport.encode("utf-8")).get("Env") == "SVCDEV"


def test_invalid_request_is_refused_before_any_upstream_call(recording):
    with TestClient(app_module.app) as client:
        response = client.post("/fssp/submit", json=payload(caseNumber="23545/20/69025-ИП"))
    assert response.status_code == 422
    assert recording.calls == []


def test_submit_without_esia_token_makes_no_upstream_call(recording, monkeypatch):
    monkeypatch.setattr(app_module, "ACCESS_TKN_ESIA", "")
    with TestClient(app_module.app) as client:
        response = client.post("/fssp/submit", json=payload())
    assert response.status_code == 401
    assert recording.calls == []


def test_course_request_needs_the_case_number_and_goes_to_fssp08_from_an_organization(recording):
    with TestClient(app_module.app) as client:
        missing = client.post("/fssp/preview", json=payload(serviceCode="10000000352"))
        assert missing.status_code == 422
        assert {item["field"] for item in missing.json()["detail"]["errors"]} == {"caseNumber"}
        response = client.post(
            "/fssp/submit", json=payload(serviceCode="10000000352", caseNumber="23545/20/69025-ИП")
        )
    assert response.status_code == 200, response.text
    (_, order_call), (_, push_call) = recording.calls
    assert order_call["json"]["targetCode"] == "-10000000352"
    with zipfile.ZipFile(io.BytesIO(push_call["files"]["file"][1])) as archive:
        assert find(archive.read("req.xml").decode("utf-8"), "ReceiverID", NS_TRANSPORT) == "FSSP08"
        assert find(archive.read("piev_epgu.xml").decode("utf-8"), "DeloNum") == "23545/20/69025-ИП"


def test_personal_and_person_representative_variants_build():
    personal = payload(representation="self", organization=None)
    representative = payload(
        representation="person",
        organization=None,
        representative={
            "document": "04",
            "issuedBy": "Отдел ЗАГС",
            "number": "III-МЮ 123456",
            "issuedOn": "2015-07-10",
            "principal": {
                "fullName": "Петрова Анна Петровна",
                "gender": "2",
                "birthDate": "2015-07-01",
                "snils": "12345678964",
            },
        },
    )
    with TestClient(app_module.app) as client:
        first = client.post("/fssp/preview", json=personal)
        second = client.post("/fssp/preview", json=representative)
    assert first.status_code == second.status_code == 200
    assert "TrusteeDoctype" not in first.json()["documents"]["piev_epgu.xml"]
    assert find(second.json()["documents"]["piev_epgu.xml"], "TrusteeSnils") == "12345678964"


def test_generic_upload_routes_refuse_the_form_built_profiles():
    meta = {"region": "45000000000", "serviceCode": "60010153", "targetCode": "-60010153"}
    files = [("files_upload", ("req.xml", b"<x/>", "application/xml"))]
    with TestClient(app_module.app) as client:
        response = client.post("/push", data={"meta": json.dumps(meta)}, files=files)
    assert response.status_code == 409
    assert "/fssp/submit" in response.json()["detail"]


def test_contracts_list_what_the_form_supports():
    with TestClient(app_module.app) as client:
        body = client.get("/fssp/contracts").json()
    assert body["environment"] == "SVCDEV"
    assert {item["serviceCode"]: item["caseNumberRequired"] for item in body["services"]} == {
        "60010153": False,
        "10000000352": True,
    }


def test_environment_follows_the_epgu_host():
    assert fssp_api.environment_for("https://svcdev-gostapi.test.gosuslugi.ru").value == "SVCDEV"
    assert fssp_api.environment_for("https://www.gosuslugi.ru").value == "PROD"


def test_order_time_is_moscow():
    moment = datetime(2026, 10, 8, 21, 30, tzinfo=timezone.utc)
    documents = fssp_api.build_checked(
        fssp_api.FsspPayload(**payload()),
        order_id=5,
        moment=moment,
        environment=fssp_api.environment_for("https://svcdev-gostapi.test.gosuslugi.ru"),
    )
    transport = documents["req.xml"].decode("utf-8")
    assert find(transport, "Date", NS_TRANSPORT) == "2026-10-09T00:30:00+03:00"
    assert find(transport, "StatementDate", NS_TRANSPORT) == "2026-10-09"
