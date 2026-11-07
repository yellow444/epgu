"""Публичный расчёт без внешних проверок и мутаций: HTTP и пакет дают один ответ."""
import json

import pytest
from epgu_knowledge import (
    KnowledgeError,
    connection_card_input_schema,
    connection_card_output_schema,
    load_connection_card,
)
from jsonschema import Draft202012Validator

import auth_api
import capabilities
import knowledge_api
from test_knowledge_api import _fresh_budget, anonymous, assert_problem, client  # noqa: F401

URL = "/v1/knowledge/connection-card"
EVALUATE = URL + "/evaluate"
PAYLOAD = {"goal": "obtain_api_key", "facts": {"same_context": "reported_yes", "power_issued": "reported_yes"}}


@pytest.mark.real_auth
def test_public_exact_routes_without_session_or_cookie(client, anonymous):  # noqa: F811
    for response in (client.get(URL), client.post(EVALUATE, json=PAYLOAD)):
        assert response.status_code == 200
        assert "set-cookie" not in response.headers
        assert response.headers["X-EPGU-API-Version"] == "1"
    for path in (URL + "x", EVALUATE + "/x", "/v1/capabilities", "/services"):
        assert client.get(path).status_code in (401, 404)
    assert client.delete(EVALUATE).status_code in (401, 405)


def test_static_definition_etag_and_calculation(client):  # noqa: F811
    static = client.get(URL)
    assert static.json() == load_connection_card().document()
    assert client.get(URL, headers={"If-None-Match": static.headers["ETag"]}).status_code == 304
    answer = client.post(EVALUATE, json=PAYLOAD)
    assert answer.json() == load_connection_card().evaluate(PAYLOAD)
    Draft202012Validator(connection_card_output_schema()).validate(answer.json())
    assert answer.headers["Cache-Control"] == "no-store"
    assert answer.headers["Pragma"] == "no-cache"
    assert "ETag" not in answer.headers


@pytest.mark.parametrize("payload,expected_rule", [
    ({"goal": "request_power", "facts": {"same_context": "reported_yes", "system_registered": "reported_yes",
        "cert_bound": "reported_yes", "application_submitted": "reported_no"}}, "request_power"),
    ({"goal": "check_signature", "facts": {"same_context": "reported_yes", "local_signature_valid": "reported_yes",
        "server_signature_accepted": "reported_no", "cert_bound": "reported_yes",
        "signature_context_checked": "reported_yes", "error_recorded": "reported_yes"}}, "signature_rejected_unexplained"),
    ({"goal": "obtain_api_key", "facts": {"same_context": "reported_yes", "application_submitted": "reported_yes",
        "application_received": "reported_yes"}}, "application_pending"),
])
def test_three_scenarios_are_exactly_the_package_result(client, payload, expected_rule):  # noqa: F811
    response = client.post(EVALUATE, json=payload)
    assert response.status_code == 200
    assert response.json() == load_connection_card().evaluate(payload)
    assert response.json()["rule"]["id"] == expected_rule
    assert response.json()["basis"] == "caller_reported"


@pytest.mark.parametrize("payload", [None, {}, [], {"goal": "PROD"},
    {"goal": "request_power", "SECRET_MARKER": "SECRET_MARKER"},
    {"goal": "request_power", "facts": {"same_context": "SECRET_MARKER"}},
    {"goal": "request_power", "facts": {"__proto__": "reported_yes"}}])
def test_invalid_input_is_private_error(client, payload):  # noqa: F811
    response = client.post(EVALUATE, json=payload)
    assert_problem(response, 422, "invalid_parameter")
    assert response.headers["Cache-Control"] == "no-store"
    assert "SECRET_MARKER" not in response.text


def test_malformed_json_is_private_error(client):  # noqa: F811
    response = client.post(EVALUATE, content='{"SECRET_MARKER":', headers={"Content-Type": "application/json"})
    assert_problem(response, 422, "invalid_parameter")
    assert response.headers["Cache-Control"] == "no-store"
    assert "SECRET_MARKER" not in response.text


def test_public_budget_and_error_cache(client, monkeypatch):  # noqa: F811
    monkeypatch.setenv("EPGU_PUBLIC_RATE_PER_MINUTE", "1")
    assert client.get(URL).status_code == 200
    response = client.post(EVALUATE, json=PAYLOAD)
    assert_problem(response, 429, "rate_limited")
    assert response.headers["Cache-Control"] == "no-store"


def test_broken_rules_not_disclosed(client, monkeypatch):  # noqa: F811
    def broken():
        raise KnowledgeError("invalid_dataset", "PRIVATE_DETAIL")
    monkeypatch.setattr(knowledge_api, "load_connection_card", broken)
    response = client.post(EVALUATE, json=PAYLOAD)
    assert_problem(response, 503, "dataset_unavailable")
    assert response.headers["Cache-Control"] == "no-store"
    assert "PRIVATE_DETAIL" not in response.text


def test_openapi_and_capability_are_exact(client):  # noqa: F811
    paths = client.get("/openapi.json").json()["paths"]
    schema = paths[EVALUATE]["post"]["requestBody"]["content"]["application/json"]["schema"]
    # FastAPI добавляет заголовок поля Body; ограничения остаются общими.
    schema.pop("title", None)
    assert schema == connection_card_input_schema()
    output = paths[EVALUATE]["post"]["responses"]["200"]["content"]["application/json"]["schema"]
    assert output == connection_card_output_schema()
    assert set(paths[URL]) == {"get"} and set(paths[EVALUATE]) == {"post"}
    cap = capabilities.get("knowledge.connection_card")
    assert cap.requires == () and cap.scopes == () and cap.gates == ()
    assert cap.mcp_profile.value == "knowledge"
    assert cap.api == ("GET " + URL, "POST " + EVALUATE)
    assert "caller_reported" in cap.notes


def test_query_does_not_override_body(client):  # noqa: F811
    answer = client.post(EVALUATE + "?contour=PROD&key=SECRET_MARKER", json=PAYLOAD)
    assert answer.json() == load_connection_card().evaluate(PAYLOAD)
    assert "SECRET_MARKER" not in json.dumps(answer.json())


@pytest.mark.real_auth
def test_public_post_does_not_weaken_get_allowlist(client, anonymous):  # noqa: F811
    assert all(getattr(endpoint, "__name__", "") == "connection_card_evaluate"
               for endpoint in auth_api.public_post_endpoints)
    assert client.post("/v1/knowledge/manual-path", json=PAYLOAD).status_code in (401, 405)
    assert client.post("/v1/knowledge/dataset", json=PAYLOAD).status_code in (401, 405)
    assert client.post("/v1/operations/plans", json=PAYLOAD).status_code == 401


def test_origin_rejection_does_not_cache_flags(client):  # noqa: F811
    response = client.post(EVALUATE, json=PAYLOAD, headers={"Origin": "https://untrusted.invalid"})
    assert response.status_code == 403
    assert response.headers["Cache-Control"] == "no-store"
