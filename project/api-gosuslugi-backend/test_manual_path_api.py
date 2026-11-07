"""Ручной маршрут по HTTP: публичное чтение одного канона, без значений и без записи."""
import json
from pathlib import Path

import pytest
from epgu_knowledge import KnowledgeError, load, load_manual_path

import auth_api
import capabilities
import knowledge_api
from test_knowledge_api import _fresh_budget, anonymous, assert_problem, client  # noqa: F401

URL = "/v1/knowledge/manual-path"
CLIENT_COPY = Path(__file__).resolve().parents[1] / "api-gosuslugi-client/src/components/PublicSetup/manual_path.v1.json"


@pytest.mark.real_auth
def test_public_without_login_or_cookie(client, anonymous):  # noqa: F811
    response = client.get(URL)
    assert response.status_code == 200
    assert "set-cookie" not in response.headers
    assert response.headers["X-EPGU-API-Version"] == "1"
    assert response.headers["Cache-Control"] == "public, max-age=300"


@pytest.mark.real_auth
def test_opening_this_route_does_not_open_neighbours(client, anonymous):  # noqa: F811
    for path in ("/v1/knowledge/manual-path/x", "/v1/knowledge/manual-pathx"):
        assert client.get(path).status_code in (401, 404)
    assert client.get("/v1/capabilities").status_code == 401
    assert client.get("/v1/admin/operations/plans/plan_" + "1" * 32).status_code == 401
    assert client.get("/services").status_code == 401


def test_only_the_exact_endpoint_is_public(client):  # noqa: F811
    names = {getattr(e, "__name__", "") for e in auth_api.public_endpoints}
    assert "manual_path" in names


@pytest.mark.real_auth
@pytest.mark.parametrize("method", ["post", "put", "patch", "delete"])
def test_no_write_methods(client, anonymous, method):  # noqa: F811
    assert getattr(client, method)(URL).status_code in (401, 405)


def test_answer_is_the_canon_shown_by_the_interface(client):  # noqa: F811
    body = client.get(URL).json()
    assert body == load_manual_path().document()
    assert body == json.loads(CLIENT_COPY.read_text(encoding="utf-8"))


def test_own_etag_and_304(client):  # noqa: F811
    first = client.get(URL)
    etag = first.headers["ETag"]
    assert etag == f'"{load_manual_path().content_sha256}"'
    assert etag != f'"{load().content_sha256}"'
    again = client.get(URL, headers={"If-None-Match": etag})
    assert again.status_code == 304 and not again.content
    assert again.headers["ETag"] == etag
    assert client.get(URL, headers={"If-None-Match": '"stale"'}).status_code == 200


def test_values_in_the_query_change_nothing(client):  # noqa: F811
    base = client.get(URL)
    probe = client.get(URL, params={"organizationOid": "VALUE_MARKER", "contour": "PROD"})
    assert probe.status_code == 200
    assert probe.content == base.content
    assert b"VALUE_MARKER" not in probe.content


def test_shares_the_public_budget(client, anonymous, monkeypatch):  # noqa: F811
    monkeypatch.setenv("EPGU_PUBLIC_RATE_PER_MINUTE", "2")
    assert client.get(URL).status_code == 200
    assert client.get(URL).status_code == 200
    assert_problem(client.get(URL), 429, "rate_limited")


def test_broken_bundle_is_a_problem_without_details(client, monkeypatch):  # noqa: F811
    def broken():
        raise KnowledgeError("invalid_dataset", "локальная подробность")

    monkeypatch.setattr(knowledge_api, "load_manual_path", broken)
    response = client.get(URL)
    body = assert_problem(response, 503, "dataset_unavailable")
    assert "локальная подробность" not in json.dumps(body, ensure_ascii=False)


def test_listed_in_openapi_as_a_read_without_parameters(client):  # noqa: F811
    operation = client.get("/openapi.json").json()["paths"][URL]
    assert set(operation) == {"get"}
    assert not operation["get"].get("parameters")
    assert "requestBody" not in operation["get"]


def test_registry_describes_what_exists():
    manual = capabilities.get("knowledge.manual_path")
    assert manual.api == ("GET " + URL,) and manual.ui == "PublicSetup"
    assert manual.requires == () and manual.mcp_profile.value == "knowledge"
    assert manual.scopes == () and manual.gates == () and manual.machine == "none"
    links = capabilities.get("knowledge.official_links")
    assert links.api == ("GET " + URL,)
    assert "knowledge.sources" not in links.notes
    assert capabilities.get("operation.review").ui == "PlanReviewModal"
    assert capabilities.get("operation.approve").ui == "PlanReviewModal"
    assert capabilities.get("operation.approve").mcp_profile.value == "none"
    assert capabilities.get("knowledge.sources").ui and capabilities.get("knowledge.notes").ui


def test_official_links_are_really_served(client):  # noqa: F811
    served = {link["url"] for link in client.get(URL).json()["links"]}
    assert len(served) == 6
    assert "https://svcdev-partners.test.gosuslugi.ru/powers" in served
    assert "https://esia.gosuslugi.ru/console/tech" in served
