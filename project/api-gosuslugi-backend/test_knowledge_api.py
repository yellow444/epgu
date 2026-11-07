"""API v1 знаний: чтение, пагинация, problem+json, вход, OpenAPI."""

import json

import pytest
from fastapi.testclient import TestClient

PROBLEM = "application/problem+json"


@pytest.fixture()
def client():
    import app as application

    return TestClient(application.app)


@pytest.fixture(autouse=True)
def _fresh_budget():
    import public_budget

    public_budget.budget.reset()
    yield
    public_budget.budget.reset()


@pytest.fixture()
def anonymous(tmp_path, monkeypatch):
    """Настоящая проверка сессии на пустой временной базе, без cookie."""
    monkeypatch.setenv("AUTH_DB_FILE", str(tmp_path / "auth" / "auth.sqlite3"))
    import auth
    import auth_store

    auth_store._initialized_for = None
    auth.throttle.reset()


def assert_problem(response, status, code):
    assert response.status_code == status, response.text
    assert response.headers["content-type"].startswith(PROBLEM)
    body = response.json()
    assert body["status"] == status
    assert body["code"] == code
    assert body["type"] == "https://epgu.local/problems/" + code
    assert body["title"] and body["detail"]
    assert response.headers["X-EPGU-API-Version"] == "1"
    return body


def test_meta_and_version_header(client):
    response = client.get("/v1/knowledge")
    assert response.status_code == 200
    assert response.headers["X-EPGU-API-Version"] == "1"
    body = response.json()
    assert body["schema_version"] == "1.0"
    assert body["counts"]["routes"] >= 1


def test_routes_route_node_roundtrip(client):
    routes = client.get("/v1/knowledge/routes").json()["items"]
    assert routes and all("node_count" in r for r in routes)
    route = client.get(f"/v1/knowledge/routes/{routes[0]['id']}").json()
    assert route["id"] == routes[0]["id"] and route["nodes"]
    node = client.get(
        f"/v1/knowledge/routes/{route['id']}/nodes/{route['entry_node']}"
    ).json()
    assert node["id"] == route["entry_node"]
    assert "sources_resolved" in node
    for link in node["incoming"]:
        assert set(link) == {"from", "label"}


def test_sources_and_notes(client):
    sources = client.get("/v1/knowledge/sources").json()["items"]
    assert sources
    official = client.get("/v1/knowledge/sources", params={"officiality": "official"}).json()
    assert official["items"] and all(s["officiality"] == "official" for s in official["items"])
    detail = client.get(f"/v1/knowledge/sources/{sources[0]['id']}").json()
    assert detail["id"] == sources[0]["id"] and "used_by" in detail
    notes = client.get("/v1/knowledge/notes").json()["items"]
    assert notes and {"id", "title", "text"} <= set(notes[0])


def test_not_found_is_problem_json(client):
    assert_problem(client.get("/v1/knowledge/routes/no-such-route"), 404, "not_found")
    assert_problem(client.get("/v1/knowledge/routes/no-such/nodes/x"), 404, "not_found")
    assert_problem(client.get("/v1/knowledge/sources/NoSuch"), 404, "not_found")
    assert_problem(client.get("/v1/capabilities/no.such"), 404, "not_found")
    # Неизвестный путь внутри v1 тоже отдаётся как problem+json.
    assert_problem(client.get("/v1/no-such-endpoint"), 404, "not_found")


def test_invalid_parameters_are_422_problem_json(client):
    assert_problem(client.get("/v1/knowledge/search"), 422, "invalid_parameter")
    assert_problem(client.get("/v1/knowledge/search", params={"q": "x", "limit": 0}),
                   422, "invalid_parameter")
    assert_problem(client.get("/v1/knowledge/search", params={"q": "x", "limit": 51}),
                   422, "invalid_parameter")
    assert_problem(client.get("/v1/knowledge/search", params={"q": "x", "limit": "abc"}),
                   422, "invalid_parameter")
    assert_problem(client.get("/v1/knowledge/search", params={"q": "   "}),
                   422, "invalid_parameter")
    assert_problem(client.get("/v1/knowledge/search", params={"q": "api", "cursor": "!!bad"}),
                   422, "invalid_parameter")
    assert_problem(client.get("/v1/knowledge/search", params={"q": "api", "domain": "nope"}),
                   422, "invalid_parameter")
    assert_problem(client.get("/v1/knowledge/sources", params={"officiality": "nope"}),
                   422, "invalid_parameter")


def test_search_items_carry_resolvable_source_ids(client):
    items = client.get("/v1/knowledge/search", params={"q": "api", "limit": 50}).json()["items"]
    assert items and all(isinstance(i["source_ids"], list) for i in items)
    refs = {s for i in items for s in i["source_ids"]}
    assert refs, "в выдаче должна быть хотя бы одна ссылка"
    for sid in sorted(refs):
        assert client.get(f"/v1/knowledge/sources/{sid}").status_code == 200
    spec = client.get("/openapi.json").json()["components"]["schemas"]["SearchItem"]
    assert "source_ids" in spec["required"]


def test_search_pagination_has_no_gaps_or_duplicates(client):
    full = client.get("/v1/knowledge/search", params={"q": "api", "limit": 50}).json()
    assert len(full["items"]) >= 4, "для проверки пагинации нужно хотя бы четыре результата"

    def key(item):
        return (item["type"], item["route_id"], item["node_id"], item["id"])

    collected, cursor, pages = [], None, 0
    while True:
        params = {"q": "api", "limit": 2}
        if cursor:
            params["cursor"] = cursor
        page = client.get("/v1/knowledge/search", params=params).json()
        assert len(page["items"]) <= 2
        collected.extend(page["items"])
        cursor = page["next_cursor"]
        pages += 1
        if not cursor:
            break
        assert pages < 100
    assert pages >= 2
    assert [key(i) for i in collected] == [key(i) for i in full["items"]]
    assert len({key(i) for i in collected}) == len(collected)


def test_cursor_from_another_query_is_rejected(client):
    page = client.get("/v1/knowledge/search", params={"q": "api", "limit": 1}).json()
    assert page["next_cursor"]
    other = client.get("/v1/knowledge/search",
                       params={"q": "сертификат", "limit": 1, "cursor": page["next_cursor"]})
    assert_problem(other, 422, "invalid_parameter")


def test_dataset_matches_package_and_supports_etag(client):
    from epgu_knowledge import load

    kb = load()
    response = client.get("/v1/knowledge/dataset")
    assert response.status_code == 200
    assert response.json() == kb.dataset()
    etag = response.headers["ETag"]
    assert etag == f'"{kb.content_sha256}"'
    assert client.get("/v1/knowledge").json()["content_sha256"] == kb.content_sha256
    again = client.get("/v1/knowledge/dataset", headers={"If-None-Match": etag})
    assert again.status_code == 304 and not again.content
    other = client.get("/v1/knowledge/dataset", headers={"If-None-Match": '"stale"'})
    assert other.status_code == 200


PUBLIC_PATHS = (
    "/v1/knowledge", "/v1/knowledge/dataset", "/v1/knowledge/routes", "/v1/knowledge/routes/epgu-vendor",
    "/v1/knowledge/sources", "/v1/knowledge/notes", "/v1/knowledge/search?q=api",
    "/v1/knowledge/capabilities",
)


@pytest.mark.real_auth
def test_public_knowledge_without_login(client, anonymous):
    for path in PUBLIC_PATHS:
        response = client.get(path)
        assert response.status_code == 200, (path, response.text)
        assert response.headers["X-EPGU-API-Version"] == "1"
        assert "set-cookie" not in response.headers


@pytest.mark.real_auth
def test_installation_registry_still_needs_login(client, anonymous):
    for path in ("/v1/capabilities", "/v1/capabilities/knowledge.search"):
        assert_problem(client.get(path), 401, "unauthenticated")


@pytest.mark.real_auth
def test_public_routes_are_exact_not_prefix(client, anonymous):
    # Методы, кроме GET, и соседние пути не открываются.
    assert client.post("/v1/knowledge/search?q=api").status_code in (401, 405)
    # Несуществующие соседние пути не находятся (404 до проверки входа), данных нет.
    for path in ("/v1/knowledge-admin", "/v1/knowledgex", "/v1"):
        assert client.get(path).status_code == 404
    assert client.get("/v1/capabilities").status_code == 401
    assert client.get("/services").status_code == 401


def test_public_catalog_excludes_private_registrations(client, monkeypatch):
    import capabilities

    monkeypatch.setattr(capabilities, "_private", [])
    capabilities.register(capabilities.Capability(
        id="private.demo.read", title="Частная запись", effect=capabilities.Effect.READ_LOCAL,
        edition="private",
    ))
    public_ids = {c["id"] for c in client.get("/v1/knowledge/capabilities").json()["items"]}
    full_ids = {c["id"] for c in client.get("/v1/capabilities").json()["items"]}
    assert "private.demo.read" in full_ids
    assert "private.demo.read" not in public_ids
    assert public_ids < full_ids


@pytest.mark.real_auth
def test_anonymous_budget_returns_429(client, anonymous, monkeypatch):
    monkeypatch.setenv("EPGU_PUBLIC_RATE_PER_MINUTE", "3")
    for _ in range(3):
        assert client.get("/v1/knowledge").status_code == 200
    blocked = client.get("/v1/knowledge")
    assert_problem(blocked, 429, "rate_limited")
    assert int(blocked.headers["Retry-After"]) >= 1


def test_forwarded_for_ignored_without_trusted_proxy(client, monkeypatch):
    monkeypatch.setenv("EPGU_PUBLIC_RATE_PER_MINUTE", "2")
    monkeypatch.delenv("EPGU_TRUSTED_PROXIES", raising=False)
    for i in range(2):
        headers = {"X-Forwarded-For": f"10.0.0.{i}"}
        assert client.get("/v1/knowledge", headers=headers).status_code == 200
    # Подмена заголовка не даёт нового бюджета.
    spoofed = client.get("/v1/knowledge", headers={"X-Forwarded-For": "10.9.9.9"})
    assert spoofed.status_code == 429


def test_forwarded_for_used_from_trusted_proxy(client, monkeypatch):
    monkeypatch.setenv("EPGU_PUBLIC_RATE_PER_MINUTE", "1")
    monkeypatch.setenv("EPGU_TRUSTED_PROXIES", "testclient")
    assert client.get("/v1/knowledge", headers={"X-Forwarded-For": "1.1.1.1"}).status_code == 200
    assert client.get("/v1/knowledge", headers={"X-Forwarded-For": "2.2.2.2"}).status_code == 200
    assert client.get("/v1/knowledge", headers={"X-Forwarded-For": "1.1.1.1"}).status_code == 429


def test_budget_key_store_is_bounded():
    import public_budget

    b = public_budget.Budget(clock=lambda: 0.0)
    for i in range(public_budget.MAX_KEYS + 50):
        b.take(f"k{i}")
    assert len(b._hits) == public_budget.MAX_KEYS


def test_search_limits_match_package(client):
    from epgu_knowledge import limits as L

    ok = client.get("/v1/knowledge/search", params={"q": "а" * L.MAX_QUERY_LEN})
    assert ok.status_code == 200
    too_long = client.get("/v1/knowledge/search", params={"q": "а" * (L.MAX_QUERY_LEN + 1)})
    assert_problem(too_long, 422, "invalid_parameter")
    long_cursor = client.get("/v1/knowledge/search",
                             params={"q": "api", "cursor": "A" * (L.MAX_CURSOR_LEN + 1)})
    assert_problem(long_cursor, 422, "invalid_parameter")
    long_id = client.get("/v1/knowledge/routes/" + "a" * (L.MAX_ID_LEN + 1))
    assert_problem(long_id, 422, "invalid_parameter")

    params = client.get("/openapi.json").json()["paths"]["/v1/knowledge/search"]["get"]["parameters"]
    by_name = {p["name"]: p["schema"] for p in params}
    assert by_name["q"]["maxLength"] == L.MAX_QUERY_LEN
    assert by_name["limit"]["maximum"] == L.MAX_LIMIT
    cursor = by_name["cursor"]
    cursor = next((x for x in cursor.get("anyOf", [cursor]) if x.get("type") == "string"), cursor)
    assert cursor["maxLength"] == L.MAX_CURSOR_LEN


def test_no_external_effects_from_public_reads(client, monkeypatch):
    """Чтение знаний не трогает сеть и общепроцессное состояние."""
    import socket

    import app as application

    def no_network(*_a, **_k):
        raise AssertionError("обращение к сети из публичного чтения")

    # socket.socket не трогаем: им пользуется цикл событий самого TestClient.
    monkeypatch.setattr(socket, "create_connection", no_network)
    monkeypatch.setattr(socket, "getaddrinfo", no_network)
    names = ("CURRENT_CERT_ID", "ACCESS_TKN_ESIA", "SESSION_GENERATION")
    before = {n: getattr(application, n) for n in names}
    for path in PUBLIC_PATHS:
        assert client.get(path).status_code == 200
    assert {n: getattr(application, n) for n in names} == before


@pytest.mark.real_auth
def test_legacy_routes_keep_their_error_format(client, tmp_path, monkeypatch):
    monkeypatch.setenv("AUTH_DB_FILE", str(tmp_path / "auth" / "auth.sqlite3"))
    import auth
    import auth_store

    auth_store._initialized_for = None
    auth.throttle.reset()
    response = client.get("/services")
    assert response.status_code == 401
    assert not response.headers["content-type"].startswith(PROBLEM)
    assert "detail" in response.json()
    assert "X-EPGU-API-Version" not in response.headers
    assert client.get("/no-such-route").status_code == 404


def test_legacy_validation_error_format_is_unchanged(client):
    response = client.get("/xml")
    assert response.status_code == 422
    assert not response.headers["content-type"].startswith(PROBLEM)
    assert isinstance(response.json()["detail"], list)


def test_openapi_describes_v1_with_typed_schemas(client):
    spec = client.get("/openapi.json").json()
    paths = {p: v for p, v in spec["paths"].items() if p.startswith("/v1/")}
    assert "/v1/knowledge/search" in paths and "/v1/capabilities" in paths
    for path, operations in paths.items():
        for method, operation in operations.items():
            ok = operation["responses"]["200"]["content"]["application/json"]["schema"]
            assert ok, (method, path)


# Политика схемы (уточнение к finding #8): публичная core-схема. /openapi.json
# и /docs открыты, но описывают только безопасные публичные контракты;
# публичная документация не делает сами операции публичными.
_PRIVATE_MARKERS = ("tenancy", "multiorg", "testep", "entitlement")
_SECRET_WORDS = ("password", "passwd", "secret", "token", "pin", "api_key", "apikey",
                 "authorization")


@pytest.mark.real_auth
@pytest.mark.parametrize("path", ["/openapi.json", "/docs"])
def test_schema_and_docs_are_public(client, anonymous, path):
    response = client.get(path)
    assert response.status_code == 200
    assert "set-cookie" not in response.headers


@pytest.mark.real_auth
def test_public_docs_do_not_open_operations(client, anonymous):
    assert client.get("/openapi.json").status_code == 200
    assert client.get("/services").status_code == 401
    assert_problem(client.get("/v1/capabilities"), 401, "unauthenticated")


def test_public_schema_has_no_private_paths_or_secret_defaults(client):
    spec = client.get("/openapi.json").json()
    text = json.dumps(spec["paths"], ensure_ascii=False).lower()
    for marker in _PRIVATE_MARKERS:
        assert marker not in text, marker
    for server in spec.get("servers", []):
        assert server["url"].startswith("/"), "только относительный префикс, без адреса установки"

    found = []

    def walk(node, path, hint=""):
        if isinstance(node, dict):
            name = str(node.get("name", hint)).lower()
            for key, value in node.items():
                if key in ("default", "example") and isinstance(value, str) and value:
                    if any(w in name for w in _SECRET_WORDS):
                        found.append((path, value))
                walk(value, f"{path}/{key}", name if key == "schema" else key)
        elif isinstance(node, list):
            for i, value in enumerate(node):
                walk(value, f"{path}/{i}", hint)

    walk(spec, "")
    assert not found, found


def test_openapi_error_media_types_match_responses(client):
    """Опубликованный media type ошибок v1 совпадает с реальными ответами."""
    spec = client.get("/openapi.json").json()
    for path, operations in spec["paths"].items():
        if not path.startswith("/v1/"):
            continue
        responses = [
            (status, resp)
            for operation in operations.values()
            for status, resp in operation["responses"].items()
        ]
        for status, resp in responses:
            if status.startswith("2"):
                assert list(resp["content"]) == ["application/json"], (path, status)
                continue
            if status.startswith("3"):
                assert "content" not in resp, (path, status)
                continue
            assert list(resp["content"]) == [PROBLEM], (path, status)
            schema = resp["content"][PROBLEM]["schema"]
            assert {"type", "title", "status", "code", "detail"} <= set(schema["required"])

    real = {
        ("/v1/knowledge/routes/{route_id}", "404"): client.get("/v1/knowledge/routes/no-such"),
        ("/v1/knowledge/search", "422"): client.get("/v1/knowledge/search", params={"limit": 0}),
        ("/v1/capabilities/{capability_id}", "404"): client.get("/v1/capabilities/no.such"),
    }
    for (path, status), response in real.items():
        assert response.status_code == int(status)
        declared = spec["paths"][path]["get"]["responses"][status]["content"]
        assert response.headers["content-type"].split(";")[0] in declared, (path, status)
        body = response.json()
        assert set(declared[PROBLEM]["schema"]["required"]) <= set(body)


@pytest.mark.real_auth
def test_openapi_401_matches_real_response(client, anonymous):
    spec = client.get("/openapi.json").json()
    declared = spec["paths"]["/v1/capabilities"]["get"]["responses"]["401"]["content"]
    response = client.get("/v1/capabilities")
    assert response.status_code == 401
    assert response.headers["content-type"].split(";")[0] in declared
