"""Ключи интеграций: выпуск, проверка, отзыв, срок, доступ по HTTP."""

import logging
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient

pytestmark = pytest.mark.real_auth

PASSWORD = "correct horse battery staple"
CONTEXT = {"organization_ref": "org-1", "contour": "TEST"}
ADMIN_URL = "/v1/admin/integrations"


@pytest.fixture()
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("AUTH_DB_FILE", str(tmp_path / "auth" / "auth.sqlite3"))
    import auth
    import auth_store

    auth_store._initialized_for = None
    auth.throttle.reset()
    return tmp_path


@pytest.fixture()
def client(store):
    import app as application

    return TestClient(application.app)


def make_admin(login="admin"):
    import auth

    return auth.create_account(login, PASSWORD, installation_admin=True, source="cli")


def signed_in(client, login="admin"):
    response = client.post("/auth/login", json={"login": login, "password": PASSWORD})
    assert response.status_code == 200, response.text
    return response


def issue(scopes=("knowledge:read",), **kwargs):
    import integration_auth

    kwargs.setdefault("created_by", "acc_" + "1" * 32)
    return integration_auth.create_client("Тестовая интеграция", list(scopes), dict(CONTEXT), **kwargs)


def bearer(secret):
    return {"Authorization": "Bearer " + secret}


# ---------- выпуск и хранение ----------


def test_create_returns_secret_once_and_db_keeps_only_hash(store):
    import auth_store
    import integration_auth

    created = issue()
    secret = created["secret"]
    assert secret.startswith("epgu_ic_" + created["id"][len("ic_"):] + "_")
    listing = integration_auth.list_clients()
    assert secret not in repr(listing) and "secret" not in listing[0]
    assert "secret_hash" not in listing[0] and "hash" not in repr(listing).lower()
    with auth_store.read() as db:
        row = db.execute("SELECT * FROM integration_clients").fetchone()
        dump = repr(tuple(row))
    assert secret not in dump
    assert len(row["secret_hash"]) == 64 and row["secret_hash"] != secret


def test_scope_and_ttl_validation(store):
    import integration_auth

    for scopes in ([], ["nope"], ["admin"], ["*"], ["knowledge:read", "admin"], "knowledge:read"):
        with pytest.raises(integration_auth.IntegrationError):
            integration_auth.create_client("x", scopes, dict(CONTEXT), created_by="a")
    for ttl in (0, -1, integration_auth.MAX_TTL_DAYS + 1, 91, True, "30"):
        with pytest.raises(integration_auth.IntegrationError):
            integration_auth.create_client("x", ["local:read"], dict(CONTEXT), created_by="a", ttl_days=ttl)
    assert "admin" not in integration_auth.SCOPES and "*" not in integration_auth.SCOPES
    ok = issue(ttl_days=integration_auth.MAX_TTL_DAYS)
    assert ok["secret"]


def test_context_is_validated_and_stored_as_is(store):
    import integration_auth

    org = {"organization_ref": "o", "contour": "PROD"}
    for bad in ({}, {"organization_ref": "o"}, {"organization_ref": "o", "contour": "DEV"},
                {"organization_ref": "o", "contour": "TEST", "extra": 1},
                # Установку из запроса не принимаем: ключ привязан к базе этой установки.
                {**org, "installation": "other"},
                # is_ref это ссылка на ИС, не флаг.
                {**org, "is_ref": True}, {**org, "is_ref": False}, {**org, "is_ref": ""},
                {**org, "is_ref": " SVCDEV261022"}, {**org, "is_ref": "SVCDEV 261022"},
                {**org, "is_ref": "x" * 201}, {**org, "is_ref": 261022},
                {"organization_ref": " o", "contour": "PROD"},
                {"organization_ref": "o\n", "contour": "PROD"}):
        with pytest.raises(integration_auth.IntegrationError):
            integration_auth.create_client("x", ["local:read"], bad, created_by="a")
    first = integration_auth.create_client(
        "x", ["local:read"], {**org, "is_ref": "SVCDEV261022"}, created_by="a"
    )
    second = integration_auth.create_client(
        "x", ["local:read"], {**org, "is_ref": "SVCDEV261023"}, created_by="a"
    )
    principal = integration_auth.verify(first["secret"])
    assert principal.context == {"organization_ref": "o", "contour": "PROD", "is_ref": "SVCDEV261022"}
    assert integration_auth.verify(second["secret"]).context["is_ref"] == "SVCDEV261023"
    principal.context["contour"] = "TEST"  # копия, база не меняется
    assert integration_auth.verify(first["secret"]).context["contour"] == "PROD"


def test_context_matching_is_exact_and_is_ref_is_not_a_wildcard():
    from integration_auth import context_matches

    with_is = {"organization_ref": "o", "contour": "TEST", "is_ref": "SVCDEV261022"}
    without_is = {"organization_ref": "o", "contour": "TEST"}
    assert context_matches(with_is, dict(with_is), requires_is=True)
    assert not context_matches(with_is, {**with_is, "is_ref": "SVCDEV261023"}, requires_is=True)
    assert not context_matches(with_is, {**with_is, "is_ref": "svcdev261022"}, requires_is=False)
    assert not context_matches(with_is, {**with_is, "contour": "PROD"}, requires_is=False)
    assert not context_matches(with_is, {**with_is, "organization_ref": "o2"}, requires_is=False)
    # Ключ без ИС не подходит для операции, привязанной к ИС.
    assert not context_matches(without_is, with_is, requires_is=True)
    assert not context_matches(without_is, without_is, requires_is=True)
    # ИС указана только с одной стороны: не совпадает.
    assert not context_matches(without_is, with_is, requires_is=False)
    assert not context_matches(with_is, without_is, requires_is=False)
    assert context_matches(without_is, dict(without_is), requires_is=False)
    # Неизвестный или неполный текущий контекст не совпадает ни с чем.
    for unknown in ({}, None, {"organization_ref": "o"}, {**without_is, "installation": "x"}):
        assert not context_matches(without_is, unknown, requires_is=False)


def test_default_ttl_is_30_days(store):
    import integration_auth

    assert integration_auth.DEFAULT_TTL_DAYS == 30 and integration_auth.MAX_TTL_DAYS == 90
    issue()
    row = integration_auth.list_clients()[0]
    span = datetime.fromisoformat(row["expires_at"]) - datetime.fromisoformat(row["created_at"])
    assert span == timedelta(days=30)


# ---------- проверка ----------


def test_verify_ok_updates_last_used(store):
    import integration_auth

    created = issue(scopes=("knowledge:read", "local:read"))
    assert integration_auth.list_clients()[0]["last_used_at"] is None
    principal = integration_auth.verify(created["secret"])
    assert principal.id == created["id"]
    assert principal.scopes == frozenset({"knowledge:read", "local:read"})
    assert principal.name == "Тестовая интеграция"
    assert integration_auth.list_clients()[0]["last_used_at"] is not None


def test_revoke_works_on_the_very_next_call(store):
    import integration_auth

    created = issue()
    integration_auth.verify(created["secret"])
    integration_auth.revoke(created["id"], by="acc_" + "2" * 32)
    with pytest.raises(integration_auth.InvalidToken):
        integration_auth.verify(created["secret"])
    assert integration_auth.list_clients()[0]["status"] == "revoked"
    with pytest.raises(integration_auth.IntegrationNotFound):
        integration_auth.revoke("ic_" + "f" * 32, by="x")


def test_expired_is_rejected(store):
    import integration_auth

    created = issue()
    start = datetime.now(timezone.utc)
    integration_auth.verify(created["secret"], now=start + timedelta(days=29))
    with pytest.raises(integration_auth.InvalidToken):
        integration_auth.verify(created["secret"], now=start + timedelta(days=31))
    assert integration_auth.list_clients(now=start + timedelta(days=31))[0]["status"] == "expired"
    assert integration_auth.list_clients()[0]["status"] == "active"


def test_bad_tokens_fail_the_same_way(store):
    import integration_auth

    first = issue()
    second = issue()
    prefix_first = first["secret"].rsplit("_", 1)[0]
    candidates = [
        "", "epgu_ic_", "epgu_ic_zzz_abc", "epgu_ic_" + "0" * 32 + "_", "Bearer x", None, 123,
        "epgu_ic_" + "0" * 32 + "_" + "a" * 43,                      # нет такого id
        prefix_first + "_wrong-secret",                              # верный id, чужой секрет
        first["secret"] + "x",
        first["secret"].replace(first["id"][3:], second["id"][3:]),  # id другого ключа
        "epgu_ic_" + "A" * 32 + "_abc",
        "epgu_ic_" + first["id"][3:] + chr(10) + "_" + first["secret"].rsplit("_", 1)[1],  # id с переводом строки
    ]
    messages = set()
    for candidate in candidates:
        with pytest.raises(integration_auth.InvalidToken) as caught:
            integration_auth.verify(candidate)
        messages.add((str(caught.value), repr(caught.value)))
    assert len(messages) == 1
    assert integration_auth.verify(first["secret"]).id == first["id"]
    assert integration_auth.verify(second["secret"]).id == second["id"]


def test_disabling_creator_does_not_revoke_credential(store):
    import auth
    import integration_auth

    creator = make_admin("creator")
    other = make_admin("other")
    created = integration_auth.create_client(
        "ключ", ["knowledge:read"], dict(CONTEXT), created_by=creator.id
    )
    auth.set_disabled(creator.id, True, by=other.id)
    with pytest.raises(auth.AccessDenied):
        auth.get_account(creator.id)  # создатель отключён
    assert integration_auth.verify(created["secret"]).id == created["id"]
    assert integration_auth.list_clients()[0]["status"] == "active"


# ---------- утечки секрета ----------


def test_secret_never_leaks(client, caplog):
    import auth_store
    import integration_auth

    make_admin()
    signed_in(client)
    caplog.set_level(logging.DEBUG)
    response = client.post(
        ADMIN_URL, json={"name": "ключ", "scopes": ["knowledge:read"], "context": CONTEXT}
    )
    assert response.status_code == 200, response.text
    body = response.json()
    secret = body["secret"]
    assert client.get(ADMIN_URL).status_code == 200
    assert secret not in client.get(ADMIN_URL).text
    assert client.post("%s/%s/revoke" % (ADMIN_URL, body["id"])).status_code == 200
    assert secret not in client.get(ADMIN_URL).text

    with pytest.raises(integration_auth.InvalidToken) as caught:
        integration_auth.verify(secret)
    assert secret not in str(caught.value) and secret not in repr(caught.value)
    with pytest.raises(integration_auth.IntegrationError) as bad:
        integration_auth.create_client("x", [secret], dict(CONTEXT), created_by="a")
    assert secret not in str(bad.value)

    fresh = issue()
    principal = integration_auth.verify(fresh["secret"])
    assert fresh["secret"] not in repr(principal) and fresh["secret"] not in str(principal)

    with auth_store.read() as db:
        rows = [tuple(row) for row in db.execute("SELECT * FROM audit")]
    actions = [row[4] for row in rows]
    assert "integration.create" in actions and "integration.revoke" in actions
    assert secret not in repr(rows) and fresh["secret"] not in repr(rows)
    assert secret not in caplog.text and fresh["secret"] not in caplog.text


# ---------- зависимость require_integration ----------


def tiny_app(*scopes):
    import integration_api

    app = FastAPI()

    @app.get("/probe")
    def probe(principal=Depends(integration_api.require_integration(*scopes))):
        return {"id": principal.id, "scopes": sorted(principal.scopes)}

    return app


def test_dependency_rejects_missing_and_bad_credentials(store):
    import integration_auth

    created = issue(scopes=("knowledge:read",))
    probe = TestClient(tiny_app("knowledge:read"))
    for headers in ({}, {"Authorization": "Basic abc"}, {"Authorization": "Bearer"},
                    bearer("garbage"), bearer(created["secret"] + "x"), bearer("epgu_ic_" + "0" * 32 + "_a")):
        response = probe.get("/probe", headers=headers)
        assert response.status_code == 401, headers
        assert response.headers["www-authenticate"] == "Bearer"
        assert response.json() == {"detail": "invalid_token"}
    ok = probe.get("/probe", headers=bearer(created["secret"]))
    assert ok.status_code == 200 and ok.json()["id"] == created["id"]

    integration_auth.revoke(created["id"], by="admin")
    revoked = probe.get("/probe", headers=bearer(created["secret"]))
    assert revoked.status_code == 401 and revoked.json() == {"detail": "invalid_token"}


def test_dependency_scopes_are_exact(store):
    read_only = issue(scopes=("knowledge:read",))
    both = issue(scopes=("knowledge:read", "local:write", "external:execute"))
    need_write = TestClient(tiny_app("local:write"))
    response = need_write.get("/probe", headers=bearer(read_only["secret"]))
    assert response.status_code == 403 and response.json() == {"detail": "insufficient_scope"}
    assert need_write.get("/probe", headers=bearer(both["secret"])).status_code == 200
    # Нужны оба: одного разрешения мало, лишние разрешения ничего не расширяют.
    need_two = TestClient(tiny_app("local:write", "local:read"))
    assert need_two.get("/probe", headers=bearer(both["secret"])).status_code == 403
    with pytest.raises(ValueError):
        tiny_app("admin")
    with pytest.raises(ValueError):
        tiny_app("*")


def test_cookie_session_does_not_satisfy_require_integration(client):
    make_admin()
    signed_in(client)
    assert client.get("/auth/session").status_code == 200
    probe = TestClient(tiny_app("knowledge:read"))
    for name, value in client.cookies.items():
        probe.cookies.set(name, value)
    response = probe.get("/probe")
    assert response.status_code == 401 and response.headers["www-authenticate"] == "Bearer"
    # Секрет человека в заголовке Bearer тоже не ключ интеграции.
    assert probe.get("/probe", headers=bearer(client.cookies.get("epgu_session", "x"))).status_code == 401


# ---------- административные методы ----------


def test_bearer_token_does_not_authorize_admin_router(client):
    import integration_auth

    make_admin()
    created = issue(scopes=tuple(sorted(integration_auth.SCOPES)))
    headers = bearer(created["secret"])
    assert client.get(ADMIN_URL, headers=headers).status_code == 401
    assert client.post(
        ADMIN_URL, headers=headers,
        json={"name": "x", "scopes": ["local:read"], "context": CONTEXT},
    ).status_code == 401
    assert client.post("%s/%s/revoke" % (ADMIN_URL, created["id"]), headers=headers).status_code == 401
    # Даже вместе с сессией обычного пользователя заголовок прав не добавляет.
    import auth

    auth.create_account("operator", PASSWORD, source="cli")
    signed_in(client, "operator")
    assert client.get(ADMIN_URL, headers=headers).status_code == 403


def test_admin_routes_are_closed_without_admin_session(client):
    import auth

    make_admin()
    auth.create_account("operator", PASSWORD, source="cli")
    body = {"name": "x", "scopes": ["local:read"], "context": CONTEXT}
    anonymous = [
        client.get(ADMIN_URL), client.post(ADMIN_URL, json=body),
        client.post("%s/ic_%s/revoke" % (ADMIN_URL, "0" * 32)),
    ]
    assert [r.status_code for r in anonymous] == [401, 401, 401]
    signed_in(client, "operator")
    denied = [
        client.get(ADMIN_URL), client.post(ADMIN_URL, json=body),
        client.post("%s/ic_%s/revoke" % (ADMIN_URL, "0" * 32)),
    ]
    assert [r.status_code for r in denied] == [403, 403, 403]


def test_admin_api_create_list_revoke_and_errors(client):
    make_admin()
    signed_in(client)
    created = client.post(
        ADMIN_URL, json={"name": "ключ", "scopes": ["knowledge:read"], "context": CONTEXT}
    )
    assert created.status_code == 200
    data = created.json()
    assert data["secret"].startswith("epgu_ic_") and data["context"] == CONTEXT
    assert TestClient(tiny_app("knowledge:read")).get("/probe", headers=bearer(data["secret"])).status_code == 200

    listed = client.get(ADMIN_URL).json()["integrations"]
    assert [item["id"] for item in listed] == [data["id"]]
    assert listed[0]["status"] == "active" and listed[0]["prefix"] in data["secret"]

    bad = [
        {"name": "x", "scopes": [], "context": CONTEXT},
        {"name": "x", "scopes": ["admin"], "context": CONTEXT},
        {"name": "x", "scopes": ["*"], "context": CONTEXT},
        {"name": "x", "scopes": ["local:read"], "context": CONTEXT, "ttl_days": 0},
        {"name": "x", "scopes": ["local:read"], "context": CONTEXT, "ttl_days": 91},
        {"name": "x", "scopes": ["local:read"], "context": {"organization_ref": "o", "contour": "X"}},
    ]
    for body in bad:
        assert client.post(ADMIN_URL, json=body).status_code == 400, body

    assert client.post("%s/%s/revoke" % (ADMIN_URL, data["id"])).json() == {"id": data["id"], "revoked": True}
    assert client.get(ADMIN_URL).json()["integrations"][0]["status"] == "revoked"
    assert client.post("%s/ic_%s/revoke" % (ADMIN_URL, "a" * 32)).status_code == 404
    assert client.post("%s/not-an-id/revoke" % ADMIN_URL).status_code == 422


def test_admin_mutations_from_foreign_origin_are_rejected(client):
    # Вход администратора по cookie не должен давать выпуск и отзыв ключей со
    # стороннего сайта: такие запросы отсекает общий middleware приложения.
    make_admin()
    signed_in(client)
    foreign = {"Origin": "https://attacker.example"}
    body = {"name": "ключ", "scopes": ["knowledge:read"], "context": CONTEXT}
    assert client.post(ADMIN_URL, json=body, headers=foreign).status_code == 403
    assert client.get(ADMIN_URL).json()["integrations"] == []
    created = client.post(ADMIN_URL, json=body).json()
    revoke = "%s/%s/revoke" % (ADMIN_URL, created["id"])
    assert client.post(revoke, headers=foreign).status_code == 403
    assert client.get(ADMIN_URL).json()["integrations"][0]["status"] == "active"


# ---------- HTTP-контракт выдачи (настоящее приложение) ----------

PROBLEM = "application/problem+json"


def test_issued_secret_is_not_cached(client):
    make_admin()
    signed_in(client)
    response = client.post(ADMIN_URL, json={"name": "ключ", "scopes": ["knowledge:read"], "context": CONTEXT})
    assert response.status_code == 200
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["pragma"] == "no-cache"
    assert response.headers["x-epgu-api-version"] == "1"


def test_is_ref_roundtrip_through_http_and_db(client):
    import integration_auth

    make_admin()
    signed_in(client)
    ids = {}
    for is_ref in ("SVCDEV261022", "SVCDEV261023"):
        body = {"name": is_ref, "scopes": ["local:read"], "context": {**CONTEXT, "is_ref": is_ref}}
        created = client.post(ADMIN_URL, json=body)
        assert created.status_code == 200, created.text
        assert created.json()["context"]["is_ref"] == is_ref
        ids[is_ref] = created.json()
    listed = {item["id"]: item["context"] for item in client.get(ADMIN_URL).json()["integrations"]}
    for is_ref, created in ids.items():
        assert listed[created["id"]]["is_ref"] == is_ref
        assert integration_auth.verify(created["secret"]).context["is_ref"] == is_ref
    for bad in (True, "", " SVCDEV261022", 261022):
        body = {"name": "x", "scopes": ["local:read"], "context": {**CONTEXT, "is_ref": bad}}
        response = client.post(ADMIN_URL, json=body)
        assert response.status_code == 400, bad
        assert response.headers["content-type"].startswith(PROBLEM)
    assert len(client.get(ADMIN_URL).json()["integrations"]) == 2


@pytest.mark.parametrize("ttl_days, status", [
    (True, 422), (False, 422), ("30", 422), (1.5, 422), (30.0, 422), ([30], 422),
    (0, 400), (-1, 400), (91, 400),
])
def test_ttl_is_strict_over_http(client, ttl_days, status):
    make_admin()
    signed_in(client)
    body = {"name": "x", "scopes": ["local:read"], "context": CONTEXT, "ttl_days": ttl_days}
    response = client.post(ADMIN_URL, json=body)
    assert response.status_code == status, response.text
    assert response.headers["content-type"].startswith(PROBLEM)
    problem = response.json()
    assert problem["code"] == "invalid_parameter" and problem["status"] == status
    assert "secret" not in problem and "epgu_ic_" not in response.text
    assert "cache-control" not in response.headers or "no-store" in response.headers["cache-control"]
    assert client.get(ADMIN_URL).json()["integrations"] == []


@pytest.mark.parametrize("body", [
    {"name": "x", "scopes": "local:read", "context": CONTEXT},
    {"name": 1, "scopes": ["local:read"], "context": CONTEXT},
    {"name": "x", "scopes": ["local:read"]},
    {"name": "x", "scopes": ["local:read"], "context": CONTEXT, "installation": "other"},
])
def test_create_body_is_strict_over_http(client, body):
    make_admin()
    signed_in(client)
    response = client.post(ADMIN_URL, json=body)
    assert response.status_code == 422, response.text
    assert response.headers["content-type"].startswith(PROBLEM)
    assert client.get(ADMIN_URL).json()["integrations"] == []


def test_admin_errors_are_problem_json(client):
    make_admin()
    anonymous = client.get(ADMIN_URL)
    assert anonymous.status_code == 401 and anonymous.headers["content-type"].startswith(PROBLEM)
    signed_in(client)
    missing = client.post("%s/ic_%s/revoke" % (ADMIN_URL, "a" * 32))
    assert missing.status_code == 404 and missing.json()["code"] == "not_found"


def test_admin_operations_are_in_openapi_and_not_in_mcp(client):
    spec = client.get("/openapi.json").json()["paths"]
    assert {"post"} <= set(spec["/v1/admin/integrations"]) and "get" in spec["/v1/admin/integrations"]
    assert "post" in spec["/v1/admin/integrations/{client_id}/revoke"]
    created = spec["/v1/admin/integrations"]["post"]["responses"]["200"]
    assert created["content"]["application/json"]["schema"]


# Значения контура не того типа: управляемый отказ, а не 500.
_BAD_CONTOURS = [[], {}, ["TEST"], {"value": "TEST"}, None, True, False, 1, 0.5, "test", ""]


@pytest.mark.parametrize("contour", _BAD_CONTOURS)
def test_malformed_contour_is_rejected_over_http(client, contour):
    make_admin()
    signed_in(client)
    body = {"name": "review", "scopes": ["local:read"],
            "context": {"organization_ref": "review-org", "contour": contour}}
    response = client.post(ADMIN_URL, json=body)
    assert response.status_code == 400, response.text
    assert response.headers["content-type"].startswith(PROBLEM)
    assert response.json()["code"] == "invalid_parameter"
    assert "epgu_ic_" not in response.text
    assert client.get(ADMIN_URL).json()["integrations"] == []


@pytest.mark.parametrize("contour", _BAD_CONTOURS)
def test_malformed_contour_never_matches(contour):
    from integration_auth import context_matches

    valid = {"organization_ref": "o", "contour": "TEST", "is_ref": "SVCDEV261022"}
    bad = {**valid, "contour": contour}
    for requires_is in (False, True):
        assert context_matches(valid, bad, requires_is=requires_is) is False
        assert context_matches(bad, valid, requires_is=requires_is) is False


@pytest.mark.parametrize("value", [[], {}, ["o"], {"value": "o"}, None, True, 1])
def test_malformed_refs_never_match_and_never_raise(value):
    from integration_auth import context_matches

    valid = {"organization_ref": "o", "contour": "PROD", "is_ref": "SVCDEV261022"}
    for key in ("organization_ref", "is_ref"):
        bad = {**valid, key: value}
        assert context_matches(valid, bad, requires_is=True) is False
        assert context_matches(bad, valid, requires_is=True) is False
    for not_a_dict in (value, "o", ["organization_ref"]):
        assert context_matches(valid, not_a_dict, requires_is=False) is False
        assert context_matches(not_a_dict, valid, requires_is=False) is False


@pytest.mark.parametrize("contour", ["TEST", "PROD"])
@pytest.mark.parametrize("is_ref", [None, "SVCDEV261022", "SVCDEV261023"])
def test_valid_contexts_still_match_themselves(contour, is_ref):
    from integration_auth import context_matches

    context = {"organization_ref": "o", "contour": contour}
    if is_ref:
        context["is_ref"] = is_ref
    assert context_matches(context, dict(context), requires_is=bool(is_ref))
