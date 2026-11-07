"""Контекст оператора для интеграций: привязка, живое состояние, машинный маршрут.

Все проверки идут через настоящее приложение ``app.app`` и HTTP.
"""

import dataclasses
import itertools
import logging

import pytest
from fastapi import routing as fastapi_routing
from fastapi.testclient import TestClient

import capabilities

pytestmark = pytest.mark.real_auth

PASSWORD = "correct horse battery staple"
PROBLEM = "application/problem+json"
CONTEXT_URL = "/v1/operator/context"
BINDING_URL = "/v1/admin/operator-binding"
TH = "AB" * 20
OTHER_TH = "CD" * 20
ORG = "org-1"
IS_REF = "SVCDEV261022"
ADMIN_ID = "acc_" + "1" * 32

SENTINEL_BEARER = "SENTINEL-ESIA-BEARER-7f3a"
SENTINEL_PIN = "SENTINEL-PIN-4812"
SENTINEL_API_KEY = "SENTINEL-API-KEY-9c21"


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


def issue(scopes=("local:read",), context=None, **kwargs):
    import integration_auth

    kwargs.setdefault("created_by", ADMIN_ID)
    ctx = dict(context) if context is not None else {"organization_ref": ORG, "contour": "TEST"}
    return integration_auth.create_client("Тестовая интеграция", list(scopes), ctx, **kwargs)


def bearer(secret):
    return {"Authorization": "Bearer " + secret}


def live(monkeypatch, *, selected=TH, certs=(TH,), env="test"):
    """Живое состояние приложения: сертификаты, выбранный, адреса контура."""
    import app as application
    import config

    hosts = config.ENVIRONMENTS[env]
    monkeypatch.setattr(application, "CERTIFICATES", {cert: object() for cert in certs})
    monkeypatch.setattr(application, "CURRENT_CERT_ID", selected)
    monkeypatch.setattr(application, "ESIA_HOST", hosts["esia_host"])
    monkeypatch.setattr(application, "SVCDEV_HOST", hosts["svcdev_host"])
    # Эти значения меняют методы приложения: возвращаем прежние после теста.
    monkeypatch.setattr(application, "SESSION_GENERATION", application.SESSION_GENERATION)
    monkeypatch.setattr(application, "ACCESS_TKN_EXP", application.ACCESS_TKN_EXP)
    monkeypatch.setattr(application, "ACCESS_TKN_ESIA", SENTINEL_BEARER)
    monkeypatch.setattr(application, "KEY_PIN", SENTINEL_PIN)
    monkeypatch.setattr(application, "API_KEY_DEFAULT", SENTINEL_API_KEY)


def bind(*, org=ORG, contour="TEST", thumbprint=TH, is_ref=None):
    import operator_context

    return operator_context.set_binding(org, contour, thumbprint, is_ref=is_ref, by=ADMIN_ID)


@pytest.fixture()
def ready(client, monkeypatch):
    """Привязка TEST, выбран сертификат, ключ с local:read и тем же контекстом."""
    live(monkeypatch)
    bind()
    return client, issue()


def problem_of(response, status, code):
    assert response.status_code == status, response.text
    assert response.headers["content-type"].startswith(PROBLEM)
    body = response.json()
    assert body["code"] == code and body["status"] == status
    return body


# ---------- доступ к машинному маршруту ----------


def test_no_bearer_is_401_problem_with_www_authenticate(client, monkeypatch):
    live(monkeypatch)
    bind()
    response = client.get(CONTEXT_URL)
    body = problem_of(response, 401, "unauthenticated")
    assert response.headers["www-authenticate"] == "Bearer"
    assert response.headers["x-epgu-api-version"] == "1"
    assert body["detail"] == "invalid_token"
    for headers in ({"Authorization": "Basic abc"}, {"Authorization": "Bearer"}, bearer("garbage")):
        again = client.get(CONTEXT_URL, headers=headers)
        problem_of(again, 401, "unauthenticated")
        assert again.headers["www-authenticate"] == "Bearer"


def test_401_comes_before_context_checks(client):
    # Привязки и состояния нет, но без ключа ответ 401, а не 409.
    problem_of(client.get(CONTEXT_URL), 401, "unauthenticated")


def test_admin_cookie_alone_is_not_a_machine_credential(client, monkeypatch):
    live(monkeypatch)
    bind()
    make_admin()
    signed_in(client)
    assert client.get("/auth/session").status_code == 200
    response = client.get(CONTEXT_URL)
    problem_of(response, 401, "unauthenticated")
    assert response.headers["www-authenticate"] == "Bearer"


def test_bearer_without_local_read_is_403(ready):
    client, _ = ready
    weak = issue(scopes=("knowledge:read",))
    response = client.get(CONTEXT_URL, headers=bearer(weak["secret"]))
    body = problem_of(response, 403, "forbidden")
    assert body["detail"] == "insufficient_scope"
    assert "insufficient_scope" in response.headers["www-authenticate"]
    assert weak["secret"] not in response.text


def test_revoked_credential_is_401_on_the_next_call(ready):
    import integration_auth

    client, key = ready
    assert client.get(CONTEXT_URL, headers=bearer(key["secret"])).status_code == 200
    integration_auth.revoke(key["id"], by=ADMIN_ID)
    problem_of(client.get(CONTEXT_URL, headers=bearer(key["secret"])), 401, "unauthenticated")


# ---------- контекст недоступен ----------


def _unavailable(client, key, reason):
    response = client.get(CONTEXT_URL, headers=bearer(key["secret"]))
    body = problem_of(response, 409, "context_unavailable")
    assert body["detail"] == reason
    assert key["secret"] not in response.text
    return body


def test_unavailable_no_binding(client, monkeypatch):
    live(monkeypatch)
    _unavailable(client, issue(), "no_binding")


def test_unavailable_no_provider(client, monkeypatch):
    import operator_context

    live(monkeypatch)
    bind()
    monkeypatch.setattr(operator_context, "_provider", None)
    _unavailable(client, issue(), "no_provider")


def test_unavailable_no_selected_certificate(client, monkeypatch):
    live(monkeypatch, selected=None)
    bind()
    _unavailable(client, issue(), "no_certificate")


def test_unavailable_when_selected_id_is_not_among_certificates(client, monkeypatch):
    live(monkeypatch, selected=TH, certs=(OTHER_TH,))
    bind()
    _unavailable(client, issue(), "no_certificate")


def test_unavailable_certificate_mismatch(client, monkeypatch):
    live(monkeypatch, selected=OTHER_TH, certs=(TH, OTHER_TH))
    bind()
    _unavailable(client, issue(), "certificate_mismatch")


def test_unavailable_custom_hosts(client, monkeypatch):
    import app as application

    live(monkeypatch)
    bind()
    monkeypatch.setattr(application, "SVCDEV_HOST", "https://internal.example.test")
    _unavailable(client, issue(), "unknown_contour")
    # Один адрес от тестового контура, другой от боевого: тоже не известный контур.
    import config

    monkeypatch.setattr(application, "SVCDEV_HOST", config.ENVIRONMENTS["prod"]["svcdev_host"])
    _unavailable(client, issue(), "unknown_contour")


def test_unavailable_binding_prod_vs_live_test(client, monkeypatch):
    live(monkeypatch, env="test")
    bind(contour="PROD")
    _unavailable(client, issue(context={"organization_ref": ORG, "contour": "PROD"}),
                 "contour_mismatch")


def test_unavailable_binding_test_vs_live_prod(client, monkeypatch):
    live(monkeypatch, env="prod")
    bind(contour="TEST")
    _unavailable(client, issue(), "contour_mismatch")


# ---------- контекст ключа не совпадает ----------


MISMATCH_DETAIL = "контекст ключа не совпадает с контекстом оператора"


@pytest.mark.parametrize("binding_is, key_context", [
    (None, {"organization_ref": "org-2", "contour": "TEST"}),
    # Регистр ссылок значим.
    (None, {"organization_ref": "ORG-1", "contour": "TEST"}),
    (IS_REF, {"organization_ref": ORG, "contour": "TEST", "is_ref": "SVCDEV261023"}),
    (IS_REF, {"organization_ref": ORG, "contour": "TEST"}),
    (None, {"organization_ref": ORG, "contour": "TEST", "is_ref": IS_REF}),
    (None, {"organization_ref": ORG, "contour": "PROD"}),
])
def test_context_mismatch(client, monkeypatch, binding_is, key_context):
    live(monkeypatch)
    bind(is_ref=binding_is)
    key = issue(context=key_context)
    response = client.get(CONTEXT_URL, headers=bearer(key["secret"]))
    body = problem_of(response, 409, "context_mismatch")
    assert body["detail"] == MISMATCH_DETAIL
    assert key["secret"] not in response.text


# ---------- успех ----------


def test_success_returns_exact_fields_and_no_secrets(ready):
    import app as application

    client, key = ready
    response = client.get(CONTEXT_URL, headers=bearer(key["secret"]))
    assert response.status_code == 200, response.text
    assert response.headers["x-epgu-api-version"] == "1"
    assert response.json() == {
        "contour": "TEST",
        "organization_ref": ORG,
        "is_ref": None,
        "certificate_thumbprint": TH,
        "generation": application.SESSION_GENERATION,
        "binding_epoch": 1,
    }
    dump = (response.text + repr(dict(response.headers))).lower()
    for secret in (SENTINEL_BEARER, SENTINEL_PIN, SENTINEL_API_KEY, key["secret"], key["id"]):
        assert secret.lower() not in dump
    assert "pin" not in response.text.lower() and "secret" not in response.text.lower()


@pytest.mark.parametrize("env, contour", [("test", "TEST"), ("test-beta", "TEST"), ("prod", "PROD")])
def test_success_per_live_contour_with_is_ref(client, monkeypatch, env, contour):
    live(monkeypatch, env=env)
    bind(contour=contour, is_ref=IS_REF)
    key = issue(context={"organization_ref": ORG, "contour": contour, "is_ref": IS_REF})
    response = client.get(CONTEXT_URL, headers=bearer(key["secret"]))
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["contour"] == contour and body["is_ref"] == IS_REF


def test_binding_thumbprint_is_case_insensitive_and_stored_upper(client, monkeypatch):
    import operator_context

    live(monkeypatch)
    stored = bind(thumbprint=TH.lower())
    assert stored.certificate_thumbprint == TH
    assert operator_context.get_binding().certificate_thumbprint == TH
    key = issue()
    assert client.get(CONTEXT_URL, headers=bearer(key["secret"])).json()["certificate_thumbprint"] == TH
    # Выбранный сертификат в нижнем регистре сверяется как то же значение.
    live(monkeypatch, selected=TH.lower(), certs=(TH.lower(),))
    assert client.get(CONTEXT_URL, headers=bearer(key["secret"])).status_code == 200


def test_certificate_switch_through_real_route_and_session_clear(ready, monkeypatch):
    client, key = ready
    live(monkeypatch, certs=(TH, OTHER_TH))
    make_admin()
    signed_in(client)
    headers = bearer(key["secret"])
    first = client.get(CONTEXT_URL, headers=headers)
    assert first.status_code == 200, first.text

    assert client.post("/set_current_certificate", params={"cert_id": OTHER_TH}).status_code == 200
    body = problem_of(client.get(CONTEXT_URL, headers=headers), 409, "context_unavailable")
    assert body["detail"] == "certificate_mismatch"

    assert client.post("/set_current_certificate", params={"cert_id": TH}).status_code == 200
    again = client.get(CONTEXT_URL, headers=headers)
    assert again.status_code == 200
    # Смена сертификата дважды продвинула эпоху авторизации.
    assert again.json()["generation"] == first.json()["generation"] + 2

    assert client.post("/session/clear").status_code == 200
    body = problem_of(client.get(CONTEXT_URL, headers=headers), 409, "context_unavailable")
    assert body["detail"] == "no_certificate"


# ---------- привязка оператора по HTTP ----------


def _binding_body(**over):
    body = {"organization_ref": ORG, "contour": "TEST", "certificate_thumbprint": TH}
    body.update(over)
    return body


def _audit_rows():
    import auth_store

    with auth_store.read() as db:
        return [tuple(row) for row in db.execute("SELECT * FROM audit")]


def test_binding_admin_is_closed_without_admin_session(client):
    import auth

    make_admin()
    auth.create_account("operator", PASSWORD, source="cli")
    calls = (
        lambda: client.get(BINDING_URL),
        lambda: client.put(BINDING_URL, json=_binding_body()),
        lambda: client.delete(BINDING_URL),
    )
    assert [call().status_code for call in calls] == [401, 401, 401]
    signed_in(client, "operator")
    assert [call().status_code for call in calls] == [403, 403, 403]
    import operator_context

    assert operator_context.get_binding() is None


def test_binding_admin_rejects_bearer(client):
    import integration_auth

    make_admin()
    key = issue(scopes=tuple(sorted(integration_auth.SCOPES)))
    headers = bearer(key["secret"])
    for response in (
        client.get(BINDING_URL, headers=headers),
        client.put(BINDING_URL, headers=headers, json=_binding_body()),
        client.delete(BINDING_URL, headers=headers),
    ):
        problem_of(response, 401, "unauthenticated")
    import operator_context

    assert operator_context.get_binding() is None


@pytest.mark.parametrize("body", [
    _binding_body(organization_ref=True), _binding_body(organization_ref=["o"]),
    _binding_body(organization_ref=1), _binding_body(organization_ref={"a": "b"}),
    _binding_body(contour=True), _binding_body(contour=["TEST"]), _binding_body(contour=1),
    _binding_body(certificate_thumbprint=1), _binding_body(certificate_thumbprint=True),
    _binding_body(certificate_thumbprint=[TH]), _binding_body(certificate_thumbprint=1.5),
    _binding_body(is_ref=True), _binding_body(is_ref=1), _binding_body(is_ref=["x"]),
    _binding_body(installation="other"),
    {"organization_ref": ORG, "contour": "TEST"},
    {},
])
def test_binding_put_wrong_type_is_422_and_stores_nothing(client, body):
    import operator_context

    make_admin()
    signed_in(client)
    response = client.put(BINDING_URL, json=body)
    problem_of(response, 422, "invalid_parameter")
    assert operator_context.get_binding() is None
    assert client.get(BINDING_URL).status_code == 404


@pytest.mark.parametrize("body", [
    _binding_body(certificate_thumbprint="AB" * 19), _binding_body(certificate_thumbprint="AB" * 21),
    _binding_body(certificate_thumbprint="Z" * 40), _binding_body(certificate_thumbprint=TH + "\n"),
    _binding_body(certificate_thumbprint=" " + TH[1:]), _binding_body(certificate_thumbprint=""),
    _binding_body(contour="test"), _binding_body(contour="DEV"), _binding_body(contour=""),
    _binding_body(organization_ref=""), _binding_body(organization_ref=" o"),
    _binding_body(organization_ref="o\n"), _binding_body(organization_ref="x" * 201),
    _binding_body(is_ref=""), _binding_body(is_ref=" SVCDEV261022"),
    _binding_body(is_ref="SVCDEV 261022"),
])
def test_binding_put_bad_value_is_400_and_stores_nothing(client, body):
    import operator_context

    make_admin()
    signed_in(client)
    problem_of(client.put(BINDING_URL, json=body), 400, "invalid_parameter")
    assert operator_context.get_binding() is None
    assert client.get(BINDING_URL).status_code == 404
    assert _audit_rows() and all("operator_binding" not in row[4] for row in _audit_rows())


def test_binding_epoch_grows_on_every_set_and_clear(client):
    import auth_store
    import operator_context

    def epoch():
        with auth_store.read() as db:
            return operator_context.current_epoch(db)

    assert epoch() == 0 and operator_context.get_binding() is None
    assert bind().epoch == 1 and operator_context.get_binding().epoch == 1
    # Повтор тех же значений это тоже установка и тоже новая версия.
    assert bind().epoch == 2
    assert operator_context.clear_binding(ADMIN_ID) is True and epoch() == 3
    # Повторное снятие без привязки версию не меняет.
    assert operator_context.clear_binding(ADMIN_ID) is False and epoch() == 3
    # Удаление и повторное создание тех же значений даёт новую версию.
    recreated = bind()
    assert recreated.epoch == 4 and operator_context.get_binding().epoch == 4
    assert recreated.public()["epoch"] == 4


def test_binding_roundtrip_and_audit_without_secrets(client):
    make_admin()
    signed_in(client)
    key = issue()
    assert client.get(BINDING_URL).status_code == 404

    put = client.put(BINDING_URL, json=_binding_body(certificate_thumbprint=TH.lower(), is_ref=IS_REF))
    assert put.status_code == 200, put.text
    assert put.headers["x-epgu-api-version"] == "1"
    data = put.json()
    assert data["certificate_thumbprint"] == TH and data["is_ref"] == IS_REF
    assert data["organization_ref"] == ORG and data["contour"] == "TEST"
    assert data["updated_by"].startswith("acc_") and data["updated_at"]
    assert data["epoch"] == 1
    assert client.get(BINDING_URL).json() == data

    # Повторная установка заменяет единственную строку.
    second = client.put(BINDING_URL, json=_binding_body(organization_ref="org-2", contour="PROD"))
    assert second.status_code == 200
    assert second.json()["is_ref"] is None and second.json()["organization_ref"] == "org-2"
    assert second.json()["epoch"] == 2
    import auth_store

    with auth_store.read() as db:
        assert db.execute("SELECT COUNT(*) FROM operator_binding").fetchone()[0] == 1

    assert client.delete(BINDING_URL).json() == {"removed": True}
    assert client.get(BINDING_URL).status_code == 404
    assert client.delete(BINDING_URL).json() == {"removed": False}

    rows = _audit_rows()
    actions = [row[4] for row in rows]
    assert actions.count("operator_binding.set") == 2
    assert actions.count("operator_binding.clear") == 1
    dump = repr(rows)
    for secret in (PASSWORD, key["secret"], SENTINEL_BEARER, SENTINEL_PIN, "password_hash"):
        assert secret not in dump


def test_binding_put_from_foreign_origin_is_rejected(client):
    import operator_context

    make_admin()
    signed_in(client)
    foreign = {"Origin": "https://attacker.example"}
    assert client.put(BINDING_URL, json=_binding_body(), headers=foreign).status_code == 403
    assert operator_context.get_binding() is None
    assert client.put(BINDING_URL, json=_binding_body()).status_code == 200
    assert client.delete(BINDING_URL, headers=foreign).status_code == 403
    assert operator_context.get_binding() is not None


def test_binding_change_takes_effect_on_the_next_call(ready):
    import operator_context

    client, key = ready
    headers = bearer(key["secret"])
    assert client.get(CONTEXT_URL, headers=headers).status_code == 200
    operator_context.set_binding("org-2", "TEST", TH, by=ADMIN_ID)
    problem_of(client.get(CONTEXT_URL, headers=headers), 409, "context_mismatch")
    operator_context.clear_binding(ADMIN_ID)
    body = problem_of(client.get(CONTEXT_URL, headers=headers), 409, "context_unavailable")
    assert body["detail"] == "no_binding"


# ---------- секреты и приватность ----------


def test_operator_context_has_no_secret_fields_and_safe_repr(monkeypatch):
    import operator_context

    live(monkeypatch)
    context = operator_context.OperatorContext(
        contour="TEST", organization_ref=ORG, is_ref=IS_REF, certificate_thumbprint=TH,
        generation=3, binding_epoch=5
    )
    assert [f.name for f in dataclasses.fields(context)] == [
        "contour", "organization_ref", "is_ref", "certificate_thumbprint", "generation",
        "binding_epoch",
    ]
    for text in (repr(context), str(context), "%s" % (context,), repr([context])):
        for secret in (SENTINEL_BEARER, SENTINEL_PIN, SENTINEL_API_KEY):
            assert secret not in text
        assert TH in text and ORG in text
    with pytest.raises(dataclasses.FrozenInstanceError):
        context.contour = "PROD"


def test_capture_snapshot_has_no_secrets(client, monkeypatch):
    import operator_context

    live(monkeypatch)
    bind(is_ref=IS_REF)
    snapshot = operator_context.capture()
    assert snapshot.is_ref == IS_REF and snapshot.certificate_thumbprint == TH
    for secret in (SENTINEL_BEARER, SENTINEL_PIN, SENTINEL_API_KEY):
        assert secret not in repr(snapshot) and secret not in repr(snapshot.public())


def test_success_path_logs_no_secrets(ready, caplog):
    client, key = ready
    caplog.set_level(logging.DEBUG)
    response = client.get(CONTEXT_URL, headers=bearer(key["secret"]))
    assert response.status_code == 200
    client.get(CONTEXT_URL)
    client.get(CONTEXT_URL, headers=bearer(key["secret"] + "x"))
    for secret in (key["secret"], SENTINEL_BEARER, SENTINEL_PIN, SENTINEL_API_KEY):
        assert secret not in caplog.text


# ---------- согласованность реестра и маршрутов ----------


def _mounted():
    """Смонтированные операции: {(метод, путь): обработчик}."""
    import app as application

    iterate = getattr(fastapi_routing, "iter_route_contexts", None)
    contexts = iterate(application.app.routes) if iterate else application.app.routes
    result = {}
    for context in contexts:
        path, methods = getattr(context, "path", None), getattr(context, "methods", None)
        if not path or not methods:
            continue
        for method in set(methods) - {"HEAD", "OPTIONS"}:
            result["%s %s" % (method.upper(), path)] = getattr(context, "endpoint", None)
    return result


def test_every_machine_endpoint_belongs_to_an_enforced_capability():
    import auth_api

    assert auth_api.machine_endpoints
    enforced_ops = {op for cap in capabilities.items() if cap.machine == "enforced" for op in cap.api}
    mounted = _mounted()
    for endpoint in auth_api.machine_endpoints:
        ops = {op for op, handler in mounted.items() if handler is endpoint}
        assert ops, "машинный маршрут не смонтирован: %r" % endpoint
        assert ops <= enforced_ops, sorted(ops - enforced_ops)


def test_every_enforced_capability_is_mounted_and_registered():
    import auth_api

    mounted = _mounted()
    enforced = [cap for cap in capabilities.items() if cap.machine == "enforced"]
    assert [cap.id for cap in enforced] == [
        "operator.context", "operation.prepare", "operation.plan.get", "operation.execute",
    ]
    for cap in enforced:
        assert cap.api and cap.scopes, cap.id
        for op in cap.api:
            assert op in mounted, op
            assert mounted[op] in auth_api.machine_endpoints, op


def test_exact_machine_capabilities_and_no_targets_in_the_core():
    modes = {cap.id: cap.machine for cap in capabilities.items() if cap.machine != "none"}
    assert modes == {
        "operator.context": "enforced", "operation.prepare": "enforced",
        "operation.plan.get": "enforced", "operation.execute": "enforced",
    }
    # Целевых (target) возможностей в ядре нет: исполнитель есть только у теста.
    assert [cap.id for cap in capabilities.catalog() if cap.machine == "target"] == []


def test_machine_registration_is_exact_not_a_prefix(ready):
    client, key = ready
    # Ключ без cookie не открывает соседние маршруты под тем же префиксом /v1.
    for path in ("/v1/capabilities", "/v1/operator/other", "/v1/admin/integrations", "/services"):
        response = client.get(path, headers=bearer(key["secret"]))
        assert response.status_code in (401, 404), path
    assert client.get(CONTEXT_URL, headers=bearer(key["secret"])).status_code == 200


def test_machine_endpoint_is_never_served_by_cookie(ready):
    client, _ = ready
    make_admin()
    signed_in(client)
    for method in ("get", "post", "put", "delete"):
        response = getattr(client, method)(CONTEXT_URL)
        assert response.status_code in (401, 405), (method, response.status_code)
    assert client.get(CONTEXT_URL).status_code == 401


def test_openapi_describes_machine_route(client):
    spec = client.get("/openapi.json").json()["paths"]
    get = spec[CONTEXT_URL]["get"]
    assert {"200", "401", "403", "409"} <= set(get["responses"])
    assert PROBLEM in get["responses"]["409"]["content"]
    assert {"get", "put", "delete"} <= set(spec[BINDING_URL])
    # Привязка описана как ручное утверждение, а не проверка прав в ЕСИА.
    note = spec[BINDING_URL]["put"]["description"]
    assert "Ручное утверждение" in note and "не проверка членства" in note


def test_require_machine_accepts_only_enforced_capabilities(monkeypatch):
    import machine_api

    assert callable(machine_api.require_machine("operator.context"))
    with pytest.raises(ValueError):
        machine_api.require_machine("services.list")
    with pytest.raises(ValueError):
        machine_api.require_machine("no.such.capability")
    with pytest.raises(ValueError):
        machine_api.require_machine("operator.binding.set")
    monkeypatch.setattr(capabilities, "_private", [])
    capabilities.register(capabilities.Capability(
        id="private.target", title="Целевая", effect="read_local", scopes=("local:read",),
        machine="target"))
    with pytest.raises(ValueError):
        machine_api.require_machine("private.target")


# ---------- проверки записи реестра ----------


def _cap(**kwargs):
    base = dict(id="x.y", title="t", effect="read_local")
    base.update(kwargs)
    return capabilities.Capability(**base)


def test_operator_capabilities_are_declared():
    cap = capabilities.get("operator.context")
    assert cap is not None
    assert cap.api == ("GET /v1/operator/context",) and cap.requires == ()
    assert cap.effect is capabilities.Effect.READ_LOCAL
    assert cap.scopes == ("local:read",) and cap.machine == "enforced"
    assert cap.gates == ("integration_credential", "operator_binding", "certificate_match",
                         "contour_match", "context_match")
    assert cap.mcp_profile is capabilities.McpProfile.NONE and cap.side_effects == ()
    assert cap.to_dict()["machine"] == "enforced" and cap.to_dict()["scopes"] == ["local:read"]
    for cap_id, op in (("operator.binding.get", "GET"), ("operator.binding.set", "PUT"),
                       ("operator.binding.clear", "DELETE")):
        admin = capabilities.get(cap_id)
        assert admin.api == (op + " /v1/admin/operator-binding",)
        assert admin.effect is capabilities.Effect.ADMIN and admin.machine == "none"
        assert admin.requires == ("login", "installation_admin")
        assert admin.mcp_profile is capabilities.McpProfile.NONE


def test_capability_new_fields_default_and_serialize():
    cap = _cap()
    assert (cap.scopes, cap.gates, cap.side_effects, cap.machine) == ((), (), (), "none")
    data = cap.to_dict()
    assert data["scopes"] == [] and data["gates"] == [] and data["side_effects"] == []
    assert data["machine"] == "none"
    ok = _cap(effect="write_external", scopes=["external:execute"], gates=["human_approval"],
              side_effects=["external_write", "legal_effect"])
    assert ok.side_effects == ("external_write", "legal_effect")
    assert dataclasses.replace(ok) == ok


def test_scope_set_is_shared_with_integration_auth():
    import integration_auth

    assert capabilities.SCOPES == integration_auth.SCOPES
    assert "admin" not in capabilities.SCOPES and "*" not in capabilities.SCOPES


@pytest.mark.parametrize("profile", ["knowledge", "read"])
def test_side_effects_are_forbidden_in_safe_profiles(profile):
    with pytest.raises(ValueError):
        _cap(side_effects=("marks_read",), scopes=("local:write",), mcp_profile=profile)


@pytest.mark.parametrize("kwargs", [
    dict(side_effects=("teleport",), scopes=("local:write",)),
    dict(side_effects=("legal_effect",), scopes=("external:read",)),
    dict(side_effects=("legal_effect",), scopes=("local:read",)),
    dict(side_effects=("legal_effect",), scopes=("local:read", "external:read")),
    dict(side_effects=("marks_read",), scopes=("knowledge:read",)),
    dict(scopes=("admin",)),
    dict(scopes=("*",)),
    dict(machine="always"),
    dict(machine="enforced"),
    dict(machine="target"),
    dict(effect="admin", machine="enforced", scopes=("local:read",)),
    dict(effect="admin", machine="target", scopes=("local:read",)),
])
def test_invalid_capability_declarations_raise(kwargs):
    with pytest.raises(ValueError):
        _cap(**kwargs)


def test_valid_machine_declarations_are_accepted():
    assert _enforced().machine == "enforced"
    assert _enforced(gates=_BASE + ("is_bound",), scopes=("knowledge:read",)).machine == "enforced"
    assert _cap(machine="target", scopes=("knowledge:read",)).machine == "target"
    assert _cap(machine="target", scopes=("local:read",), gates=("esia_token",)).machine == "target"
    assert _cap(effect="admin").machine == "none"


# ---------- R6: условия допуска fail-closed ----------

_BASE = capabilities.BASE_MACHINE_GATES
PROBE_URL = "/v1/operator/probe"


def _enforced(**kwargs):
    base = dict(machine="enforced", scopes=("local:read",), api=("GET " + PROBE_URL,),
                gates=_BASE)
    base.update(kwargs)
    return _cap(**base)


def test_gate_vocabulary_matches_the_checks_in_machine_api():
    import machine_api

    assert set(machine_api.GATE_CHECKS) == capabilities.ENFORCED_GATES
    assert set(_BASE) < capabilities.ENFORCED_GATES
    assert not capabilities.ENFORCED_GATES & capabilities.PLANNED_GATES
    assert capabilities.GATES == capabilities.ENFORCED_GATES | capabilities.PLANNED_GATES


@pytest.mark.parametrize("machine", ["none", "target", "enforced"])
def test_unknown_gate_is_rejected_in_every_mode(machine):
    with pytest.raises(ValueError, match="неизвестное условие"):
        _cap(machine=machine, scopes=("local:read",), api=("GET " + PROBE_URL,),
             gates=_BASE + ("not_a_real_gate",))


@pytest.mark.parametrize("gate", sorted(capabilities.PLANNED_GATES))
def test_planned_gate_cannot_be_enforced(gate):
    with pytest.raises(ValueError, match="ещё не проверяет"):
        _enforced(gates=_BASE + (gate,))
    assert gate in _cap(machine="target", scopes=("local:read",), gates=(gate,)).gates


@pytest.mark.parametrize("kwargs", [
    dict(implemented=False),
    dict(api=()),
    dict(gates=()),
    dict(gates=_BASE[1:]),
    dict(gates=("integration_credential",)),
    dict(effect="write_local", scopes=("local:write",)),
    dict(effect="write_external", scopes=("external:execute",)),
    dict(scopes=("external:execute",), side_effects=("external_write",)),
    dict(scopes=("local:read", "local:write"), side_effects=("reserves_number",)),
])
def test_bad_enforced_declarations_raise(kwargs):
    with pytest.raises(ValueError):
        _enforced(**kwargs)


def test_require_machine_rechecks_a_declaration_changed_after_validation(monkeypatch):
    import machine_api

    monkeypatch.setattr(capabilities, "_private", [])
    changes = (("gates", _BASE + ("esia_token",)), ("implemented", False),
               ("gates", _BASE + ("not_a_real_gate",)))
    for number, (field, value) in enumerate(changes):
        cap = _enforced(id="private.changed.%d" % number)
        # Доверенный код может обойти __post_init__; сборка маршрута это ловит.
        object.__setattr__(cap, field, value)
        capabilities._private.append(cap)
        with pytest.raises(ValueError):
            machine_api.require_machine(cap.id)


@pytest.fixture()
def mount_probe(monkeypatch):
    """Временный machine-маршрут на настоящем app.app; после теста убирается."""
    import app as application
    import auth_api
    import machine_api
    from fastapi import APIRouter, Depends

    monkeypatch.setattr(capabilities, "_private", [])
    monkeypatch.setattr(auth_api, "machine_endpoints", set(auth_api.machine_endpoints))
    saved = list(application.app.router.routes)

    def mount(cap):
        capabilities.register(cap)
        router = APIRouter()

        @router.get(PROBE_URL)
        async def probe(snapshot=Depends(machine_api.require_machine(cap.id))):
            return snapshot.public()

        auth_api.machine_endpoints.add(probe)
        application.app.include_router(router)

    yield mount
    application.app.router.routes[:] = saved


@pytest.mark.parametrize("machine", ["target", "none"])
def test_target_or_none_capability_cannot_be_mounted(client, mount_probe, machine):
    with pytest.raises(ValueError):
        mount_probe(_cap(id="private.probe", scopes=("local:read",), api=("GET " + PROBE_URL,),
                         machine=machine))
    assert client.get(PROBE_URL).status_code == 404


def test_known_unmet_gate_is_enforced_by_real_dispatch(client, monkeypatch, mount_probe):
    # is_bound: ключ без ИС не проходит, хотя базовые условия выполнены.
    live(monkeypatch)
    bind(is_ref=IS_REF)
    mount_probe(_enforced(id="private.probe", gates=_BASE + ("is_bound",)))
    without_is = issue(context={"organization_ref": ORG, "contour": "TEST"})
    problem_of(client.get(PROBE_URL, headers=bearer(without_is["secret"])), 409,
               "context_mismatch")
    with_is = issue(context={"organization_ref": ORG, "contour": "TEST", "is_ref": IS_REF})
    response = client.get(PROBE_URL, headers=bearer(with_is["secret"]))
    assert response.status_code == 200, response.text
    assert response.json()["is_ref"] == IS_REF
    # Базовые условия действуют и здесь: без ключа 401, без привязки 409.
    assert client.get(PROBE_URL).status_code == 401
    import operator_context

    operator_context.clear_binding(ADMIN_ID)
    problem_of(client.get(PROBE_URL, headers=bearer(with_is["secret"])), 409,
               "context_unavailable")


def test_every_machine_route_depends_on_its_own_capability():
    import app as application
    import auth_api

    iterate = getattr(fastapi_routing, "iter_route_contexts", None)
    contexts = iterate(application.app.routes) if iterate else application.app.routes
    checked = 0
    for context in contexts:
        if getattr(context, "endpoint", None) not in auth_api.machine_endpoints:
            continue
        route = getattr(context, "route", context)
        marks = {getattr(dep.call, "capability_id", None) for dep in route.dependant.dependencies}
        marks.discard(None)
        assert len(marks) == 1, (context.path, marks)
        cap = capabilities.get(marks.pop())
        assert cap is not None and cap.machine == "enforced"
        ops = {"%s %s" % (method, context.path) for method in context.methods
               if method not in ("HEAD", "OPTIONS")}
        assert ops and ops <= set(cap.api), (ops, cap.api)
        checked += 1
    assert checked == len(auth_api.machine_endpoints) >= 1


# ---------- R7: побочные эффекты и разрешения только на чтение ----------

_READ = sorted(capabilities.READ_SCOPES)
_READ_COMBOS = [combo for size in (1, 2, 3) for combo in itertools.combinations(_READ, size)]


def test_knowledge_read_is_a_read_only_scope():
    assert capabilities.READ_SCOPES == {"knowledge:read", "local:read", "external:read"}


@pytest.mark.parametrize("scopes", _READ_COMBOS)
@pytest.mark.parametrize("effect", sorted(capabilities.SIDE_EFFECTS))
@pytest.mark.parametrize("machine", ["none", "target", "enforced"])
def test_side_effects_never_pass_with_read_only_scopes(scopes, effect, machine):
    with pytest.raises(ValueError):
        _cap(effect="read_external", scopes=scopes, side_effects=(effect,), machine=machine,
             api=("GET " + PROBE_URL,), gates=_BASE if machine == "enforced" else ())


@pytest.mark.parametrize("effect", sorted(capabilities.SIDE_EFFECTS))
def test_side_effects_of_an_old_ui_route_need_no_scopes(effect):
    # Описание опасности маршрута без машинного доступа не требует давать ключам прав.
    cap = _cap(effect="read_external", side_effects=(effect,))
    assert cap.machine == "none" and cap.scopes == () and cap.side_effects == (effect,)


def test_side_effects_with_a_non_read_scope_can_only_be_a_target():
    cap = _cap(effect="read_external", scopes=("local:read", "external:execute"),
               side_effects=("marks_read",), machine="target")
    assert cap.machine == "target"
    with pytest.raises(ValueError):
        _enforced(effect="read_external", scopes=("local:read", "external:execute"),
                  side_effects=("marks_read",))


def test_read_only_scopes_without_side_effects_stay_valid():
    for scopes in _READ_COMBOS:
        assert _enforced(scopes=scopes).scopes == scopes
        assert _cap(machine="target", scopes=scopes).machine == "target"
