"""Планы внешних операций: prepare, approve, execute на тестовом исполнителе.

Все проверки идут через настоящее приложение ``app.app`` и HTTP. Исполнитель
существует только в fixture ``mock_executor``: в ядре встроенных исполнителей
нет, реальных адресов, подписи и ключей API тоже.
"""

import asyncio
import base64
import dataclasses
import json
import logging
import sqlite3
import threading
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

import capabilities

pytestmark = pytest.mark.real_auth

PASSWORD = "correct horse battery staple"
PROBLEM = "application/problem+json"
PLANS = "/v1/operations/plans"
CAP = "test.mock.send"
TH = "AB" * 20
OTHER_TH = "CD" * 20
ORG = "org-1"
ADMIN_ID = "acc_" + "1" * 32
PAYLOAD = b"SENTINEL-PAYLOAD-5521"

SENTINEL_BEARER = "SENTINEL-ESIA-BEARER-7f3a"
SENTINEL_PIN = "SENTINEL-PIN-4812"
SENTINEL_API_KEY = "SENTINEL-API-KEY-9c21"
SCOPES = ("external:prepare", "external:execute")


# ---------- общие заготовки (по образцу test_operator_context) ----------


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


def issue(scopes=SCOPES, context=None, **kwargs):
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
    monkeypatch.setattr(application, "SESSION_GENERATION", application.SESSION_GENERATION)
    monkeypatch.setattr(application, "ACCESS_TKN_EXP", application.ACCESS_TKN_EXP)
    monkeypatch.setattr(application, "ACCESS_TKN_ESIA", SENTINEL_BEARER)
    monkeypatch.setattr(application, "KEY_PIN", SENTINEL_PIN)
    monkeypatch.setattr(application, "API_KEY_DEFAULT", SENTINEL_API_KEY)


def bind(*, org=ORG, contour="TEST", thumbprint=TH, is_ref=None):
    import operator_context

    return operator_context.set_binding(org, contour, thumbprint, is_ref=is_ref, by=ADMIN_ID)


def problem_of(response, status, code):
    assert response.status_code == status, response.text
    assert response.headers["content-type"].startswith(PROBLEM)
    body = response.json()
    assert body["code"] == code and body["status"] == status
    return body


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


# ---------- тестовый исполнитель ----------


class MockExecutor:
    """Две внешние операции по порядку: резервирование номера и отправка."""

    capability_id = CAP

    def __init__(self):
        import operations

        self.external_calls = (
            operations.ExternalCall("reserve_number", ("reserves_number",)),
            operations.ExternalCall("send", ("external_write",)),
        )
        self.counts = {"sign": 0, "reserve_number": 0, "send": 0}
        self.after_sign = None
        self.after_reserve = None
        self.in_send = None
        self.fail_send = None
        self.use_session = False
        self.seen = []
        self.sessions = []

    async def run(self, ctx, payload, attachments, target):
        self.seen.append((payload, attachments, target))
        if self.use_session:
            self.sessions.append(ctx.session())
        self.counts["sign"] += 1
        if self.after_sign:
            self.after_sign()
        ctx.start_call("reserve_number")
        self.counts["reserve_number"] += 1
        ctx.mark_done("reserve_number", "N-1")
        if self.after_reserve:
            self.after_reserve()
        ctx.start_call("send")
        self.counts["send"] += 1
        if self.in_send:
            await self.in_send()
        if self.fail_send:
            raise self.fail_send
        ctx.mark_done("send", "msg-1")
        return {"sent": True, "target": target, "number": "N-1"}

    def calls(self):
        return self.counts["reserve_number"], self.counts["send"]


@pytest.fixture()
def mock_executor(monkeypatch):
    import operations

    monkeypatch.setattr(capabilities, "_private", [])
    capabilities.register(capabilities.Capability(
        id=CAP, title="Тестовая отправка", effect="write_external", api=("POST /test/mock",),
        scopes=("external:execute",), side_effects=("external_write", "reserves_number"),
        machine="target"))
    executor = MockExecutor()
    operations.register_executor(executor)
    yield executor
    operations.unregister_executor(CAP)


@pytest.fixture()
def env(client, monkeypatch, mock_executor):
    """Привязка TEST, выбран сертификат, администратор по сессии, ключ с правами плана."""
    import app as application

    live(monkeypatch, certs=(TH, OTHER_TH))
    bind()
    make_admin()
    admin = TestClient(application.app)
    signed_in(admin)
    key = issue()
    return SimpleNamespace(client=client, admin=admin, key=key, ex=mock_executor,
                           headers=bearer(key["secret"]), monkeypatch=monkeypatch, number=[0])


def body_of(env, **over):
    env.number[0] += 1
    body = {"capability_id": CAP, "target": "target-1", "payload_b64": b64(PAYLOAD),
            "attachments": [], "idempotency_key": "idem-key-%04d" % env.number[0]}
    body.update(over)
    return body


def prepare(env, headers=None, **over):
    return env.client.post(PLANS, json=body_of(env, **over),
                           headers=env.headers if headers is None else headers)


def approve(env, plan, plan_hash=None, client=None):
    return (client or env.admin).post(
        "/v1/admin/operations/plans/%s/approve" % plan["plan_id"],
        json={"plan_hash": plan_hash or plan["plan_hash"]})


def execute(env, plan, plan_hash=None, headers=None):
    return env.client.post(
        "%s/%s/execute" % (PLANS, plan["plan_id"]),
        json={"plan_hash": plan_hash or plan["plan_hash"]},
        headers=env.headers if headers is None else headers)


def approved_plan(env, **over):
    created = prepare(env, **over)
    assert created.status_code == 201, created.text
    plan = created.json()
    assert approve(env, plan).status_code == 200
    return plan


def row_of(plan_id):
    import auth_store

    with auth_store.read() as db:
        return dict(db.execute("SELECT * FROM operation_plans WHERE id = ?", (plan_id,)).fetchone())


def count_plans():
    import auth_store

    with auth_store.read() as db:
        return db.execute("SELECT COUNT(*) FROM operation_plans").fetchone()[0]


def dump_tables(tables=("operation_plans", "operation_plan_attachments", "operation_plan_steps",
                        "audit")):
    """Таблицы планов и журнал аудита одной строкой для поиска сигнальных значений."""
    import auth_store

    with auth_store.read() as db:
        parts = []
        for table in tables:
            for row in db.execute("SELECT * FROM %s" % table).fetchall():
                parts.append(repr([v.decode("latin-1") if isinstance(v, bytes) else v for v in row]))
    return "\n".join(parts)


def audit_actions():
    import auth_store

    with auth_store.read() as db:
        return [row[0] for row in db.execute("SELECT action FROM audit ORDER BY seq")]


def forward(monkeypatch, minutes):
    """Сдвинуть часы планов вперёд (ключ живёт 30 дней, его срок не страдает)."""
    import operations

    real = operations._clock
    monkeypatch.setattr(operations, "_clock", lambda: real() + timedelta(minutes=minutes))


# ---------- 1. без исполнителя ----------


def test_without_executor_prepare_and_execute_are_503(client, monkeypatch):
    import operations

    live(monkeypatch)
    bind()
    assert operations._executors == {}
    key = issue()
    body = {"capability_id": CAP, "target": "target-1", "payload_b64": b64(PAYLOAD),
            "attachments": [], "idempotency_key": "idem-key-0001"}
    response = client.post(PLANS, json=body, headers=bearer(key["secret"]))
    detail = problem_of(response, 503, "executor_unavailable")
    assert key["secret"] not in response.text and detail["detail"]
    assert count_plans() == 0
    execute_url = "%s/plan_%s/execute" % (PLANS, "0" * 32)
    problem_of(client.post(execute_url, json={"plan_hash": "0" * 64},
                           headers=bearer(key["secret"])), 503, "executor_unavailable")
    assert count_plans() == 0


def test_executor_removed_after_approve_makes_execute_503_and_keeps_plan(env):
    import operations

    plan = approved_plan(env)
    operations.unregister_executor(CAP)
    problem_of(execute(env, plan), 503, "executor_unavailable")
    assert env.ex.calls() == (0, 0) and row_of(plan["plan_id"])["status"] == "approved"
    problem_of(prepare(env), 503, "executor_unavailable")
    assert count_plans() == 1


# ---------- 2. prepare только записывает план ----------


def test_prepare_records_a_plan_and_calls_nothing(env):
    response = prepare(env, attachments=[{"name": "a.txt", "content_b64": b64(b"abc")}])
    assert response.status_code == 201, response.text
    assert response.headers["x-epgu-api-version"] == "1"
    plan = response.json()
    assert env.ex.counts == {"sign": 0, "reserve_number": 0, "send": 0}
    assert plan["status"] == "planned" and plan["plan_id"].startswith("plan_")
    assert len(plan["plan_hash"]) == 64 and plan["expires_at"]
    preview = plan["preview"]
    assert preview["capability_id"] == CAP and preview["target"] == "target-1"
    assert preview["payload_size"] == len(PAYLOAD)
    assert preview["attachments"] == [{
        "name": "a.txt", "size": 3,
        "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"}]
    assert preview["external_calls"] == [
        {"name": "reserve_number", "side_effects": ["reserves_number"]},
        {"name": "send", "side_effects": ["external_write"]},
    ]
    assert preview["context"] == {
        "contour": "TEST", "organization_ref": ORG, "is_ref": None, "certificate_thumbprint": TH,
        "generation": preview["context"]["generation"], "binding_epoch": 1}
    row = row_of(plan["plan_id"])
    assert row["status"] == "planned" and bytes(row["payload"]) == PAYLOAD
    assert row["approved_by"] is None and row["claimed_at"] is None and row["result"] is None
    dump = dump_tables() + json.dumps(plan)
    for secret in (SENTINEL_BEARER, SENTINEL_PIN, SENTINEL_API_KEY, env.key["secret"]):
        assert secret not in dump
    # Байты payload в журнал аудита не попадают.
    import auth_store

    with auth_store.read() as db:
        audit = repr([tuple(r) for r in db.execute("SELECT * FROM audit")])
    assert PAYLOAD.decode() not in audit and b64(PAYLOAD) not in audit
    assert "operation_plan.prepare" in audit_actions()


# ---------- 3. доступ к prepare ----------


def test_prepare_requires_the_prepare_scope_and_a_bearer(env):
    weak = issue(scopes=("external:execute",))
    problem_of(prepare(env, headers=bearer(weak["secret"])), 403, "forbidden")
    problem_of(env.client.post(PLANS, json=body_of(env)), 401, "unauthenticated")
    # Сессия администратора без ключа не открывает машинный маршрут.
    response = env.admin.post(PLANS, json=body_of(env))
    problem_of(response, 401, "unauthenticated")
    assert response.headers["www-authenticate"] == "Bearer"
    assert count_plans() == 0 and env.ex.calls() == (0, 0)
    plan = prepare(env).json()
    problem_of(env.client.get("%s/%s" % (PLANS, plan["plan_id"]), headers=bearer(weak["secret"])),
               403, "forbidden")


# ---------- 4. идемпотентность ----------


def test_idempotency_same_request_returns_the_same_plan(env):
    body = body_of(env)
    first = env.client.post(PLANS, json=body, headers=env.headers)
    again = env.client.post(PLANS, json=body, headers=env.headers)
    assert (first.status_code, again.status_code) == (201, 200)
    assert again.json() == first.json()
    assert count_plans() == 1
    assert audit_actions().count("operation_plan.prepare") == 1


def test_idempotency_key_with_another_request_or_credential_conflicts(env):
    body = body_of(env)
    plan = env.client.post(PLANS, json=body, headers=env.headers).json()
    for changed in ({"payload_b64": b64(b"another")}, {"target": "target-2"},
                    {"attachments": [{"name": "a", "content_b64": b64(b"1")}]}):
        problem_of(env.client.post(PLANS, json={**body, **changed}, headers=env.headers),
                   409, "idempotency_conflict")
    other = issue()
    problem_of(env.client.post(PLANS, json=body, headers=bearer(other["secret"])),
               409, "idempotency_conflict")
    assert count_plans() == 1
    assert row_of(plan["plan_id"])["status"] == "planned" and env.ex.calls() == (0, 0)


def test_context_change_between_retries_conflicts_instead_of_reusing(env):
    # request_hash включает контекст: после смены привязки прежний ключ не подходит.
    import operator_context

    body = body_of(env)
    assert env.client.post(PLANS, json=body, headers=env.headers).status_code == 201
    operator_context.clear_binding(ADMIN_ID)
    bind()
    problem_of(env.client.post(PLANS, json=body, headers=env.headers), 409, "idempotency_conflict")


# ---------- просмотр плана ----------


def test_machine_view_returns_only_the_own_plan(env):
    plan = prepare(env).json()
    own = env.client.get("%s/%s" % (PLANS, plan["plan_id"]), headers=env.headers)
    assert own.status_code == 200 and own.json() == {**plan, "result": None, "error_code": None}
    foreign = issue()
    problem_of(env.client.get("%s/%s" % (PLANS, plan["plan_id"]), headers=bearer(foreign["secret"])),
               404, "plan_not_found")
    problem_of(env.client.get("%s/plan_%s" % (PLANS, "f" * 32), headers=env.headers),
               404, "plan_not_found")
    assert env.client.get("%s/not-an-id" % PLANS, headers=env.headers).status_code == 422
    problem_of(env.client.post("%s/%s/execute" % (PLANS, plan["plan_id"]),
                               json={"plan_hash": plan["plan_hash"]},
                               headers=bearer(foreign["secret"])), 404, "plan_not_found")
    assert env.ex.calls() == (0, 0)


# ---------- 5. approve ----------


def test_approve_is_for_a_signed_in_administrator_only(env, monkeypatch):
    import app as application
    import auth

    plan = prepare(env).json()
    url = "/v1/admin/operations/plans/%s/approve" % plan["plan_id"]
    review = "/v1/admin/operations/plans/%s" % plan["plan_id"]
    all_scopes = issue(scopes=tuple(sorted(capabilities.SCOPES)))
    fresh = TestClient(application.app)
    for call in (lambda h: fresh.post(url, json={"plan_hash": plan["plan_hash"]}, headers=h),
                 lambda h: fresh.get(review, headers=h)):
        problem_of(call(bearer(all_scopes["secret"])), 401, "unauthenticated")
        problem_of(call({}), 401, "unauthenticated")
    auth.create_account("operator", PASSWORD, source="cli")
    human = TestClient(application.app)
    signed_in(human, "operator")
    problem_of(human.post(url, json={"plan_hash": plan["plan_hash"]}), 403, "forbidden")
    problem_of(human.get(review), 403, "forbidden")
    assert row_of(plan["plan_id"])["status"] == "planned" and env.ex.calls() == (0, 0)


def test_approve_checks_hash_expiry_and_state(env, monkeypatch):
    plan = prepare(env).json()
    problem_of(approve(env, plan, "0" * 64), 409, "plan_hash_mismatch")
    problem_of(approve(env, plan, "not-a-hash"), 409, "plan_hash_mismatch")
    assert row_of(plan["plan_id"])["status"] == "planned"
    done = approve(env, plan)
    assert done.status_code == 200, done.text
    view = done.json()
    assert view["status"] == "approved" and view["approved_by"].startswith("acc_")
    assert view["approved_at"] and view["hash_verified"] is True
    row = row_of(plan["plan_id"])
    assert row["approved_hash"] == plan["plan_hash"] and row["approved_by"] == view["approved_by"]
    problem_of(approve(env, plan), 409, "plan_state")
    expired = prepare(env).json()
    forward(monkeypatch, 11)
    problem_of(approve(env, expired), 410, "plan_expired")
    assert row_of(expired["plan_id"])["status"] == "planned"
    assert audit_actions().count("operation_plan.approve") == 1
    assert env.ex.calls() == (0, 0)


def test_review_shows_exact_bytes_and_flags_a_tampered_plan(env):
    plan = prepare(env, attachments=[{"name": "a.txt", "content_b64": b64(b"abc")}]).json()
    review = env.admin.get("/v1/admin/operations/plans/%s" % plan["plan_id"])
    assert review.status_code == 200, review.text
    data = review.json()
    assert data["payload_b64"] == b64(PAYLOAD) and data["hash_verified"] is True
    assert data["attachment_contents"][0]["content_b64"] == b64(b"abc")
    assert data["client_id"] == env.key["id"] and data["plan_hash"] == plan["plan_hash"]
    import auth_store

    with auth_store.write() as db:
        db.execute("UPDATE operation_plans SET payload = ? WHERE id = ?", (b"changed", plan["plan_id"]))
    again = env.admin.get("/v1/admin/operations/plans/%s" % plan["plan_id"]).json()
    assert again["hash_verified"] is False and again["payload_b64"] == b64(b"changed")
    problem_of(approve(env, plan), 409, "plan_hash_mismatch")
    problem_of(env.admin.get("/v1/admin/operations/plans/plan_%s" % ("f" * 32)), 404,
               "plan_not_found")


def test_admin_preview_and_approve_are_never_stored(env):
    plan = prepare(env).json()
    review = env.admin.get("/v1/admin/operations/plans/%s" % plan["plan_id"])
    done = approve(env, plan)
    for response in (review, done):
        assert response.status_code == 200, response.text
        assert response.headers["cache-control"] == "no-store"
        assert response.headers["pragma"] == "no-cache"


def test_admin_plan_errors_are_never_stored_either(env, monkeypatch):
    import app as application
    import auth

    plan = prepare(env).json()
    review = "/v1/admin/operations/plans/%s" % plan["plan_id"]
    url = review + "/approve"
    auth.create_account("operator", PASSWORD, source="cli")
    human = TestClient(application.app)
    signed_in(human, "operator")
    anonymous = TestClient(application.app)
    cases = [
        (anonymous.get(review), 401, "unauthenticated"),
        (anonymous.post(url, json={"plan_hash": plan["plan_hash"]}), 401, "unauthenticated"),
        (human.get(review), 403, "forbidden"),
        (human.post(url, json={"plan_hash": plan["plan_hash"]}), 403, "forbidden"),
        (env.admin.get("/v1/admin/operations/plans/plan_%s" % ("f" * 32)), 404, "plan_not_found"),
        (env.admin.get("/v1/admin/operations/plans/not-a-plan"), 422, "invalid_parameter"),
        (env.admin.post(url, json={"plan_hash": 1}), 422, "invalid_parameter"),
        (approve(env, plan, "0" * 64), 409, "plan_hash_mismatch"),
    ]
    assert approve(env, plan).status_code == 200
    cases.append((approve(env, plan), 409, "plan_state"))
    expired = prepare(env).json()
    forward(monkeypatch, 11)
    cases.append((approve(env, expired), 410, "plan_expired"))
    for response, status, code in cases:
        problem_of(response, status, code)
        assert response.headers["cache-control"] == "no-store", (status, code)
        assert response.headers["pragma"] == "no-cache", (status, code)
    # Остальные ошибки v1 своё кеширование не меняют.
    other = env.client.get("%s/plan_%s" % (PLANS, "f" * 32), headers=env.headers)
    assert other.status_code == 404 and "cache-control" not in other.headers


def test_operation_capabilities_are_never_in_an_mcp_profile():
    ids = ("operation.prepare", "operation.plan.get", "operation.execute", "operation.review",
           "operation.approve")
    for cap_id in ids:
        cap = capabilities.get(cap_id)
        assert cap is not None and cap.mcp_profile is capabilities.McpProfile.NONE, cap_id
    snapshot = (Path(__file__).resolve().parent.parent / "mcp-server" / "src" / "epgu_mcp"
                / "capabilities_snapshot.json")
    if not snapshot.is_file():
        pytest.skip("снимка MCP рядом нет")
    items = {item["id"]: item for item in json.loads(snapshot.read_text(encoding="utf-8"))["items"]}
    for cap_id in ids:
        assert items[cap_id]["mcp_profile"] == "none", cap_id


# ---------- 6. и 7. execute ----------


def test_execute_without_approval_is_plan_state(env):
    plan = prepare(env).json()
    problem_of(execute(env, plan), 409, "plan_state")
    assert env.ex.counts == {"sign": 0, "reserve_number": 0, "send": 0}
    assert row_of(plan["plan_id"])["status"] == "planned"


def test_execute_after_approve_runs_once_and_replays_the_result(env):
    plan = approved_plan(env, attachments=[{"name": "a.txt", "content_b64": b64(b"abc")}])
    first = execute(env, plan)
    assert first.status_code == 200, first.text
    assert first.json() == {"plan_id": plan["plan_id"], "status": "succeeded",
                            "result": {"sent": True, "target": "target-1", "number": "N-1"}}
    assert env.ex.calls() == (1, 1)
    # Исполнитель получил именно утверждённые байты, вложения и адресата.
    assert env.ex.seen == [(PAYLOAD, (("a.txt", b"abc"),), "target-1")]
    row = row_of(plan["plan_id"])
    assert row["status"] == "succeeded" and row["claimed_at"] and row["finished_at"]
    again = execute(env, plan)
    assert again.status_code == 200 and again.json() == first.json()
    assert env.ex.calls() == (1, 1)
    problem_of(execute(env, plan, "0" * 64), 409, "plan_hash_mismatch")
    stored = env.client.get("%s/%s" % (PLANS, plan["plan_id"]), headers=env.headers).json()
    assert stored["status"] == "succeeded" and stored["result"] == first.json()["result"]
    assert audit_actions().count("operation_plan.claim") == 1
    assert audit_actions().count("operation_plan.finish") == 1


# ---------- 8. подмена после одобрения ----------


@pytest.mark.parametrize("column, value", [
    ("payload", b"substituted"), ("target", "target-2"), ("capability_id", "other.cap"),
    ("external_calls", "[]"), ("expires_at", "2999-01-01T00:00:00+00:00"),
    ("client_id", "ic_" + "0" * 32),
])
def test_substitution_after_approve_is_refused_before_any_call(env, column, value):
    plan = approved_plan(env)
    import auth_store

    with auth_store.write() as db:
        db.execute("UPDATE operation_plans SET %s = ? WHERE id = ?" % column, (value, plan["plan_id"]))
    response = execute(env, plan)
    if column == "client_id":
        # Чужой план неотличим от несуществующего.
        problem_of(response, 404, "plan_not_found")
    else:
        problem_of(response, 409, "plan_hash_mismatch")
    assert env.ex.counts == {"sign": 0, "reserve_number": 0, "send": 0}
    assert row_of(plan["plan_id"])["status"] == "approved"


def test_attachment_substitution_after_approve_is_refused(env):
    plan = approved_plan(env, attachments=[{"name": "a.txt", "content_b64": b64(b"abc")}])
    import auth_store

    with auth_store.write() as db:
        db.execute("UPDATE operation_plan_attachments SET content = ? WHERE plan_id = ?",
                   (b"evil", plan["plan_id"]))
    problem_of(execute(env, plan), 409, "plan_hash_mismatch")
    assert env.ex.calls() == (0, 0)


def test_wrong_plan_hash_in_the_request_is_refused(env):
    plan = approved_plan(env)
    for wrong in ("0" * 64, "x", "-"):
        problem_of(execute(env, plan, wrong), 409, "plan_hash_mismatch")
    assert env.ex.calls() == (0, 0) and row_of(plan["plan_id"])["status"] == "approved"
    assert execute(env, plan).status_code == 200


# ---------- 9. смена контекста между approve и execute ----------


def _stays_approved(env, plan):
    assert env.ex.counts == {"sign": 0, "reserve_number": 0, "send": 0}
    assert row_of(plan["plan_id"])["status"] == "approved"


def test_certificate_switch_through_the_real_route_blocks_execute(env):
    plan = approved_plan(env)
    assert env.admin.post("/set_current_certificate", params={"cert_id": OTHER_TH}).status_code == 200
    body = problem_of(execute(env, plan), 409, "context_unavailable")
    assert body["detail"] == "certificate_mismatch"
    _stays_approved(env, plan)
    # Возврат прежнего сертификата продвинул эпоху сессии: план уже не тот.
    assert env.admin.post("/set_current_certificate", params={"cert_id": TH}).status_code == 200
    body = problem_of(execute(env, plan), 409, "context_changed")
    assert "generation_changed" in body["detail"]
    _stays_approved(env, plan)


def test_session_clear_blocks_execute(env):
    plan = approved_plan(env)
    assert env.admin.post("/session/clear").status_code == 200
    body = problem_of(execute(env, plan), 409, "context_unavailable")
    assert body["detail"] == "no_certificate"
    _stays_approved(env, plan)
    assert env.admin.post("/set_current_certificate", params={"cert_id": TH}).status_code == 200
    problem_of(execute(env, plan), 409, "context_changed")
    _stays_approved(env, plan)


def test_binding_change_blocks_execute(env):
    import operator_context

    plan = approved_plan(env)
    operator_context.set_binding("org-2", "TEST", TH, by=ADMIN_ID)
    problem_of(execute(env, plan), 409, "context_mismatch")
    _stays_approved(env, plan)
    operator_context.clear_binding(ADMIN_ID)
    body = problem_of(execute(env, plan), 409, "context_unavailable")
    assert body["detail"] == "no_binding"
    _stays_approved(env, plan)


def test_delete_and_recreate_of_the_same_binding_blocks_execute(env):
    import operator_context

    plan = approved_plan(env)
    before = operator_context.get_binding()
    operator_context.clear_binding(ADMIN_ID)
    after = bind()
    # Значения те же, версия другая.
    assert (after.organization_ref, after.contour, after.certificate_thumbprint, after.is_ref) == (
        before.organization_ref, before.contour, before.certificate_thumbprint, before.is_ref)
    assert after.epoch == before.epoch + 2
    body = problem_of(execute(env, plan), 409, "context_changed")
    assert "binding_epoch_changed" in body["detail"]
    _stays_approved(env, plan)
    # Даже прямое повторное создание поверх существующего меняет версию.
    plan2 = approved_plan(env)
    bind()
    problem_of(execute(env, plan2), 409, "context_changed")
    _stays_approved(env, plan2)


def test_revoked_or_expired_credential_is_401_before_the_plan(env):
    import integration_auth

    plan = approved_plan(env)
    integration_auth.revoke(env.key["id"], by=ADMIN_ID)
    problem_of(execute(env, plan), 401, "unauthenticated")
    problem_of(env.client.get("%s/%s" % (PLANS, plan["plan_id"]), headers=env.headers), 401,
               "unauthenticated")
    _stays_approved(env, plan)


def test_expired_credential_is_401(env):
    short = issue(ttl_days=1)
    created = env.client.post(PLANS, json=body_of(env), headers=bearer(short["secret"]))
    assert created.status_code == 201
    import auth_store

    with auth_store.write() as db:
        db.execute("UPDATE integration_clients SET expires_at = ? WHERE id = ?",
                   ("2000-01-01T00:00:00+00:00", short["id"]))
    problem_of(env.client.post("%s/%s/execute" % (PLANS, created.json()["plan_id"]),
                               json={"plan_hash": created.json()["plan_hash"]},
                               headers=bearer(short["secret"])), 401, "unauthenticated")
    assert env.ex.calls() == (0, 0)


def test_expired_plan_is_410(env, monkeypatch):
    plan = approved_plan(env)
    stale = prepare(env).json()
    forward(monkeypatch, 11)
    problem_of(execute(env, plan), 410, "plan_expired")
    _stays_approved(env, plan)
    # Не одобренный и истёкший план тоже 410, а не plan_state.
    problem_of(execute(env, stale), 410, "plan_expired")
    assert row_of(stale["plan_id"])["status"] == "planned"


# ---------- 10. барьеры внутри исполнения ----------


def _variants(env):
    import app as application
    import integration_auth
    import operator_context

    mp = env.monkeypatch

    def certificate():
        mp.setattr(application, "CURRENT_CERT_ID", OTHER_TH)

    def revoke():
        integration_auth.revoke(env.key["id"], by=ADMIN_ID)

    def rebind():
        operator_context.clear_binding(ADMIN_ID)
        bind()

    def generation():
        mp.setattr(application, "SESSION_GENERATION", application.SESSION_GENERATION + 1)

    return {"certificate": certificate, "revoke": revoke, "rebind": rebind,
            "generation": generation}


@pytest.mark.parametrize("variant", ["certificate", "revoke", "rebind", "generation"])
def test_change_after_sign_is_refused_before_reserve(env, variant):
    plan = approved_plan(env)
    env.ex.after_sign = _variants(env)[variant]
    body = problem_of(execute(env, plan), 409, "context_changed")
    assert body["detail"]
    assert env.ex.counts == {"sign": 1, "reserve_number": 0, "send": 0}
    row = row_of(plan["plan_id"])
    assert row["status"] == "failed" and row["error_code"] == "context_changed"
    assert row["result"] is None
    # Повтор после failed: ключ, состояние или статус плана отказывают до исполнителя.
    again = {"certificate": (409, "context_unavailable"), "revoke": (401, "unauthenticated"),
             "rebind": (409, "plan_state"), "generation": (409, "plan_state")}[variant]
    problem_of(execute(env, plan), *again)
    assert env.ex.counts == {"sign": 1, "reserve_number": 0, "send": 0}


@pytest.mark.parametrize("variant", ["certificate", "revoke", "rebind", "generation"])
def test_change_after_reserve_is_refused_before_send_and_reports_the_reserve(env, variant):
    plan = approved_plan(env)
    env.ex.after_reserve = _variants(env)[variant]
    body = problem_of(execute(env, plan), 409, "context_changed")
    # Ответ честно говорит, что номер уже зарезервирован.
    assert "reserve_number" in body["detail"]
    assert env.ex.calls() == (1, 0)
    row = row_of(plan["plan_id"])
    assert row["status"] == "failed" and row["error_code"] == "context_changed"
    assert json.loads(row["result"]) == {"completed_calls": ["reserve_number"]}
    stored = env.admin.get("/v1/admin/operations/plans/%s" % plan["plan_id"]).json()
    assert stored["status"] == "failed" and stored["result"] == {"completed_calls": ["reserve_number"]}
    for secret in (SENTINEL_BEARER, SENTINEL_PIN, SENTINEL_API_KEY, env.key["secret"]):
        assert secret not in body["detail"]


def test_not_sent_from_the_executor_fails_the_plan_without_unknown(env):
    import operations

    plan = approved_plan(env)

    def refuse():
        raise operations.NotSent("provider offline; secret=" + SENTINEL_BEARER)

    env.ex.after_sign = refuse
    body = problem_of(execute(env, plan), 409, "execution_failed")
    # Причину исполнителя в ответ пускают только в виде короткого кода.
    assert SENTINEL_BEARER not in json.dumps(body) and "unspecified" in body["detail"]
    row = row_of(plan["plan_id"])
    assert row["status"] == "failed" and row["error_code"] == "not_sent"
    assert env.ex.calls() == (0, 0)


# ---------- 11. захват ----------


def test_two_concurrent_executes_run_the_executor_once(env):
    import app as application
    import httpx

    plan = approved_plan(env)
    state = {}

    async def scenario():
        started = asyncio.Event()
        release = asyncio.Event()

        async def in_send():
            started.set()
            await release.wait()

        env.ex.in_send = in_send
        transport = httpx.ASGITransport(app=application.app)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as http:
            url = "%s/%s/execute" % (PLANS, plan["plan_id"])
            payload = {"plan_hash": plan["plan_hash"]}
            first = asyncio.ensure_future(http.post(url, json=payload, headers=env.headers))
            await asyncio.wait_for(started.wait(), 20)
            second = await asyncio.wait_for(http.post(url, json=payload, headers=env.headers), 20)
            state["second"] = second
            state["status_while_running"] = row_of(plan["plan_id"])["status"]
            release.set()
            state["first"] = await asyncio.wait_for(first, 20)

    asyncio.run(scenario())
    problem_of(state["second"], 409, "plan_inflight")
    assert state["status_while_running"] == "inflight"
    assert state["first"].status_code == 200, state["first"].text
    assert env.ex.calls() == (1, 1)
    assert row_of(plan["plan_id"])["status"] == "succeeded"


def test_claim_from_two_threads_succeeds_exactly_once(env):
    import operations
    import operator_context

    plan = approved_plan(env)
    stored = operations.get_plan(plan["plan_id"])
    context = operator_context.OperatorContext(**stored.context)
    barrier = threading.Barrier(2)
    results = []

    def attempt():
        barrier.wait()
        results.append(operations.claim_plan(stored.id, stored.approved_hash, stored.client_id,
                                             context))

    threads = [threading.Thread(target=attempt) for _ in range(2)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(30)
    assert sorted(results) == [0, 1]
    assert row_of(plan["plan_id"])["status"] == "inflight" and env.ex.calls() == (0, 0)
    problem_of(execute(env, plan), 409, "plan_inflight")
    assert env.ex.calls() == (0, 0)


@pytest.mark.parametrize("what", ["wrong_hash", "revoked", "epoch", "other_client", "expired"])
def test_claim_refuses_when_a_condition_of_the_update_fails(env, what):
    import integration_auth
    import operations
    import operator_context

    plan = approved_plan(env)
    stored = operations.get_plan(plan["plan_id"])
    context = operator_context.OperatorContext(**stored.context)
    args = [stored.id, stored.approved_hash, stored.client_id, context]
    if what == "wrong_hash":
        args[1] = "0" * 64
    elif what == "revoked":
        integration_auth.revoke(env.key["id"], by=ADMIN_ID)
    elif what == "epoch":
        bind()
    elif what == "other_client":
        args[2] = issue()["id"]
    elif what == "expired":
        forward(env.monkeypatch, 11)
    assert operations.claim_plan(*args) == 0
    assert row_of(plan["plan_id"])["status"] == "approved"


# ---------- 12. сбой после начала send ----------


def test_failure_after_the_send_started_is_unknown_and_never_retried(env):
    plan = approved_plan(env)
    env.ex.fail_send = RuntimeError("socket closed; token=" + SENTINEL_BEARER)
    response = execute(env, plan)
    body = problem_of(response, 502, "outcome_unknown")
    assert SENTINEL_BEARER not in response.text and body["detail"]
    assert body["outcome"] == {"plan_id": plan["plan_id"],
                               "completed_calls": ["reserve_number"],
                               "uncertain_calls": ["send"]}
    assert env.ex.calls() == (1, 1)
    row = row_of(plan["plan_id"])
    assert row["status"] == "unknown" and row["error_code"] == "outcome_unknown"
    assert json.loads(row["result"]) == {"completed_calls": ["reserve_number"],
                                         "uncertain_calls": ["send"]}
    problem_of(execute(env, plan), 409, "plan_state")
    assert env.ex.calls() == (1, 1)
    stored = env.client.get("%s/%s" % (PLANS, plan["plan_id"]), headers=env.headers).json()
    assert stored["status"] == "unknown" and stored["error_code"] == "outcome_unknown"


def test_a_result_that_cannot_be_recorded_is_unknown(env):
    plan = approved_plan(env)
    original = env.ex.run

    async def run(ctx, payload, attachments, target):
        await original(ctx, payload, attachments, target)
        return {"value": object()}

    env.ex.run = run
    body = problem_of(execute(env, plan), 502, "outcome_unknown")
    assert row_of(plan["plan_id"])["status"] == "unknown"
    # Оба вызова завершены, неопределённых нет: отчёт это говорит явно.
    assert body["outcome"] == {"plan_id": plan["plan_id"],
                               "completed_calls": ["reserve_number", "send"],
                               "uncertain_calls": []}


def test_outcome_is_only_in_the_unknown_problem(env):
    plan = approved_plan(env)
    body = problem_of(execute(env, dict(plan, plan_hash="0" * 64)), 409, "plan_hash_mismatch")
    assert "outcome" not in body
    document = env.client.get("/openapi.json").json()
    route = document["paths"]["/v1/operations/plans/{plan_id}/execute"]["post"]
    schema = route["responses"]["502"]["content"]["application/problem+json"]["schema"]
    outcome = next(item for item in schema["properties"]["outcome"]["anyOf"]
                   if item.get("type") == "object")
    assert set(outcome["required"]) == {"plan_id", "completed_calls", "uncertain_calls"}
    # Вложенная модель раскрыта: ссылок #/$defs, которые в OpenAPI никуда не ведут, нет.
    assert "#/$defs/" not in json.dumps(document)


# ---------- 13. обрыв процесса ----------


def test_inflight_after_a_crash_becomes_unknown_never_approved(env):
    import operations
    import operator_context

    plan = approved_plan(env)
    stored = operations.get_plan(plan["plan_id"])
    # Захват выполнен, исполнитель «упал» вместе с процессом: завершения нет.
    assert operations.claim_plan(
        stored.id, stored.approved_hash, stored.client_id,
        operator_context.OperatorContext(**stored.context)) == 1
    assert row_of(plan["plan_id"])["status"] == "inflight"
    problem_of(execute(env, plan), 409, "plan_inflight")
    assert operations.recover_inflight() == 1
    row = row_of(plan["plan_id"])
    assert row["status"] == "unknown" and row["error_code"] == "interrupted"
    assert json.loads(row["result"]) == {"completed_calls": [], "uncertain_calls": []}
    problem_of(execute(env, plan), 409, "plan_state")
    assert env.ex.counts == {"sign": 0, "reserve_number": 0, "send": 0}
    assert operations.recover_inflight() == 0
    import auth_store

    for old, new in (("unknown", "approved"), ("unknown", "inflight")):
        with pytest.raises(sqlite3.DatabaseError):
            with auth_store.write() as db:
                db.execute("UPDATE operation_plans SET status = ? WHERE id = ?",
                           (new, plan["plan_id"]))
        assert row_of(plan["plan_id"])["status"] == old


@pytest.mark.parametrize("old, new", [
    ("planned", "inflight"), ("planned", "succeeded"), ("approved", "planned"),
    ("approved", "succeeded"), ("approved", "failed"),
])
def test_database_refuses_transitions_outside_the_allowed_set(env, old, new):
    import auth_store

    plan = prepare(env).json()
    if old == "approved":
        assert approve(env, plan).status_code == 200
    with pytest.raises(sqlite3.DatabaseError):
        with auth_store.write() as db:
            db.execute("UPDATE operation_plans SET status = ? WHERE id = ?", (new, plan["plan_id"]))
    assert row_of(plan["plan_id"])["status"] == old


def test_startup_moves_leftover_inflight_to_unknown(env):
    import app as application
    import operations
    import operator_context

    plan = approved_plan(env)
    stored = operations.get_plan(plan["plan_id"])
    assert operations.claim_plan(
        stored.id, stored.approved_hash, stored.client_id,
        operator_context.OperatorContext(**stored.context)) == 1
    with TestClient(application.app):
        pass
    row = row_of(plan["plan_id"])
    assert row["status"] == "unknown" and row["error_code"] == "interrupted"


# ---------- 14. приватность ----------


def test_execution_context_and_plan_reprs_hide_the_session(env):
    import operations
    import operator_context

    secret_session = SimpleNamespace(bearer=SENTINEL_BEARER)
    context = operator_context.OperatorContext(
        contour="TEST", organization_ref=ORG, is_ref=None, certificate_thumbprint=TH,
        generation=3, binding_epoch=1)
    ctx = operations.ExecutionContext("plan_" + "a" * 32, env.key["id"], context,
                                      _provider=lambda: secret_session)
    assert ctx.session() is secret_session and SENTINEL_BEARER in repr(secret_session)
    plan = prepare(env).json()
    stored = operations.get_plan(plan["plan_id"])
    for text in (repr(ctx), str(ctx), "%s" % (ctx,), repr([ctx]), repr(stored), str(stored),
                 repr(operations.plan_view(stored)), repr(operations.admin_view(stored))):
        for secret in (SENTINEL_BEARER, SENTINEL_PIN, SENTINEL_API_KEY):
            assert secret not in text
    assert TH in repr(ctx) and ORG in repr(ctx)


def test_session_without_a_provider_is_not_sent():
    import operations
    import operator_context

    context = operator_context.OperatorContext(
        contour="TEST", organization_ref=ORG, is_ref=None, certificate_thumbprint=TH,
        generation=3, binding_epoch=1)
    ctx = operations.ExecutionContext("plan_" + "a" * 32, "ic_" + "b" * 32, context)
    with pytest.raises(operations.NotSent):
        ctx.session()


def test_execute_logs_audit_and_rows_hold_no_secrets(env, monkeypatch, caplog):
    import app as application

    monkeypatch.setattr(application, "ACCESS_TKN_EXP", 4_000_000_000)
    env.ex.use_session = True
    caplog.set_level(logging.DEBUG)
    good = approved_plan(env)
    assert execute(env, good).status_code == 200
    assert len(env.ex.sessions) == 1 and env.ex.sessions[0].bearer == SENTINEL_BEARER
    bad = approved_plan(env)
    env.ex.fail_send = RuntimeError(SENTINEL_BEARER)
    assert execute(env, bad).status_code == 502
    env.ex.fail_send = None
    monkeypatch.setattr(application, "ACCESS_TKN_EXP", 0)
    unavailable = approved_plan(env)
    body = problem_of(execute(env, unavailable), 409, "execution_failed")
    assert "session_unavailable" in body["detail"]
    assert row_of(unavailable["plan_id"])["status"] == "failed"
    everything = caplog.text + dump_tables()
    for secret in (SENTINEL_BEARER, SENTINEL_PIN, SENTINEL_API_KEY, env.key["secret"]):
        assert secret not in everything, secret
    # Байты payload хранит только строка плана, в журнале и логах их нет.
    outside = caplog.text + dump_tables(("audit",))
    assert PAYLOAD.decode() not in outside and b64(PAYLOAD) not in outside


# ---------- проверка входных данных ----------


@pytest.mark.parametrize("over", [
    {"capability_id": 1}, {"target": ["t"]}, {"payload_b64": 5}, {"attachments": "x"},
    {"attachments": [{"name": "a"}]}, {"attachments": [{"name": 1, "content_b64": ""}]},
    {"idempotency_key": True}, {"extra": 1}, {"attachments": [{"name": "a", "content_b64": "",
                                                              "extra": 1}]},
])
def test_wrong_shape_is_422_and_stores_nothing(env, over):
    problem_of(prepare(env, **over), 422, "invalid_parameter")
    assert count_plans() == 0 and env.ex.calls() == (0, 0)


def test_missing_fields_are_422(env):
    for field in ("capability_id", "target", "payload_b64", "idempotency_key"):
        body = body_of(env)
        del body[field]
        problem_of(env.client.post(PLANS, json=body, headers=env.headers), 422, "invalid_parameter")
    assert count_plans() == 0


_BIG = b"x" * 1_000_001


@pytest.mark.parametrize("over", [
    {"target": "bad target"}, {"target": ""}, {"target": "t" * 201}, {"target": "t\n"},
    {"idempotency_key": "short"}, {"idempotency_key": "bad key with spaces"},
    {"idempotency_key": "k" * 129}, {"idempotency_key": "valid-key-1\n"},
    {"payload_b64": "!!!not base64"}, {"payload_b64": b64(_BIG)},
    {"attachments": [{"name": "bad name", "content_b64": ""}]},
    {"attachments": [{"name": "a" * 101, "content_b64": ""}]},
    {"attachments": [{"name": "../a", "content_b64": ""}]},
    {"attachments": [{"name": "a", "content_b64": "***"}]},
    {"attachments": [{"name": "a", "content_b64": ""}, {"name": "a", "content_b64": ""}]},
    {"attachments": [{"name": "f%d" % i, "content_b64": ""} for i in range(6)]},
    {"payload_b64": b64(b"x" * 1_000_000),
     "attachments": [{"name": "a", "content_b64": b64(b"y" * 1_000_001)}]},
])
def test_wrong_value_is_400_and_stores_nothing(env, over):
    problem_of(prepare(env, **over), 400, "invalid_parameter")
    assert count_plans() == 0 and env.ex.calls() == (0, 0)


def test_limits_are_inclusive(env):
    ok = prepare(env, payload_b64=b64(b"x" * 1_000_000),
                 attachments=[{"name": "f%d" % i, "content_b64": b64(b"y" * 200_000)}
                              for i in range(5)])
    assert ok.status_code == 201, ok.text
    assert prepare(env, attachments=[], payload_b64="").status_code == 201


def test_unknown_capability_is_503_not_a_plan(env):
    problem_of(prepare(env, capability_id="no.such.cap"), 503, "executor_unavailable")
    problem_of(prepare(env, capability_id="operation.execute"), 503, "executor_unavailable")
    assert count_plans() == 0


# ---------- 15. реестр ----------

_BASE = capabilities.BASE_MACHINE_GATES


def _cap(**kwargs):
    base = dict(id="x.y", title="t", effect="read_local")
    base.update(kwargs)
    return capabilities.Capability(**base)


_EXECUTE_API = ("POST /v1/operations/plans/{plan_id}/execute",)
_PREPARE_API = ("POST /v1/operations/plans",)


def _mutating(**kwargs):
    base = dict(id="operation.execute", machine="enforced", scopes=("external:execute",),
                api=_EXECUTE_API,
                effect="write_external", side_effects=("external_write",),
                gates=_BASE + capabilities.PLAN_GATES)
    base.update(kwargs)
    return _cap(**base)


def test_plan_gates_are_enforced_and_have_a_check_each():
    import machine_api

    assert capabilities.PLAN_GATES == (
        "human_approval", "plan_integrity", "binding_epoch", "execution_claim")
    new = {"plan_record", *capabilities.PLAN_GATES}
    assert new <= capabilities.ENFORCED_GATES and new <= set(machine_api.GATE_CHECKS)
    assert not new & capabilities.PLANNED_GATES
    assert capabilities.PLANNED_GATES == {"esia_token", "selected_certificate", "membership",
                                          "license"}
    for gate in new:
        assert "operations" in machine_api.GATE_CHECKS[gate]


@pytest.mark.parametrize("missing", capabilities.PLAN_GATES)
def test_mutating_operation_needs_every_plan_gate(missing):
    gates = tuple(g for g in _BASE + capabilities.PLAN_GATES if g != missing)
    with pytest.raises(ValueError, match="условия плана"):
        _mutating(gates=gates)
    assert _mutating().machine == "enforced"


_ONLY_RECORD = _BASE + ("plan_record",)


@pytest.mark.parametrize("kwargs", [
    dict(effect="read_external", scopes=("external:prepare",), side_effects=("marks_read",)),
    dict(effect="write_local", scopes=("external:prepare",), side_effects=("reserves_number",)),
    dict(effect="write_external", side_effects=()),
    dict(side_effects=("legal_effect",)),
])
def test_side_effects_need_all_plan_gates_not_only_plan_record(kwargs):
    with pytest.raises(ValueError):
        _mutating(gates=_ONLY_RECORD, **kwargs)


def test_local_write_is_enforced_only_with_plan_record():
    with pytest.raises(ValueError, match="plan_record"):
        _cap(id="operation.prepare", effect="write_local", machine="enforced",
             scopes=("external:prepare",), api=_PREPARE_API, gates=_BASE)
    ok = _cap(id="operation.prepare", effect="write_local", machine="enforced",
              scopes=("external:prepare",), api=_PREPARE_API, gates=_BASE + ("plan_record",))
    assert ok.machine == "enforced"


@pytest.mark.parametrize("kwargs", [
    # Чужая возможность (например, из private) с условиями плана на своём маршруте.
    dict(id="private.send", api=("POST /v1/private/send",)),
    dict(id="private.send", api=_EXECUTE_API),
    # Встроенный id, но другой маршрут.
    dict(api=("POST /v1/operations/plans/{plan_id}/other",)),
    # Условия не своего маршрута.
    dict(gates=_BASE + capabilities.PLAN_GATES + ("plan_record",)),
])
def test_plan_gates_are_valid_only_on_the_builtin_plan_routes(kwargs):
    with pytest.raises(ValueError, match="встроенных маршрутах плана"):
        _mutating(**kwargs)


def test_plan_record_is_valid_only_on_the_prepare_route():
    for cap_id, api in (("private.prepare", ("POST /v1/private/plans",)),
                        ("operation.execute", _EXECUTE_API)):
        with pytest.raises(ValueError, match="встроенных маршрутах плана"):
            _cap(id=cap_id, effect="write_local", machine="enforced",
                 scopes=("external:prepare",), api=api, gates=_BASE + ("plan_record",))


def test_private_registration_with_plan_gates_is_refused(monkeypatch):
    monkeypatch.setattr(capabilities, "_private", [])
    with pytest.raises(ValueError):
        capabilities.register(_mutating(id="private.send", api=("POST /v1/private/send",)))
    assert capabilities.get("private.send") is None


def test_operation_capabilities_are_declared_exactly():
    prepare_cap = capabilities.get("operation.prepare")
    assert prepare_cap.api == ("POST /v1/operations/plans",)
    assert prepare_cap.effect is capabilities.Effect.WRITE_LOCAL
    assert prepare_cap.scopes == ("external:prepare",) and prepare_cap.requires == ()
    assert prepare_cap.gates == _BASE + ("plan_record",) and prepare_cap.side_effects == ()
    get_cap = capabilities.get("operation.plan.get")
    assert get_cap.api == ("GET /v1/operations/plans/{plan_id}",)
    assert get_cap.effect is capabilities.Effect.READ_LOCAL
    assert get_cap.scopes == ("external:prepare",) and get_cap.gates == _BASE
    run_cap = capabilities.get("operation.execute")
    assert run_cap.api == ("POST /v1/operations/plans/{plan_id}/execute",)
    assert run_cap.effect is capabilities.Effect.WRITE_EXTERNAL
    assert run_cap.scopes == ("external:execute",)
    assert set(run_cap.side_effects) == capabilities.SIDE_EFFECTS
    assert run_cap.gates == _BASE + capabilities.PLAN_GATES
    for cap in (prepare_cap, get_cap, run_cap):
        assert cap.machine == "enforced" and cap.mcp_profile is capabilities.McpProfile.NONE
    for cap_id, op in (("operation.review", "GET /v1/admin/operations/plans/{plan_id}"),
                       ("operation.approve", "POST /v1/admin/operations/plans/{plan_id}/approve")):
        admin = capabilities.get(cap_id)
        assert admin.api == (op,) and admin.effect is capabilities.Effect.ADMIN
        assert admin.machine == "none" and admin.requires == ("login", "installation_admin")
        assert admin.mcp_profile is capabilities.McpProfile.NONE and admin.scopes == ()


def test_only_the_three_machine_routes_skip_the_session_check():
    import auth_api
    import operations_api

    names = sorted(endpoint.__name__ for endpoint in auth_api.machine_endpoints)
    assert names == ["operator_context_get", "plan_execute", "plan_get", "prepare_plan"]
    # Человеческие маршруты в машинные не входят: ключ их не открывает.
    assert "review" not in names and "approve" not in names
    assert operations_api.admin_router is not None


def test_executor_registration_is_validated(monkeypatch):
    import operations

    monkeypatch.setattr(capabilities, "_private", [])

    def executor(cap_id, calls, run=None):
        async def default_run(self, ctx, payload, attachments, target):
            return {}

        return type("E", (), {"capability_id": cap_id, "external_calls": calls,
                              "run": run or default_run})()

    call = operations.ExternalCall
    capabilities.register(_cap(id="t.ok", effect="write_external", scopes=("external:execute",),
                               side_effects=("external_write",), machine="target"))
    capabilities.register(_cap(id="t.none", effect="write_external", scopes=("external:execute",),
                               side_effects=("external_write",)))
    capabilities.register(_cap(id="t.operate", effect="write_local", scopes=("local:write",),
                               side_effects=("external_write",), machine="target",
                               mcp_profile="operate"))
    capabilities.register(_cap(id="t.read", effect="read_local", scopes=("local:read",),
                               machine="target"))
    bad = [
        executor("no.such", (call("a", ("external_write",)),)),
        executor("t.ok", (call("a", ("external_write", "marks_read")),)),
        executor("t.ok", (call("a", ()),)),
        executor("t.ok", (call("a", ("teleport",)),)),
        executor("t.ok", ()),
        executor("t.ok", [call("a", ("external_write",))]),
        executor("t.ok", (call("a", ("external_write",)), call("a", ("external_write",)))),
        executor("t.ok", (call("Bad Name", ("external_write",)),)),
        executor("t.none", (call("a", ("external_write",)),)),
        executor("t.operate", (call("a", ("external_write",)),)),
        executor("t.read", (call("a", ()),)),
        executor("operation.execute", (call("a", tuple(capabilities.SIDE_EFFECTS)),)),
        executor("t.ok", (call("a", ("external_write",)),), run=lambda self, *a: None),
    ]
    for item in bad:
        with pytest.raises(ValueError):
            operations.register_executor(item)
    assert operations._executors == {}
    good = executor("t.ok", (call("a", ("external_write",)),))
    operations.register_executor(good)
    try:
        assert operations.get_executor("t.ok") is good
        with pytest.raises(ValueError):
            operations.register_executor(good)
    finally:
        assert operations.unregister_executor("t.ok") is True
    assert operations.unregister_executor("t.ok") is False and operations._executors == {}


def test_openapi_describes_the_operation_routes(client):
    spec = client.get("/openapi.json").json()["paths"]
    prepare_op = spec[PLANS]["post"]
    assert {"200", "201", "401", "403", "409", "410", "422", "502", "503"} <= set(
        prepare_op["responses"])
    execute_op = spec[PLANS + "/{plan_id}/execute"]["post"]
    assert PROBLEM in execute_op["responses"]["502"]["content"]
    assert PROBLEM in execute_op["responses"]["409"]["content"]
    assert "get" in spec[PLANS + "/{plan_id}"]
    admin = spec["/v1/admin/operations/plans/{plan_id}/approve"]["post"]
    assert {"401", "403", "404", "409", "410"} <= set(admin["responses"])
    assert "get" in spec["/v1/admin/operations/plans/{plan_id}"]


# ---------- 16. политика целевой возможности (R8) ----------


class OneCallExecutor:
    """Один внешний вызов send с журналом шагов."""

    def __init__(self, capability_id):
        import operations

        self.capability_id = capability_id
        self.external_calls = (operations.ExternalCall("send", ("external_write",)),)
        self.sends = 0

    async def run(self, ctx, payload, attachments, target):
        ctx.start_call("send")
        self.sends += 1
        ctx.mark_done("send", "msg-1")
        return {"sent": True}


@pytest.fixture()
def targets(env):
    """Регистрирует целевые возможности с исполнителем; снимает исполнителей после теста."""
    import operations

    made = []

    def make(cap_id, *, scopes=("external:execute",), gates=(), implemented=True):
        capabilities.register(capabilities.Capability(
            id=cap_id, title="Цель", effect="write_external", api=("POST /test/" + cap_id,),
            scopes=scopes, gates=gates, implemented=implemented,
            side_effects=("external_write",), machine="target"))
        executor = OneCallExecutor(cap_id)
        operations.register_executor(executor)
        made.append(cap_id)
        return executor

    yield make
    for cap_id in made:
        operations.unregister_executor(cap_id)


def swap(cap_id, **changes):
    """Подменить объявление возможности в реестре (как обновлённый private-модуль)."""
    for idx, cap in enumerate(capabilities._private):
        if cap.id == cap_id:
            capabilities._private[idx] = dataclasses.replace(cap, **changes)
            return
    raise AssertionError(cap_id)


_UNCHECKED = [dict(gates=("membership",)), dict(gates=("license",)),
              dict(gates=("esia_token",)), dict(gates=("selected_certificate",)),
              dict(implemented=False)]


@pytest.mark.parametrize("kwargs", _UNCHECKED)
def test_target_with_an_unchecked_gate_or_not_implemented_is_not_registered(env, targets, kwargs):
    with pytest.raises(ValueError, match="не допускается к исполнению"):
        targets("t.bad", **kwargs)
    problem_of(prepare(env, capability_id="t.bad"), 503, "executor_unavailable")
    assert count_plans() == 0


@pytest.mark.parametrize("kwargs", _UNCHECKED)
def test_unchecked_gate_added_after_approve_blocks_execute(env, kwargs):
    plan = approved_plan(env)
    swap(CAP, **kwargs)
    body = problem_of(execute(env, plan), 503, "executor_unavailable")
    assert "не допускается к исполнению" in body["detail"]
    assert env.ex.counts == {"sign": 0, "reserve_number": 0, "send": 0}
    assert row_of(plan["plan_id"])["status"] == "approved"
    problem_of(prepare(env), 503, "executor_unavailable")


def test_is_bound_target_without_an_is_on_either_side_is_refused(env, targets):
    executor = targets("t.bound", gates=("is_bound",))
    problem_of(prepare(env, capability_id="t.bound"), 409, "context_mismatch")
    assert count_plans() == 0 and executor.sends == 0


def test_is_bound_target_with_the_same_is_runs(env, targets):
    executor = targets("t.bound", gates=("is_bound",))
    bind(is_ref="is-1")
    key = issue(context={"organization_ref": ORG, "contour": "TEST", "is_ref": "is-1"})
    created = prepare(env, headers=bearer(key["secret"]), capability_id="t.bound")
    assert created.status_code == 201, created.text
    plan = created.json()
    assert plan["preview"]["target_policy"]["gates"] == ["is_bound"]
    assert approve(env, plan).status_code == 200
    response = execute(env, plan, headers=bearer(key["secret"]))
    assert response.status_code == 200, response.text
    assert executor.sends == 1


def test_target_scope_is_required_from_the_key(env, targets):
    executor = targets("t.write", scopes=("external:execute", "local:write"))
    body = problem_of(prepare(env, capability_id="t.write"), 403, "forbidden")
    assert body["detail"] == "insufficient_scope"
    assert count_plans() == 0
    strong = issue(scopes=SCOPES + ("local:write",))
    created = prepare(env, headers=bearer(strong["secret"]), capability_id="t.write")
    assert created.status_code == 201, created.text
    plan = created.json()
    assert approve(env, plan).status_code == 200
    # Право целевой операции не заменяет право этапа: без external:execute нельзя.
    prepare_only = issue(scopes=("external:prepare", "local:write"))
    problem_of(execute(env, plan, headers=bearer(prepare_only["secret"])), 403, "forbidden")
    assert executor.sends == 0
    assert execute(env, plan, headers=bearer(strong["secret"])).status_code == 200
    assert executor.sends == 1


def test_stage_scopes_split_prepare_and_execute():
    import operations

    cap = capabilities.Capability(
        id="t.s", title="t", effect="write_external", scopes=("external:execute", "local:write"),
        side_effects=("external_write",), machine="target")
    assert operations.stage_scopes(cap, "prepare") == {"external:prepare", "local:write"}
    assert operations.stage_scopes(cap, "execute") == {"external:execute", "local:write"}


@pytest.mark.parametrize("changes", [
    dict(gates=("is_bound",)),
    dict(scopes=("external:execute", "local:write")),
    dict(side_effects=("external_write", "reserves_number", "consumes_quota")),
])
def test_policy_change_after_approve_is_policy_changed(env, changes):
    plan = approved_plan(env)
    if "side_effects" in changes:
        # Набор эффектов вызовов должен совпадать с возможностью: меняем и исполнителя.
        import operations

        env.ex.external_calls = env.ex.external_calls[:1] + (
            operations.ExternalCall("send", ("external_write", "consumes_quota")),)
    swap(CAP, **changes)
    expected = (503, "executor_unavailable") if "side_effects" in changes else (409, "policy_changed")
    problem_of(execute(env, plan), *expected)
    assert env.ex.counts == {"sign": 0, "reserve_number": 0, "send": 0}
    assert row_of(plan["plan_id"])["status"] == "approved"


def test_policy_change_during_execution_stops_before_the_first_call(env):
    plan = approved_plan(env)
    env.ex.after_sign = lambda: swap(CAP, gates=("membership",))
    body = problem_of(execute(env, plan), 409, "context_changed")
    assert "policy_changed" in body["detail"]
    assert env.ex.counts == {"sign": 1, "reserve_number": 0, "send": 0}
    assert row_of(plan["plan_id"])["status"] == "failed"


def test_policy_is_part_of_the_plan_hash(env):
    import auth_store

    plan = prepare(env).json()
    policy = plan["preview"]["target_policy"]
    assert policy["capability_id"] == CAP and policy["implemented"] is True
    assert policy["scopes"] == ["external:execute"] and policy["gates"] == []
    assert approve(env, plan).status_code == 200
    # Подмена политики в строке плана после одобрения: хеш больше не сходится.
    with auth_store.write() as db:
        db.execute("UPDATE operation_plans SET target_policy = ? WHERE id = ?",
                   (json.dumps({**policy, "scopes": []}, sort_keys=True), plan["plan_id"]))
    problem_of(execute(env, plan), 409, "plan_hash_mismatch")
    assert env.ex.calls() == (0, 0)


# ---------- 17. момент захвата после блокировки (R9) ----------


def _claim_waits_for_a_writer(monkeypatch, while_waiting):
    """claim_plan ждёт чужую транзакцию записи; пока он ждёт, выполняется ``while_waiting``."""
    import auth_store
    import operations

    real_claim = operations.claim_plan

    def blocked(*args, **kwargs):
        locked = threading.Event()

        def writer():
            connection = sqlite3.connect(str(auth_store.db_path()), isolation_level=None)
            try:
                connection.execute("BEGIN IMMEDIATE")
                locked.set()
                threading.Event().wait(0.3)
                while_waiting()
                connection.execute("COMMIT")
            finally:
                connection.close()

        thread = threading.Thread(target=writer)
        thread.start()
        assert locked.wait(5)
        try:
            return real_claim(*args, **kwargs)
        finally:
            thread.join(5)

    monkeypatch.setattr(operations, "claim_plan", blocked)


def test_plan_that_expires_while_the_claim_waits_for_the_lock_is_410(env, monkeypatch):
    plan = approved_plan(env)
    _claim_waits_for_a_writer(monkeypatch, lambda: forward(monkeypatch, 11))
    problem_of(execute(env, plan), 410, "plan_expired")
    assert env.ex.counts == {"sign": 0, "reserve_number": 0, "send": 0}
    assert row_of(plan["plan_id"])["status"] == "approved"


def test_credential_that_expires_while_the_claim_waits_for_the_lock_is_401(env, monkeypatch):
    import operations

    monkeypatch.setattr(operations, "PLAN_TTL", timedelta(days=5))
    key = issue(ttl_days=1)
    created = prepare(env, headers=bearer(key["secret"]))
    assert created.status_code == 201, created.text
    plan = created.json()
    assert approve(env, plan).status_code == 200
    _claim_waits_for_a_writer(monkeypatch, lambda: forward(monkeypatch, 2 * 24 * 60))
    response = execute(env, plan, headers=bearer(key["secret"]))
    problem_of(response, 401, "unauthenticated")
    assert response.headers["www-authenticate"] == "Bearer"
    assert env.ex.counts == {"sign": 0, "reserve_number": 0, "send": 0}
    assert row_of(plan["plan_id"])["status"] == "approved"


def test_claim_reads_the_clock_inside_the_transaction(env, monkeypatch):
    import auth_store
    import operations
    import operator_context

    plan = approved_plan(env)
    stored = operations.get_plan(plan["plan_id"])
    real_write = auth_store.write
    entered = []

    def write():
        entered.append(True)
        return real_write()

    real_clock = operations._clock

    def clock():
        # Часы плана не читаются до входа в транзакцию захвата.
        assert entered, "claim read the clock before the write transaction"
        return real_clock()

    monkeypatch.setattr(auth_store, "write", write)
    monkeypatch.setattr(operations, "_clock", clock)
    assert operations.claim_plan(stored.id, stored.approved_hash, stored.client_id,
                                 operator_context.OperatorContext(**stored.context)) == 1


# ---------- 18. журнал шагов (R10) ----------


def test_unknown_after_a_reserve_keeps_the_reserve_and_its_reference(env):
    plan = approved_plan(env)
    env.ex.fail_send = RuntimeError("connection reset")
    body = problem_of(execute(env, plan), 502, "outcome_unknown")
    assert "reserve_number" in body["detail"] and "send" in body["detail"]
    stored = env.client.get("%s/%s" % (PLANS, plan["plan_id"]), headers=env.headers).json()
    assert stored["status"] == "unknown"
    assert stored["result"] == {"completed_calls": ["reserve_number"], "uncertain_calls": ["send"]}
    steps = {step["name"]: step for step in stored["steps"]}
    assert steps["reserve_number"]["state"] == "completed"
    assert steps["reserve_number"]["reference"] == "N-1"
    assert steps["send"]["state"] == "started" and steps["send"]["reference"] is None
    problem_of(execute(env, plan), 409, "plan_state")
    assert env.ex.calls() == (1, 1)


def _claimed_context(env, plan):
    import operations
    import operator_context

    stored = operations.get_plan(plan["plan_id"])
    context = operator_context.OperatorContext(**stored.context)
    assert operations.claim_plan(stored.id, stored.approved_hash, stored.client_id, context) == 1
    return operations.ExecutionContext(
        stored.id, stored.client_id, context, capability_id=stored.capability_id,
        target_policy=stored.target_policy,
        call_names=tuple(call["name"] for call in stored.external_calls))


def test_crash_after_a_reserve_keeps_the_journal_through_recovery(env):
    import operations

    plan = approved_plan(env)
    ctx = _claimed_context(env, plan)
    ctx.start_call("reserve_number")
    ctx.mark_done("reserve_number", "N-7")
    ctx.start_call("send")
    # Процесс оборвался здесь: завершения нет, журнал уже в базе.
    assert operations.recover_inflight() == 1
    row = row_of(plan["plan_id"])
    assert row["status"] == "unknown" and row["error_code"] == "interrupted"
    assert json.loads(row["result"]) == {"completed_calls": ["reserve_number"],
                                         "uncertain_calls": ["send"]}
    review = env.admin.get("/v1/admin/operations/plans/%s" % plan["plan_id"]).json()
    assert [(s["name"], s["state"], s["reference"]) for s in review["steps"]] == [
        ("reserve_number", "completed", "N-7"), ("send", "started", None)]
    problem_of(execute(env, plan), 409, "plan_state")
    assert env.ex.counts == {"sign": 0, "reserve_number": 0, "send": 0}
    # После восстановления журнал не пополняется: вызов не начинается.
    with pytest.raises(operations.ContextChanged):
        ctx.start_call("send")


def test_startup_recovery_keeps_the_completed_reserve(env):
    import app as application

    plan = approved_plan(env)
    ctx = _claimed_context(env, plan)
    ctx.start_call("reserve_number")
    ctx.mark_done("reserve_number", "N-8")
    with TestClient(application.app):
        pass
    row = row_of(plan["plan_id"])
    assert row["status"] == "unknown"
    assert json.loads(row["result"]) == {"completed_calls": ["reserve_number"],
                                         "uncertain_calls": []}


def test_call_order_violations_are_never_a_silent_success(env):
    import operations

    plan = approved_plan(env)
    ctx = _claimed_context(env, plan)
    with pytest.raises(operations.NotSent):
        ctx.start_call("teleport")
    ctx.start_call("reserve_number")
    # Новый вызов при начатом и не отмеченном прежнем: исход прежнего неизвестен.
    with pytest.raises(RuntimeError):
        ctx.start_call("send")
    ctx.mark_done("reserve_number", "N-9")
    with pytest.raises(operations.NotSent):
        ctx.start_call("reserve_number")


def test_not_sent_after_start_marks_only_that_call_as_not_sent(env):
    import operations

    plan = approved_plan(env)
    original = env.ex.run

    async def run(ctx, payload, attachments, target):
        ctx.start_call("reserve_number")
        ctx.mark_done("reserve_number", "N-2")
        ctx.start_call("send")
        raise operations.NotSent("transport_closed")

    env.ex.run = run
    body = problem_of(execute(env, plan), 409, "execution_failed")
    assert "reserve_number" in body["detail"]
    stored = env.admin.get("/v1/admin/operations/plans/%s" % plan["plan_id"]).json()
    assert stored["status"] == "failed"
    assert stored["result"] == {"completed_calls": ["reserve_number"]}
    assert [(s["name"], s["state"]) for s in stored["steps"]] == [
        ("reserve_number", "completed"), ("send", "not_sent")]
    env.ex.run = original


def test_only_a_short_reference_is_stored(env):
    plan = approved_plan(env)
    original = env.ex.run

    async def run(ctx, payload, attachments, target):
        ctx.start_call("reserve_number")
        ctx.mark_done("reserve_number", "token=" + SENTINEL_BEARER + " full upstream answer")
        ctx.start_call("send")
        ctx.mark_done("send", "msg-1")
        return {"sent": True}

    env.ex.run = run
    assert execute(env, plan).status_code == 200
    stored = env.admin.get("/v1/admin/operations/plans/%s" % plan["plan_id"]).json()
    assert [(s["name"], s["reference"]) for s in stored["steps"]] == [
        ("reserve_number", None), ("send", "msg-1")]
    assert SENTINEL_BEARER not in dump_tables()
    env.ex.run = original


def test_pending_call_stays_uncertain_even_if_the_context_then_changes(env):
    import integration_auth

    plan = approved_plan(env)

    async def run(ctx, payload, attachments, target):
        ctx.start_call("reserve_number")
        # Исход резервирования не записан, а ключ тем временем отозван.
        integration_auth.revoke(env.key["id"], by=ADMIN_ID)
        ctx.start_call("send")
        return {"sent": True}

    env.ex.run = run
    # Отказ по контексту не превращает начатое резервирование в «не отправлено».
    problem_of(execute(env, plan), 502, "outcome_unknown")
    row = row_of(plan["plan_id"])
    assert row["status"] == "unknown"
    assert json.loads(row["result"]) == {"completed_calls": [], "uncertain_calls": ["reserve_number"]}
