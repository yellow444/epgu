"""Сквозной цикл MCP: in-process сервер -> HTTP-клиент 4a -> настоящее app.app -> mock executor.

Сервер собран явно (``build_operate_registry``), штатные профили и CLI
операций не выдают. Ключ интеграции синтетический, лежит во временном файле
вне Git; одобряет человек по сессии (``env.admin``), не tool. Реальных
адресов, сертификатов и runtime нет.
"""

import base64
import json
import logging

import httpx
import pytest
from fastapi.testclient import TestClient

from test_integration_client_cycle import Spy
from test_operations import (  # noqa: F401  (fixtures)
    CAP,
    PAYLOAD,
    SENTINEL_API_KEY,
    SENTINEL_BEARER,
    SENTINEL_PIN,
    approve,
    client,
    env,
    forward,
    issue,
    mock_executor,
    row_of,
    store,
)

pytest.importorskip("mcp")
pytest.importorskip("epgu_mcp.operations")

import anyio  # noqa: E402
from mcp import Client  # noqa: E402

from epgu_mcp.operations import (  # noqa: E402
    OperationsAdapter,
    OperationsConfig,
    ResultProjection,
    build_operate_registry,
)
from epgu_mcp.server import build_registry, build_server, load_knowledge  # noqa: E402

pytestmark = pytest.mark.real_auth

CANARY = "CANARY-EXECUTOR-SECRET-77c1"
PROJECTION = {CAP: ResultProjection({"sent": bool, "target": str, "number": str}, step_references=True)}
PAYLOAD_B64 = base64.b64encode(PAYLOAD).decode()
EXECUTE_PATH = "/execute"


def prepare_args(key="mcp-e2e-0001", target="target-1"):
    return {"capability_id": CAP, "target": target, "payload_b64": PAYLOAD_B64,
            "attachments": [{"name": "scan-1.bin", "content_b64": base64.b64encode(b"\x00\xff\xfe").decode()}],
            "idempotency_key": key}


class Faulty(httpx.BaseTransport):
    """Передаёт запросы приложению, но может сломать ответ после обработки."""

    def __init__(self, inner, fail=None):
        self.inner = inner
        self.fail = fail
        self.requests = []

    def handle_request(self, request):
        self.requests.append(request)
        forced = self.fail(request) if self.fail else None
        if isinstance(forced, httpx.Response):
            return forced
        response = self.inner.handle_request(request)
        if isinstance(forced, Exception):
            # Сервер уже обработал запрос, ответ потерян по дороге.
            raise forced
        return response


def mcp_for(env, tmp_path, secret=None, fail=None, projections=PROJECTION):
    import app as application

    path = tmp_path / ("credential-%d" % len(list(tmp_path.glob("credential-*"))))
    path.write_text((secret or env.key["secret"]) + "\n", encoding="ascii")
    transport = Faulty(Spy(TestClient(application.app, base_url="https://testserver")._transport), fail)
    config = OperationsConfig(base_url="https://testserver", credential_file=path, transport=transport,
                              projections=projections)
    server = build_server(build_operate_registry(load_knowledge(), OperationsAdapter(config)))
    return server, transport


def call(server, name, args):
    async def main():
        async with Client(server) as client:
            return await client.call_tool(name, args)

    return anyio.run(main)


def ok(result):
    assert result.is_error is False, result.content[0].text
    return result.structured_content


def error_of(result):
    assert result.is_error is True
    return json.loads(result.content[0].text)["error"]


def text_of(result):
    return "".join(getattr(c, "text", "") for c in result.content) + json.dumps(result.structured_content or {})


def assert_clean(env, *results):
    for result in results:
        dump = text_of(result)
        for secret in (env.key["secret"], SENTINEL_BEARER, SENTINEL_PIN, SENTINEL_API_KEY, PAYLOAD_B64,
                       PAYLOAD.decode(), CANARY):
            assert secret not in dump, secret
        for key in ("payload_b64", "attachment_contents", "content_b64", "approved_by", "client_id",
                    "hash_verified"):
            assert '"%s"' % key not in dump, key


def executions(transport):
    return [r for r in transport.requests if r.url.path.endswith(EXECUTE_PATH)]


# ------------------------------------------------------------ положительный цикл

def test_prepare_human_approve_execute_and_get_through_mcp(env, tmp_path):
    server, transport = mcp_for(env, tmp_path)
    first = call(server, "plan_prepare", prepare_args())
    again = call(server, "plan_prepare", prepare_args())
    plan, repeat = ok(first), ok(again)
    assert (plan["created"], repeat["created"]) == (True, False)
    assert repeat["plan_id"] == plan["plan_id"] and repeat["plan_hash"] == plan["plan_hash"]
    assert plan["status"] == "planned" and env.ex.calls() == (0, 0)
    assert plan["preview"]["attachments"][0]["name"] == "scan-1.bin"

    # Одобряет человек по сессии: такого tool нет.
    assert approve(env, plan).status_code == 200
    done = call(server, "plan_execute", {"plan_id": plan["plan_id"], "plan_hash": plan["plan_hash"]})
    assert ok(done) == {"plan_id": plan["plan_id"], "status": "succeeded", "withheld": ["result"]}
    assert env.ex.calls() == (1, 1)

    stored = call(server, "plan_get", {"plan_id": plan["plan_id"]})
    data = ok(stored)
    assert data["status"] == "succeeded" and data["withheld"] == []
    assert data["result"] == {"sent": True, "target": "target-1", "number": "N-1"}
    assert [(s["name"], s["state"], s["reference"]) for s in data["steps"]] == [
        ("reserve_number", "completed", "N-1"), ("send", "completed", "msg-1")]

    for request in transport.requests:
        assert request.headers["authorization"] == "Bearer " + env.key["secret"]
        assert "cookie" not in request.headers and env.key["secret"] not in str(request.url)
    assert len(executions(transport)) == 1
    assert_clean(env, first, again, done, stored)


def test_executor_result_outside_the_projection_is_withheld(env, tmp_path):
    run = env.ex.run

    async def leaky(ctx, payload, attachments, target):
        result = await run(ctx, payload, attachments, target)
        return {**result, "token": CANARY, "nested": {"value": CANARY}}

    env.ex.run = leaky
    server, _ = mcp_for(env, tmp_path, projections={CAP: ResultProjection({"number": str})})
    plan = ok(call(server, "plan_prepare", prepare_args()))
    approve(env, plan)
    done = call(server, "plan_execute", {"plan_id": plan["plan_id"], "plan_hash": plan["plan_hash"]})
    stored = call(server, "plan_get", {"plan_id": plan["plan_id"]})
    data = ok(stored)
    assert data["result"] == {"number": "N-1"}
    assert data["withheld"] == ["result", "step_references"]
    assert {s["reference"] for s in data["steps"]} == {None}
    assert CANARY in row_of(plan["plan_id"])["result"]
    assert_clean(env, done, stored)


# ------------------------------------------------------------ отказы

def test_unknown_key_is_unauthenticated(env, tmp_path):
    server, transport = mcp_for(env, tmp_path, secret="itk_" + "Z" * 40)
    result = call(server, "plan_prepare", prepare_args())
    assert error_of(result)["code"] == "unauthenticated" and len(transport.requests) == 1
    assert_clean(env, result)


def test_key_without_execute_scope_is_forbidden_and_calls_nothing(env, tmp_path):
    limited = issue(scopes=("external:prepare",))
    server, _ = mcp_for(env, tmp_path, secret=limited["secret"])
    plan = ok(call(server, "plan_prepare", prepare_args()))
    approve(env, plan)
    result = call(server, "plan_execute", {"plan_id": plan["plan_id"], "plan_hash": plan["plan_hash"]})
    assert error_of(result)["code"] == "forbidden"
    assert env.ex.calls() == (0, 0) and row_of(plan["plan_id"])["status"] == "approved"


def test_state_and_idempotency_conflicts(env, tmp_path):
    server, _ = mcp_for(env, tmp_path)
    plan = ok(call(server, "plan_prepare", prepare_args()))
    early = call(server, "plan_execute", {"plan_id": plan["plan_id"], "plan_hash": plan["plan_hash"]})
    other = call(server, "plan_prepare", prepare_args(target="target-2"))
    assert error_of(early)["code"] == "plan_state"
    assert error_of(other)["code"] == "idempotency_conflict"
    assert env.ex.calls() == (0, 0)


def test_expired_plan_is_refused(env, tmp_path):
    server, _ = mcp_for(env, tmp_path)
    plan = ok(call(server, "plan_prepare", prepare_args()))
    approve(env, plan)
    forward(env.monkeypatch, 11)
    result = call(server, "plan_execute", {"plan_id": plan["plan_id"], "plan_hash": plan["plan_hash"]})
    assert error_of(result)["code"] == "plan_expired" and env.ex.calls() == (0, 0)


def test_missing_executor_is_unavailable(env, tmp_path):
    import operations

    server, _ = mcp_for(env, tmp_path)
    plan = ok(call(server, "plan_prepare", prepare_args()))
    approve(env, plan)
    operations.unregister_executor(CAP)
    result = call(server, "plan_execute", {"plan_id": plan["plan_id"], "plan_hash": plan["plan_hash"]})
    assert error_of(result)["code"] == "executor_unavailable"
    assert row_of(plan["plan_id"])["status"] == "approved"


# ------------------------------------------------------------ неизвестный исход

def test_unknown_after_a_partial_effect_is_reported_once_without_retry(env, tmp_path):
    server, transport = mcp_for(env, tmp_path)
    plan = ok(call(server, "plan_prepare", prepare_args()))
    approve(env, plan)
    env.ex.fail_send = RuntimeError("connection reset " + CANARY)
    result = call(server, "plan_execute", {"plan_id": plan["plan_id"], "plan_hash": plan["plan_hash"]})
    err = error_of(result)
    assert err["code"] == "outcome_unknown" and err["plan_id"] == plan["plan_id"] and err["http_status"] == 502
    assert (err["completed_calls"], err["uncertain_calls"]) == (["reserve_number"], ["send"])
    sent = len(transport.requests)
    # Ни повтора, ни скрытого plan_get внутри execute.
    assert [r.method for r in transport.requests].count("GET") == 0 and len(executions(transport)) == 1

    again = call(server, "plan_execute", {"plan_id": plan["plan_id"], "plan_hash": plan["plan_hash"]})
    assert error_of(again)["code"] == "plan_state" and env.ex.calls() == (1, 1)
    stored = ok(call(server, "plan_get", {"plan_id": plan["plan_id"]}))
    assert stored["status"] == "unknown"
    assert stored["result"] == {"completed_calls": ["reserve_number"], "uncertain_calls": ["send"]}
    assert len(transport.requests) == sent + 2
    assert_clean(env, result, again)


def test_lost_execute_answer_is_unknown_with_null_calls(env, tmp_path):
    lose = {"on": True}

    def fail(request):
        if lose["on"] and request.url.path.endswith(EXECUTE_PATH):
            return httpx.ReadError("answer lost")
        return None

    server, transport = mcp_for(env, tmp_path, fail=fail)
    plan = ok(call(server, "plan_prepare", prepare_args()))
    approve(env, plan)
    result = call(server, "plan_execute", {"plan_id": plan["plan_id"], "plan_hash": plan["plan_hash"]})
    err = error_of(result)
    assert err["code"] == "outcome_unknown" and err["reason"] == "transport_error"
    assert err["completed_calls"] is None and err["uncertain_calls"] is None and err["http_status"] is None
    # Сервер план исполнил, MCP об этом не знает и не повторяет.
    assert row_of(plan["plan_id"])["status"] == "succeeded" and env.ex.calls() == (1, 1)
    assert len(executions(transport)) == 1
    assert ok(call(server, "plan_get", {"plan_id": plan["plan_id"]}))["status"] == "succeeded"
    assert_clean(env, result)


def test_forbidden_plan_get_does_not_cancel_the_unknown_outcome(env, tmp_path):
    def fail(request):
        if request.method == "GET":
            return httpx.Response(403, headers={"content-type": "application/problem+json"},
                                  json={"type": "about:blank", "title": "Нет права", "status": 403,
                                        "code": "forbidden", "detail": "нужен external:prepare"})
        return None

    server, transport = mcp_for(env, tmp_path, fail=fail)
    plan = ok(call(server, "plan_prepare", prepare_args()))
    approve(env, plan)
    env.ex.fail_send = RuntimeError("connection reset")
    unknown = error_of(call(server, "plan_execute", {"plan_id": plan["plan_id"], "plan_hash": plan["plan_hash"]}))
    refused = error_of(call(server, "plan_get", {"plan_id": plan["plan_id"]}))
    assert unknown["code"] == "outcome_unknown" and refused["code"] == "forbidden"
    assert row_of(plan["plan_id"])["status"] == "unknown"
    assert len(executions(transport)) == 1 and env.ex.calls() == (1, 1)


# ------------------------------------------------------------ штатный сервер и журнал

def test_standard_operate_registry_has_no_operations(env):
    registry = build_registry("operate", load_knowledge())
    assert not {"plan_prepare", "plan_get", "plan_execute"} & set(registry.names())


def test_logs_carry_no_secret_payload_or_canary(env, tmp_path, caplog):
    caplog.set_level(logging.DEBUG)
    server, _ = mcp_for(env, tmp_path)
    plan = ok(call(server, "plan_prepare", prepare_args()))
    approve(env, plan)
    env.ex.fail_send = RuntimeError("connection reset " + CANARY)
    call(server, "plan_execute", {"plan_id": plan["plan_id"], "plan_hash": plan["plan_hash"]})
    call(server, "plan_get", {"plan_id": plan["plan_id"]})
    logged = "\n".join(r.getMessage() for r in caplog.records)
    assert "tools/call plan_execute: outcome_unknown" in logged
    for secret in (env.key["secret"], SENTINEL_BEARER, SENTINEL_PIN, SENTINEL_API_KEY, PAYLOAD_B64, CANARY):
        assert secret not in logged, secret
