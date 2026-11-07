"""Схемы целевых MCP tools против настоящего backend.

Каталог ``mcp-server/src/epgu_mcp/targets.py`` описывает tools plan_prepare,
plan_get и plan_execute; в штатных профилях они не включены. Здесь
проверяется, что запросы HTTP-клиента 4a проходят входные схемы, ответы
app.app с тестовым исполнителем содержат все поля выходных схем нужных типов
(источник явной проекции адаптера) и что коды отказов входят в объявленные.
Сама проекция и её строгие схемы проверяются в test_mcp_operations_adapter.py.
Реальных адресов, сертификатов и runtime нет.
"""

import importlib.util
import json
import sys
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator

from test_integration_client_cycle import sdk_client
from test_operations import (  # noqa: F401  (fixtures)
    CAP,
    PAYLOAD,
    approve,
    client,
    env,
    mock_executor,
    store,
)

_TARGETS = Path(__file__).resolve().parents[1] / "mcp-server" / "src" / "epgu_mcp" / "targets.py"

pytestmark = [
    pytest.mark.real_auth,
    pytest.mark.skipif(not _TARGETS.is_file(), reason="нет каталога целевых tools MCP"),
]


def _load_targets():
    spec = importlib.util.spec_from_file_location("_epgu_mcp_targets", _TARGETS)
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # нужно для dataclass
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    return {t.name: t for t in module.TARGET_TOOLS}


@pytest.fixture(scope="module")
def tools():
    return _load_targets()


# Поля, которые добавляет проекция адаптера, а не backend.
PROJECTION_ONLY = {"withheld", "created"}


def source_view(schema):
    """Выходная схема каталога как требование к ответу backend.

    Те же поля и типы, но без полей проекции и без запрета лишних полей:
    ответ backend шире того, что выдаёт MCP.
    """
    if isinstance(schema, list):
        return [source_view(item) for item in schema]
    if not isinstance(schema, dict):
        return schema
    out = {k: source_view(v) for k, v in schema.items() if k != "additionalProperties"}
    if isinstance(out.get("properties"), dict):
        out["properties"] = {k: v for k, v in out["properties"].items() if k not in PROJECTION_ONLY}
        out["required"] = [k for k in out.get("required", []) if k not in PROJECTION_ONLY]
    return out


def valid(schema, value):
    errors = sorted(Draft202012Validator(schema).iter_errors(value), key=str)
    assert not errors, [e.message for e in errors[:3]]


def body(request):
    return json.loads(request.content) if request.content else {}


def test_a_full_cycle_matches_the_target_schemas(env, tools):
    api, spy = sdk_client(env)
    plan = api.prepare_plan(CAP, "target-1", PAYLOAD, idempotency_key="mcp-target-0001",
                            attachments=[("scan-1.bin", b"\x00\xff\xfe")])
    again = api.prepare_plan(CAP, "target-1", PAYLOAD, idempotency_key="mcp-target-0001",
                             attachments=[("scan-1.bin", b"\x00\xff\xfe")])
    approve(env, {"plan_id": plan.plan_id, "plan_hash": plan.plan_hash})
    done = api.execute_plan(plan.plan_id, plan.plan_hash)
    stored = api.get_plan(plan.plan_id)
    assert done.status == stored.status == "succeeded"
    assert (plan.created, again.created) == (True, False)

    prepares = [r for r in spy.requests if r.method == "POST" and r.url.path == "/v1/operations/plans"]
    assert len(prepares) == 2
    for request, result in zip(prepares, (plan, again)):
        valid(tools["plan_prepare"].input_schema, body(request))
        valid(source_view(tools["plan_prepare"].output_schema), result.raw)

    (execute,) = [r for r in spy.requests if r.url.path.endswith("/execute")]
    valid(tools["plan_execute"].input_schema, {"plan_id": plan.plan_id, **body(execute)})
    valid(source_view(tools["plan_execute"].output_schema),
          {"plan_id": done.plan_id, "status": done.status, "result": done.result})

    valid(tools["plan_get"].input_schema, {"plan_id": plan.plan_id})
    valid(source_view(tools["plan_get"].output_schema), stored.raw)
    # Машинный вид без байтов документа: выходная схема их и не объявляет.
    assert "payload_b64" not in stored.raw and "attachment_contents" not in stored.raw


def test_refusals_and_unknown_outcome_use_declared_codes(env, tools):
    from epgu.integration import Conflict, OutcomeUnknown

    api, _ = sdk_client(env)
    plan = api.prepare_plan(CAP, "target-1", PAYLOAD, idempotency_key="mcp-target-0002")
    with pytest.raises(Conflict) as state:
        api.execute_plan(plan.plan_id, plan.plan_hash)
    with pytest.raises(Conflict) as idem:
        api.prepare_plan(CAP, "target-2", PAYLOAD, idempotency_key="mcp-target-0002")
    approve(env, {"plan_id": plan.plan_id, "plan_hash": plan.plan_hash})
    env.ex.fail_send = RuntimeError("connection reset")
    with pytest.raises(OutcomeUnknown) as unknown:
        api.execute_plan(plan.plan_id, plan.plan_hash)
    assert state.value.code == "plan_state" and state.value.code in tools["plan_execute"].error_codes
    assert idem.value.code == "idempotency_conflict"
    assert idem.value.code in tools["plan_prepare"].error_codes
    assert unknown.value.code == "outcome_unknown" and unknown.value.code in tools["plan_execute"].error_codes
    valid(source_view(tools["plan_get"].output_schema), api.get_plan(plan.plan_id).raw)
