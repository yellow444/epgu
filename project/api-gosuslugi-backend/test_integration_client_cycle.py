"""Сквозной цикл: IntegrationClient -> настоящее app.app -> тестовый исполнитель.

Клиент SDK ходит в backend через транспорт TestClient, без сети. Одобряет
человек по своей сессии (``env.admin``), не клиент. Реальных адресов,
сертификатов и runtime нет.
"""

import sys
from pathlib import Path

import httpx
import pytest
from fastapi.testclient import TestClient

from test_operations import (  # noqa: F401  (fixtures)
    CAP,
    PAYLOAD,
    SCOPES,
    approve,
    bearer,
    client,
    env,
    issue,
    mock_executor,
    row_of,
    store,
)

_SDK = Path(__file__).resolve().parents[1] / "python-epgu" / "src"
if str(_SDK) not in sys.path:
    sys.path.insert(0, str(_SDK))

from epgu.integration import (  # noqa: E402
    Conflict,
    Forbidden,
    IntegrationClient,
    OutcomeUnknown,
)

pytestmark = pytest.mark.real_auth


class Spy(httpx.BaseTransport):
    """Записывает запросы клиента и передаёт их приложению."""

    def __init__(self, inner):
        self.inner = inner
        self.requests = []

    def handle_request(self, request):
        self.requests.append(request)
        response = self.inner.handle_request(request)
        # Транспорт TestClient отдаёт поток не того вида для httpx.Client: копируем тело.
        return httpx.Response(response.status_code, headers=response.headers,
                              content=response.read())


def sdk_client(env, secret=None):
    import app as application

    spy = Spy(TestClient(application.app, base_url="https://testserver")._transport)
    api = IntegrationClient("https://testserver", secret or env.key["secret"], transport=spy)
    return api, spy


def test_prepare_human_approve_execute_through_the_sdk(env):
    api, spy = sdk_client(env)
    plan = api.prepare_plan(CAP, "target-1", PAYLOAD, idempotency_key="sdk-cycle-0001")
    assert plan.created is True and plan.status == "planned"
    assert env.ex.calls() == (0, 0)
    # Одобряет человек по сессии; у клиента SDK такого метода нет.
    assert env.admin.cookies and approve(env, {"plan_id": plan.plan_id,
                                               "plan_hash": plan.plan_hash}).status_code == 200
    done = api.execute_plan(plan.plan_id, plan.plan_hash)
    assert done.status == "succeeded" and done.result["number"] == "N-1"
    assert env.ex.calls() == (1, 1)
    stored = api.get_plan(plan.plan_id)
    assert stored.status == "succeeded"
    assert [(s["name"], s["state"], s["reference"]) for s in stored.steps] == [
        ("reserve_number", "completed", "N-1"), ("send", "completed", "msg-1")]
    for request in spy.requests:
        assert request.headers["authorization"] == "Bearer " + env.key["secret"]
        assert "cookie" not in request.headers
        assert env.key["secret"] not in str(request.url)


def test_prepare_repeat_with_the_same_key_is_the_same_plan(env):
    api, _ = sdk_client(env)
    first = api.prepare_plan(CAP, "target-1", PAYLOAD, idempotency_key="sdk-cycle-0002")
    again = api.prepare_plan(CAP, "target-1", PAYLOAD, idempotency_key="sdk-cycle-0002")
    assert (first.created, again.created) == (True, False)
    assert again.plan_id == first.plan_id and again.plan_hash == first.plan_hash
    with pytest.raises(Conflict) as err:
        api.prepare_plan(CAP, "target-2", PAYLOAD, idempotency_key="sdk-cycle-0002")
    assert err.value.code == "idempotency_conflict"


def test_unknown_outcome_reaches_the_caller_with_the_journal(env):
    api, spy = sdk_client(env)
    plan = api.prepare_plan(CAP, "target-1", PAYLOAD, idempotency_key="sdk-cycle-0003")
    approve(env, {"plan_id": plan.plan_id, "plan_hash": plan.plan_hash})
    env.ex.fail_send = RuntimeError("connection reset")
    with pytest.raises(OutcomeUnknown) as err:
        api.execute_plan(plan.plan_id, plan.plan_hash)
    assert err.value.status == 502 and err.value.partial_known
    assert err.value.completed_calls == ("reserve_number",)
    assert err.value.uncertain_calls == ("send",)
    sent = len(spy.requests)
    # Клиент сам не повторяет; повтор вызывающим получает отказ, send не повторён.
    with pytest.raises(Conflict) as again:
        api.execute_plan(plan.plan_id, plan.plan_hash)
    assert again.value.code == "plan_state"
    assert len(spy.requests) == sent + 1 and env.ex.calls() == (1, 1)
    stored = api.get_plan(plan.plan_id)
    assert stored.status == "unknown"
    assert stored.result == {"completed_calls": ["reserve_number"], "uncertain_calls": ["send"]}
    steps = {s["name"]: s for s in stored.steps}
    assert steps["reserve_number"]["reference"] == "N-1"
    assert steps["send"]["state"] == "started"
    assert row_of(plan.plan_id)["status"] == "unknown"


def test_refusals_before_execution_are_typed_and_call_nothing(env):
    api, _ = sdk_client(env)
    plan = api.prepare_plan(CAP, "target-1", PAYLOAD, idempotency_key="sdk-cycle-0004")
    with pytest.raises(Conflict) as err:
        api.execute_plan(plan.plan_id, plan.plan_hash)
    assert err.value.code == "plan_state"
    approve(env, {"plan_id": plan.plan_id, "plan_hash": plan.plan_hash})
    prepare_only = issue(scopes=("external:prepare",))
    limited, _ = sdk_client(env, prepare_only["secret"])
    with pytest.raises(Forbidden):
        limited.execute_plan(plan.plan_id, plan.plan_hash)
    assert env.ex.calls() == (0, 0)
    assert row_of(plan.plan_id)["status"] == "approved"
