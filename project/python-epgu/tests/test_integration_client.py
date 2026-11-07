"""IntegrationClient: транспорт, ошибки и неизвестный исход на mock-транспорте.

Сквозной цикл client -> backend -> mock executor лежит в тестах backend
(``test_integration_client_cycle.py``): здесь backend нет.
"""

import base64
import json
import time

import httpx
import pytest

from epgu import EpguClient
from epgu.integration import (
    Conflict,
    Forbidden,
    IntegrationClient,
    IntegrationConfigError,
    InvalidRequest,
    OutcomeUnknown,
    PlanExpired,
    PlanNotFound,
    ProblemError,
    ServiceUnavailable,
    TransportError,
    Unauthenticated,
    UnexpectedResponse,
)

BASE = "https://backend.test/api"
SECRET = "epgu_ik_" + "S" * 40
PLAN_ID = "plan_" + "a" * 32
HASH = "b" * 64
PROBLEM = "application/problem+json"

PLAN = {
    "plan_id": PLAN_ID, "plan_hash": HASH, "status": "planned",
    "expires_at": "2026-11-02T10:00:00Z", "preview": {"capability_id": "svc.send"},
    "result": None, "error_code": None, "steps": [],
}


def problem(status, code, detail="текст", **extra):
    body = {"type": "https://epgu.local/problems/" + code, "title": "заголовок",
            "status": status, "code": code, "detail": detail, **extra}
    return httpx.Response(status, json=body, headers={"content-type": PROBLEM})


class Recorder:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.requests = []

    def __call__(self, request):
        self.requests.append(request)
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item


def client_with(*responses, **kwargs):
    recorder = Recorder(*responses)
    return IntegrationClient(BASE, SECRET, transport=httpx.MockTransport(recorder),
                             **kwargs), recorder


# ---------- запрос ----------


def test_prepare_sends_the_exact_request_with_bearer_and_no_cookie():
    api, rec = client_with(
        httpx.Response(201, json=PLAN, headers={"set-cookie": "session=human; Path=/"}),
        httpx.Response(200, json=PLAN))
    plan = api.prepare_plan("svc.send", "target-1", b"\x00\xffdata", idempotency_key="idem-0001",
                            attachments=[("a.bin", b"\x01\x02")])
    assert plan.created is True and plan.plan_id == PLAN_ID and plan.plan_hash == HASH
    request = rec.requests[0]
    assert request.method == "POST"
    assert str(request.url) == BASE + "/v1/operations/plans"
    assert request.headers["authorization"] == "Bearer " + SECRET
    assert "cookie" not in request.headers
    assert json.loads(request.content) == {
        "capability_id": "svc.send", "target": "target-1",
        "payload_b64": base64.b64encode(b"\x00\xffdata").decode(),
        "attachments": [{"name": "a.bin", "content_b64": base64.b64encode(b"\x01\x02").decode()}],
        "idempotency_key": "idem-0001",
    }
    # Set-Cookie ответа не превращается в cookie следующего запроса.
    again = api.prepare_plan("svc.send", "target-1", b"\x00\xffdata", idempotency_key="idem-0001",
                             attachments=[("a.bin", b"\x01\x02")])
    assert again.created is False
    assert "cookie" not in rec.requests[1].headers
    assert rec.requests[0].content == rec.requests[1].content


def test_get_and_execute_use_fixed_paths():
    api, rec = client_with(
        httpx.Response(200, json=dict(PLAN, status="approved")),
        httpx.Response(200, json={"plan_id": PLAN_ID, "status": "succeeded", "result": {"n": 1}}))
    assert api.get_plan(PLAN_ID).status == "approved"
    done = api.execute_plan(PLAN_ID, HASH)
    assert done.status == "succeeded" and done.result == {"n": 1}
    assert [(r.method, r.url.path) for r in rec.requests] == [
        ("GET", "/api/v1/operations/plans/" + PLAN_ID),
        ("POST", "/api/v1/operations/plans/%s/execute" % PLAN_ID),
    ]
    assert json.loads(rec.requests[1].content) == {"plan_hash": HASH}
    assert all(SECRET not in str(r.url) for r in rec.requests)


def test_there_is_no_approve_and_the_upstream_client_is_untouched():
    names = {name for name in dir(IntegrationClient) if not name.startswith("_")}
    assert names == {"prepare_plan", "get_plan", "execute_plan", "close"}
    assert not any("approve" in name or "admin" in name for name in dir(IntegrationClient))
    assert not hasattr(EpguClient, "prepare_plan") and not hasattr(EpguClient, "execute_plan")


# ---------- настройка ----------


@pytest.mark.parametrize("url", [
    "http://backend.test/api", "ftp://backend.test", "backend.test/api", "",
    "https://user:pw@backend.test", "https://backend.test/api?x=1", "https://backend.test/#f",
])
def test_base_url_must_be_explicit_https(url):
    with pytest.raises(IntegrationConfigError):
        IntegrationClient(url, SECRET)


def test_http_only_by_explicit_development_flag():
    api = IntegrationClient("http://127.0.0.1:8000", SECRET, allow_insecure_http=True)
    assert api.base_url == "http://127.0.0.1:8000"
    api.close()


@pytest.mark.parametrize("secret", ["", "short", "with space" * 4, SECRET + "\r\nX: y", None])
def test_bad_credential_is_refused_without_echo(secret):
    with pytest.raises(IntegrationConfigError) as err:
        IntegrationClient(BASE, secret)
    assert not secret or secret not in str(err.value)


def test_credential_is_not_in_repr_and_env_is_not_trusted():
    api = IntegrationClient(BASE, SECRET)
    assert SECRET not in repr(api) and SECRET not in str(vars(api).get("base_url"))
    assert api._client.trust_env is False and api._client.follow_redirects is False
    api.close()


@pytest.mark.parametrize("plan_id", ["plan_x", "../admin", "plan_" + "A" * 32, PLAN_ID + "/"])
def test_plan_id_is_checked_before_any_request(plan_id):
    api, rec = client_with()
    with pytest.raises(IntegrationConfigError):
        api.get_plan(plan_id)
    with pytest.raises(IntegrationConfigError):
        api.execute_plan(plan_id, HASH)
    assert rec.requests == []


# ---------- ошибки problem+json ----------


@pytest.mark.parametrize("status,code,kind", [
    (400, "invalid_parameter", InvalidRequest),
    (401, "unauthenticated", Unauthenticated),
    (403, "forbidden", Forbidden),
    (404, "plan_not_found", PlanNotFound),
    (409, "policy_changed", Conflict),
    (410, "plan_expired", PlanExpired),
    (422, "invalid_parameter", InvalidRequest),
    (503, "executor_unavailable", ServiceUnavailable),
])
def test_problem_statuses_are_distinct_types(status, code, kind):
    api, _ = client_with(problem(status, code), problem(status, code))
    with pytest.raises(kind) as err:
        api.get_plan(PLAN_ID)
    assert err.value.status == status and err.value.code == code
    with pytest.raises(kind):
        api.execute_plan(PLAN_ID, HASH)


def test_credential_echoed_by_a_server_is_redacted():
    api, _ = client_with(problem(403, "forbidden", detail="ключ %s не подходит" % SECRET))
    with pytest.raises(Forbidden) as err:
        api.get_plan(PLAN_ID)
    assert SECRET not in str(err.value) and SECRET not in err.value.detail


def test_error_without_problem_json_is_unexpected():
    api, _ = client_with(httpx.Response(403, text="<html>proxy</html>"))
    with pytest.raises(UnexpectedResponse):
        api.get_plan(PLAN_ID)


# ---------- неизвестный исход ----------


def test_unknown_with_outcome_gives_the_server_lists():
    outcome = {"plan_id": PLAN_ID, "completed_calls": ["reserve_number"],
               "uncertain_calls": ["send"]}
    api, rec = client_with(problem(502, "outcome_unknown", outcome=outcome))
    with pytest.raises(OutcomeUnknown) as err:
        api.execute_plan(PLAN_ID, HASH)
    assert err.value.partial_known
    assert err.value.completed_calls == ("reserve_number",)
    assert err.value.uncertain_calls == ("send",)
    assert err.value.plan_id == PLAN_ID and err.value.status == 502
    assert len(rec.requests) == 1


@pytest.mark.parametrize("extra", [
    {},  # старый backend без outcome
    {"outcome": {"plan_id": "plan_" + "c" * 32, "completed_calls": [], "uncertain_calls": []}},
    {"outcome": {"plan_id": PLAN_ID, "completed_calls": "reserve", "uncertain_calls": []}},
])
def test_unknown_without_a_valid_outcome_is_not_empty_lists(extra):
    api, _ = client_with(problem(502, "outcome_unknown",
                                 detail="точно выполнены: reserve_number", **extra))
    with pytest.raises(OutcomeUnknown) as err:
        api.execute_plan(PLAN_ID, HASH)
    # detail не разбирается: частичный результат неизвестен.
    assert err.value.completed_calls is None and err.value.uncertain_calls is None
    assert not err.value.partial_known
    assert err.value.code == "outcome_unknown" and err.value.plan_id == PLAN_ID


@pytest.mark.parametrize("failure", [
    httpx.ReadTimeout("read"), httpx.WriteTimeout("write"), httpx.RemoteProtocolError("eof"),
])
def test_execute_without_an_answer_is_unknown_and_not_repeated(failure):
    api, rec = client_with(failure)
    with pytest.raises(OutcomeUnknown) as err:
        api.execute_plan(PLAN_ID, HASH)
    assert err.value.status is None and err.value.completed_calls is None
    assert len(rec.requests) == 1


@pytest.mark.parametrize("response", [
    httpx.Response(500, text="internal"),
    httpx.Response(504, text="gateway timeout"),
    httpx.Response(503, text="<html>proxy</html>"),
    httpx.Response(200, text="not json"),
    httpx.Response(401, text="proxy auth"),
])
def test_execute_answer_outside_the_contract_is_unknown(response):
    api, rec = client_with(response)
    with pytest.raises(OutcomeUnknown) as err:
        api.execute_plan(PLAN_ID, HASH)
    assert err.value.completed_calls is None and err.value.status == response.status_code
    assert len(rec.requests) == 1


def test_prepare_timeout_is_a_transport_error_without_retry():
    api, rec = client_with(httpx.ReadTimeout("read"))
    with pytest.raises(TransportError) as err:
        api.prepare_plan("svc.send", "t", b"x", idempotency_key="idem-0002")
    assert err.value.may_have_reached_server is True
    assert len(rec.requests) == 1
    assert not isinstance(err.value, ProblemError)


def test_connect_error_did_not_reach_the_server():
    api, _ = client_with(httpx.ConnectError("refused"))
    with pytest.raises(TransportError) as err:
        api.get_plan(PLAN_ID)
    assert err.value.may_have_reached_server is False


# ---------- редиректы ----------


def test_redirect_to_another_origin_is_not_followed():
    moved = httpx.Response(307, headers={"location": "https://evil.test/collect"})
    api, rec = client_with(moved, moved)
    with pytest.raises(UnexpectedResponse) as err:
        api.get_plan(PLAN_ID)
    assert err.value.status == 307
    with pytest.raises(OutcomeUnknown):
        api.execute_plan(PLAN_ID, HASH)
    assert [r.url.host for r in rec.requests] == ["backend.test", "backend.test"]

# ---------- срез 4a, вторая редакция: замечания R11-R14 ----------


OTHER_ID = "plan_" + "2" * 32


@pytest.mark.parametrize("body", [
    {"plan_id": OTHER_ID, "status": "succeeded", "result": {}},
    {"plan_id": PLAN_ID, "status": "unknown", "result": None},
    {"plan_id": PLAN_ID, "status": "failed", "result": None},
    {"plan_id": None, "status": None},
    {"plan_id": PLAN_ID},
    {"plan_id": PLAN_ID, "status": "succeeded", "result": ["not", "an", "object"]},
    {"plan_id": PLAN_ID, "status": "succeeded", "result": "ok"},
])
def test_execute_200_that_does_not_prove_our_success_is_unknown(body):
    api, rec = client_with(httpx.Response(200, json=body))
    with pytest.raises(OutcomeUnknown) as err:
        api.execute_plan(PLAN_ID, HASH)
    assert err.value.plan_id == PLAN_ID and err.value.status == 200
    assert err.value.partial_known is False
    assert len(rec.requests) == 1


def test_execute_200_of_our_plan_is_success():
    api, _ = client_with(httpx.Response(200, json={"plan_id": PLAN_ID, "status": "succeeded",
                                                    "result": None}))
    done = api.execute_plan(PLAN_ID, HASH)
    assert (done.plan_id, done.status, done.result) == (PLAN_ID, "succeeded", None)


@pytest.mark.parametrize("change", [
    {"plan_id": OTHER_ID}, {"plan_id": None}, {"plan_id": "plan_x"},
    {"plan_hash": None}, {"plan_hash": ""}, {"status": "done"}, {"status": None},
    {"expires_at": 5}, {"preview": "text"}, {"result": []}, {"error_code": 7},
    {"steps": "none"}, {"steps": [{"name": "send"}]}, {"steps": [None]},
])
def test_get_plan_outside_the_contract_is_unexpected(change):
    api, _ = client_with(httpx.Response(200, json={**PLAN, **change}))
    with pytest.raises(UnexpectedResponse):
        api.get_plan(PLAN_ID)


def test_prepare_plan_with_a_bad_plan_id_is_unexpected():
    api, _ = client_with(httpx.Response(201, json={**PLAN, "plan_id": "../admin"}))
    with pytest.raises(UnexpectedResponse):
        api.prepare_plan("svc.send", "t", b"x", idempotency_key="idem-0003")


def _no_secret(err):
    seen = [str(err), repr(err), err.code, err.title, err.detail, repr(err.errors),
            repr(getattr(err, "completed_calls", None)),
            repr(getattr(err, "uncertain_calls", None))]
    return all(SECRET not in text for text in seen)


def test_credential_in_code_and_errors_is_not_in_the_error():
    body = problem(409, SECRET, detail="d", errors=[
        {"loc": ["body", SECRET], "msg": "bad " + SECRET, SECRET: SECRET, "n": 1}])
    api, _ = client_with(body)
    with pytest.raises(Conflict) as err:
        api.get_plan(PLAN_ID)
    assert err.value.status == 409 and err.value.code == "unrecognized_code"
    assert _no_secret(err.value)
    assert err.value.errors[0]["loc"] == ["body", "***"] and err.value.errors[0]["n"] == 1


def test_credential_in_502_code_and_outcome_is_not_in_the_error():
    body = problem(502, SECRET, outcome={"plan_id": PLAN_ID, "completed_calls": [SECRET],
                                         "uncertain_calls": ["send-" + SECRET]})
    api, _ = client_with(body)
    with pytest.raises(OutcomeUnknown) as err:
        api.execute_plan(PLAN_ID, HASH)
    assert err.value.code == "unrecognized_code" and err.value.partial_known
    assert err.value.completed_calls == ("***",)
    assert _no_secret(err.value)


@pytest.mark.parametrize("code", ["Plan State", "x" * 65, "1abc", "код"])
def test_code_that_is_not_a_machine_code_is_not_passed_through(code):
    api, _ = client_with(problem(409, code))
    with pytest.raises(Conflict) as err:
        api.get_plan(PLAN_ID)
    assert err.value.code == "unrecognized_code" and err.value.status == 409


# Проверяется только ограничение между раскодированными порциями тела.
# Общего срока у Python-клиента нет: сжатое тело без порций его обходит.
def _slow_body(delay, parts=4):
    def chunks():
        for index in range(parts):
            time.sleep(delay)
            yield b"{}" if index == 0 else b" "
    return httpx.Response(200, content=chunks(), headers={"content-type": "application/json"})


def test_slow_body_of_execute_is_unknown_after_one_post():
    api, rec = client_with(_slow_body(0.05), timeout=0.08)
    started = time.monotonic()
    with pytest.raises(OutcomeUnknown) as err:
        api.execute_plan(PLAN_ID, HASH)
    assert time.monotonic() - started < 1.0
    assert err.value.code == "transport_error" and len(rec.requests) == 1
    assert _no_secret(err.value)


@pytest.mark.parametrize("call", ["get", "prepare"])
def test_slow_body_of_get_and_prepare_is_a_transport_error(call):
    api, rec = client_with(_slow_body(0.05), timeout=0.08)
    with pytest.raises(TransportError) as err:
        if call == "get":
            api.get_plan(PLAN_ID)
        else:
            api.prepare_plan("svc.send", "t", b"x", idempotency_key="idem-0004")
    assert err.value.may_have_reached_server is True and len(rec.requests) == 1
    assert SECRET not in str(err.value)


@pytest.mark.parametrize("url", [
    "http://remote.invalid/api", "http://10.0.0.5:8000", "http://backend:8000",
    "http://localhost.evil.invalid", "http://127.0.0.1.nip.invalid", "http://[2001:db8::1]",
])
def test_development_http_flag_does_not_allow_a_remote_origin(url):
    with pytest.raises(IntegrationConfigError):
        IntegrationClient(url, SECRET, allow_insecure_http=True)


@pytest.mark.parametrize("url", [
    "http://localhost:8000", "http://api.localhost", "http://127.0.0.1", "http://127.1.2.3:9",
    "http://[::1]:8000",
])
def test_development_http_flag_allows_only_loopback(url):
    IntegrationClient(url, SECRET, allow_insecure_http=True).close()
