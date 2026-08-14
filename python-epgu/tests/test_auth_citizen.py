import base64
import json
import time
from urllib.parse import parse_qs, urlparse

import httpx
import pytest

from epgu.auth import AasClient
from epgu.const import TEST
from epgu.errors import AuthError
from epgu.signature import CallableSigner


def make_aas(handler, **kwargs):
    client = httpx.Client(transport=httpx.MockTransport(handler))
    return AasClient(
        "MY_SYSTEM",
        CallableSigner(lambda data: b"signature"),
        env=TEST,
        redirect_uri="https://app.example/esia/callback",
        client=client,
        **kwargs,
    )


def token_response(request: httpx.Request) -> httpx.Response:
    return httpx.Response(
        200,
        json={"access_token": "ACCESS", "expires_in": "3600", "refresh_token": "REFRESH"},
    )


def jwt(payload):
    encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return "header.{0}.signature".format(encoded)


def test_authorization_url_generates_high_entropy_state_and_required_params():
    aas = make_aas(token_response)
    url, state = aas.authorization_url()
    params = parse_qs(urlparse(url).query)

    assert len(state) >= 32
    assert params["state"] == [state]
    assert params["client_id"] == ["MY_SYSTEM"]
    assert params["redirect_uri"] == ["https://app.example/esia/callback"]
    assert params["response_type"] == ["code"]
    assert params["access_type"] == ["offline"]
    assert params["client_secret"][0]


def test_exchange_callback_validates_state_and_consumes_it_once():
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(parse_qs(request.content.decode()))
        return token_response(request)

    aas = make_aas(handler)
    _, state = aas.authorization_url(scope="openid fullname email")
    callback = f"https://app.example/esia/callback?code=CODE&state={state}"

    token = aas.exchange_callback(callback)

    assert token.access_token == "ACCESS"
    assert token.expires_in == 3600
    assert token.refresh_token == "REFRESH"
    assert requests[0]["state"] == [state]
    assert requests[0]["scope"] == ["openid fullname email"]
    with pytest.raises(AuthError, match="неизвестен|использован"):
        aas.exchange_callback(callback)


def test_exchange_code_supports_external_server_side_state_store():
    aas = make_aas(token_response)
    token = aas.exchange_code(
        "CODE",
        state="callback-state",
        expected_state="callback-state",
    )
    assert token.access_token == "ACCESS"


@pytest.mark.parametrize(
    ("callback", "message"),
    [
        (
            "https://evil.example/esia/callback?code=CODE&state=STATE",
            "redirect_uri",
        ),
        (
            "https://app.example/esia/callback?error=access_denied&error_description=No",
            "отклонила",
        ),
        (
            "https://app.example/esia/callback?code=A&code=B&state=STATE",
            "ровно один",
        ),
        (
            "https://app.example/esia/callback?code=CODE",
            "state",
        ),
    ],
)
def test_exchange_callback_rejects_unsafe_or_invalid_callbacks(callback, message):
    aas = make_aas(token_response)
    with pytest.raises(AuthError, match=message):
        aas.exchange_callback(callback, expected_state="STATE")


def test_exchange_callback_rejects_state_mismatch_before_network():
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return token_response(request)

    aas = make_aas(handler)
    with pytest.raises(AuthError, match="CSRF"):
        aas.exchange_callback(
            "https://app.example/esia/callback?code=CODE&state=attacker",
            expected_state="expected",
        )
    assert called is False


def test_expired_state_is_rejected(monkeypatch):
    now = 100.0
    monkeypatch.setattr("epgu.auth.citizen.time.monotonic", lambda: now)
    aas = make_aas(token_response, state_ttl=10)
    _, state = aas.authorization_url()
    now = 111.0
    with pytest.raises(AuthError, match="истёк"):
        aas.exchange_code("CODE", state=state)


def test_refresh_uses_refresh_grant_and_validates_input():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured.update(parse_qs(request.content.decode()))
        return token_response(request)

    aas = make_aas(handler)
    assert aas.refresh("REFRESH").access_token == "ACCESS"
    assert captured["grant_type"] == ["refresh_token"]
    assert captured["refresh_token"] == ["REFRESH"]
    with pytest.raises(AuthError, match="refresh_token"):
        aas.refresh("")


def test_citizen_jwt_exp_bounds_lifetime_when_expires_in_is_absent():
    aas = make_aas(
        lambda request: httpx.Response(
            200,
            json={"access_token": jwt({"exp": time.time() - 1})},
        )
    )
    token = aas.refresh("REFRESH")
    assert token.expires_in == 0
    assert token.is_expired(leeway=0)


def test_citizen_opaque_token_gets_fail_safe_lifetime():
    aas = make_aas(lambda request: httpx.Response(200, json={"access_token": "opaque"}))
    assert aas.refresh("REFRESH").expires_in == 300


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(500, text="failure"),
        httpx.Response(200, text="not-json"),
        httpx.Response(200, json=[]),
        httpx.Response(200, json={}),
        httpx.Response(200, json={"access_token": "x", "expires_in": "bad"}),
    ],
)
def test_token_endpoint_contract_errors_are_wrapped(response):
    aas = make_aas(lambda request: response)
    with pytest.raises(AuthError):
        aas.refresh("REFRESH")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"client_id": "", "redirect_uri": "https://app.example/callback"},
        {"client_id": "id", "redirect_uri": "relative/callback"},
        {"client_id": "id", "redirect_uri": "http://external.example/callback"},
    ],
)
def test_aas_configuration_rejects_insecure_values(kwargs):
    with pytest.raises(AuthError):
        AasClient(
            kwargs["client_id"],
            CallableSigner(lambda data: data),
            env=TEST,
            redirect_uri=kwargs["redirect_uri"],
        )


@pytest.mark.parametrize(
    "extra",
    [
        {"scope": ""},
        {"timeout": 0},
        {"state_ttl": 0},
    ],
)
def test_aas_configuration_rejects_empty_scope_and_nonpositive_limits(extra):
    with pytest.raises(AuthError):
        AasClient(
            "id",
            CallableSigner(lambda data: data),
            env=TEST,
            redirect_uri="https://app.example/callback",
            **extra,
        )


def test_authorization_state_and_signer_validation():
    aas = make_aas(token_response)
    with pytest.raises(AuthError, match="state"):
        aas.authorization_url(state="")

    _, state = aas.authorization_url(state="fixed-state")
    assert state == "fixed-state"
    with pytest.raises(AuthError, match="уже"):
        aas.authorization_url(state="fixed-state")

    def fail(data):
        raise RuntimeError("HSM offline")

    broken = AasClient(
        "id",
        CallableSigner(fail),
        env=TEST,
        redirect_uri="https://app.example/callback",
    )
    with pytest.raises(AuthError, match="подписать"):
        broken.authorization_url()


def test_exchange_code_validates_code_state_and_original_scope():
    aas = make_aas(token_response)
    with pytest.raises(AuthError, match="code"):
        aas.exchange_code("", state="state", expected_state="state")
    with pytest.raises(AuthError, match="state"):
        aas.exchange_code("CODE", state="", expected_state="")

    _, state = aas.authorization_url(scope="openid email")
    with pytest.raises(AuthError, match="scope"):
        aas.exchange_code("CODE", state=state, scope="openid fullname")


def test_aas_wraps_transport_error_and_closes_owned_client():
    def fail(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("offline", request=request)

    aas = make_aas(fail)
    with pytest.raises(AuthError, match="Сетевая"):
        aas.refresh("REFRESH")

    owned = AasClient(
        "id",
        CallableSigner(lambda data: data),
        env=TEST,
        redirect_uri="https://app.example/callback",
    )
    http = owned._http()
    with owned as same:
        assert same is owned
    assert http.is_closed
    assert owned._client is None


def test_aas_errors_never_expose_signer_network_or_response_secrets():
    sentinel = "SENTINEL-OAUTH-SECRET"

    def signer_failure(data):
        raise RuntimeError(sentinel)

    broken_signer = AasClient(
        "id",
        CallableSigner(signer_failure),
        env=TEST,
        redirect_uri="https://app.example/callback",
    )
    with pytest.raises(AuthError) as signer_error:
        broken_signer.authorization_url()
    assert sentinel not in str(signer_error.value)

    def network_failure(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError(sentinel, request=request)

    with pytest.raises(AuthError) as network_error:
        make_aas(network_failure).refresh("REFRESH")
    assert sentinel not in str(network_error.value)

    with pytest.raises(AuthError) as response_error:
        make_aas(lambda request: httpx.Response(502, text=sentinel)).refresh("REFRESH")
    assert sentinel not in str(response_error.value)

    callback = "https://app.example/esia/callback?error=access_denied&error_description=" + sentinel
    with pytest.raises(AuthError) as callback_error:
        make_aas(token_response).exchange_callback(callback, expected_state="state")
    assert sentinel not in str(callback_error.value)
