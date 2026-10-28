import base64
import json
import time

import httpx
import pytest

from epgu.auth import OrgTokenProvider
from epgu.const import TEST
from epgu.errors import AuthError
from epgu.signature import CallableSigner


def _jwt(payload):
    encoded = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    return f"e30.{encoded}.signature"


def test_org_token_provider_signs_encodes_path_and_caches():
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return httpx.Response(200, json={"accessTkn": "TKN-123", "expiresIn": "3600"})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    provider = OrgTokenProvider(
        "API/KEY 42",
        CallableSigner(lambda data: data),
        env=TEST,
        client=client,
    )

    token = provider.get_token()
    assert token.access_token == "TKN-123"
    assert token.expires_in == 3600
    expected_sig = base64.urlsafe_b64encode(b"API/KEY 42").decode().rstrip("=")
    assert requests[0].url.params["signature"] == expected_sig
    assert b"ext-app/API%2FKEY%2042/tkn" in requests[0].url.raw_path

    assert provider.get_token() is token
    assert len(requests) == 1


def test_expired_org_token_is_refetched():
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"accessTkn": f"TKN-{calls}", "expiresIn": 1})

    provider = OrgTokenProvider(
        "KEY",
        CallableSigner(lambda data: data),
        env=TEST,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    first = provider.get_token()
    first.created_at = time.time() - 100
    assert provider.get_token().access_token == "TKN-2"


def test_jwt_exp_bounds_cache_when_esia_omits_expires_in():
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(200, json={"accessTkn": _jwt({"exp": time.time() - 1})})

    provider = OrgTokenProvider(
        "KEY",
        CallableSigner(lambda data: data),
        env=TEST,
        client=httpx.Client(transport=httpx.MockTransport(handler)),
    )
    provider.get_token()
    provider.get_token()
    assert calls == 2


def test_opaque_token_without_exp_uses_short_fail_safe_ttl():
    provider = OrgTokenProvider(
        "KEY",
        CallableSigner(lambda data: data),
        env=TEST,
        client=httpx.Client(
            transport=httpx.MockTransport(
                lambda request: httpx.Response(200, json={"accessTkn": "opaque"})
            )
        ),
    )
    assert provider.get_token().expires_in == 300


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(403, text="forbidden"),
        httpx.Response(200, text="not-json"),
        httpx.Response(200, json=[]),
        httpx.Response(200, json={}),
        httpx.Response(200, json={"accessTkn": "x", "expiresIn": "bad"}),
    ],
)
def test_org_token_provider_wraps_contract_errors(response):
    provider = OrgTokenProvider(
        "KEY",
        CallableSigner(lambda data: data),
        env=TEST,
        client=httpx.Client(transport=httpx.MockTransport(lambda request: response)),
    )
    with pytest.raises(AuthError):
        provider.get_token()


def test_org_token_provider_wraps_signer_error():
    def fail(data):
        raise RuntimeError("HSM offline")

    provider = OrgTokenProvider("KEY", CallableSigner(fail), env=TEST)
    with pytest.raises(AuthError, match="подписать"):
        provider.get_token()


def test_org_token_provider_requires_api_key():
    with pytest.raises(AuthError, match="API-Key"):
        OrgTokenProvider("", CallableSigner(lambda data: data), env=TEST)


def test_org_provider_wraps_transport_error_and_closes_owned_client():
    def fail(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("offline", request=request)

    transport_client = httpx.Client(transport=httpx.MockTransport(fail))
    provider = OrgTokenProvider(
        "KEY",
        CallableSigner(lambda data: data),
        env=TEST,
        client=transport_client,
    )
    with pytest.raises(AuthError, match="Сетевая"):
        provider.get_token()

    owned = OrgTokenProvider("KEY", CallableSigner(lambda data: data), env=TEST)
    http = owned._http()
    with owned as same:
        assert same is owned
    assert http.is_closed
    assert owned._client is None


def test_org_errors_never_expose_key_signature_or_response_body():
    key = "API-KEY-SENTINEL"
    signature = b"SIGNATURE-SENTINEL"
    reflected = "RESPONSE-BODY-SENTINEL"

    provider = OrgTokenProvider(
        key,
        CallableSigner(lambda data: signature),
        env=TEST,
        client=httpx.Client(
            transport=httpx.MockTransport(lambda request: httpx.Response(403, text=reflected))
        ),
    )
    with pytest.raises(AuthError) as caught:
        provider.get_token()
    message = str(caught.value)
    assert key not in message
    assert "SIGNATURE-SENTINEL" not in message
    assert reflected not in message
