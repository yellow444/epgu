import base64

import httpx

from epgu.auth import OrgTokenProvider
from epgu.const import TEST
from epgu.signature import CallableSigner


def test_org_token_provider_signs_and_fetches():
    captured = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["url"] = str(request.url)
        return httpx.Response(200, json={"accessTkn": "TKN-123", "expiresIn": 3600})

    client = httpx.Client(transport=httpx.MockTransport(handler))
    # подпись = просто эхо API-Key, чтобы проверить кодирование
    signer = CallableSigner(lambda data: data)
    provider = OrgTokenProvider("API_KEY_42", signer, env=TEST, client=client)

    token = provider.get_token()
    assert token.access_token == "TKN-123"
    assert token.expires_in == 3600

    # подпись должна быть base64url(API_KEY) без '='
    expected_sig = base64.urlsafe_b64encode(b"API_KEY_42").decode().rstrip("=")
    assert f"signature={expected_sig}" in captured["url"]
    assert "ext-app/API_KEY_42/tkn" in captured["url"]

    # повторный вызов не должен ходить в сеть (кэш)
    captured["url"] = None
    again = provider.get_token()
    assert again.access_token == "TKN-123"
    assert captured["url"] is None


def test_org_token_provider_raises_on_error():
    import pytest

    from epgu.errors import AuthError

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, text="forbidden")

    client = httpx.Client(transport=httpx.MockTransport(handler))
    provider = OrgTokenProvider("k", CallableSigner(lambda d: d), env=TEST, client=client)
    with pytest.raises(AuthError):
        provider.get_token()
