import time

import pytest

from epgu import Env, EpguClient
from epgu.auth import StaticToken, Token
from epgu.errors import AuthError, HttpError


def test_token_expiration_and_validation():
    token = Token(access_token="token", expires_in=60, created_at=time.time() - 120)
    assert token.expires_at is not None
    assert token.is_expired() is True
    assert str(token) == "<redacted-token>"
    assert "access_token='token'" not in repr(token)

    secret = Token(
        access_token="ACCESS-SENTINEL",
        refresh_token="REFRESH-SENTINEL",
        raw={"nested": "RAW-SENTINEL"},
    )
    rendered = repr(secret) + str(secret)
    assert "ACCESS-SENTINEL" not in rendered
    assert "REFRESH-SENTINEL" not in rendered
    assert "RAW-SENTINEL" not in rendered

    timeless = Token(access_token="token")
    assert timeless.expires_at is None
    assert timeless.is_expired() is False
    with pytest.raises(ValueError, match="leeway"):
        timeless.is_expired(-1)
    with pytest.raises(ValueError, match="access_token"):
        Token(access_token="")
    with pytest.raises(ValueError, match="expires_in"):
        Token(access_token="x", expires_in=-1)


def test_static_token_and_client_reject_empty_token():
    assert StaticToken("token").get_token().access_token == "token"
    with pytest.raises(AuthError):
        EpguClient("", env=Env("https://esia.example/", "https://epgu.example/"))


def test_env_strips_trailing_slashes():
    env = Env("https://esia.example///", "https://epgu.example/")
    assert env.esia == "https://esia.example"
    assert env.epgu == "https://epgu.example"


def test_http_error_string_contains_status():
    error = HttpError("boom", status_code=500)
    assert str(error) == "[500] boom"
