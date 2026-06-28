"""OAuth2-поток ЕСИА (Authorization Code) для граждан.

Используется, когда от имени **человека** нужно получить маркер доступа: гражданин
переходит по ссылке в ЕСИА, подтверждает доступ, ЕСИА возвращает ``code``, который
обменивается на маркер.

Важно: для этого потока всё равно нужна зарегистрированная информационная система
(мнемоника = ``client_id``) и её КЭП - ЕСИА подписывает запросы ГОСТ-подписью.
Поэтому «простой гражданин» использует этот класс через приложение/ИС, которая
действует от его имени с его согласия.
"""

from __future__ import annotations

import base64
import time
import uuid
from typing import Dict, Optional, Tuple
from urllib.parse import urlencode

import httpx

from ..const import USER_AGENT, Env
from ..errors import AuthError
from ..signature.base import Signer
from .token import Token


def _timestamp() -> str:
    """Метка времени в формате ЕСИА: ``yyyy.MM.dd HH:mm:ss +0000``."""
    # ЕСИА требует смещение UTC; используем UTC, чтобы не зависеть от локали.
    return time.strftime("%Y.%m.%d %H:%M:%S +0000", time.gmtime())


class AasClient:
    """Клиент OAuth2-авторизации ЕСИА (поток Authorization Code).

    Args:
        client_id: мнемоника информационной системы (ИС) в ЕСИА.
        signer: подписант КЭП организации/ИС.
        env: контур (TEST/PROD).
        redirect_uri: адрес возврата, зарегистрированный для ИС.
        scope: запрашиваемые права (по умолчанию ``"openid fullname"``).
        authorize_path / token_path: пути эндпоинтов (на случай иной версии API).
    """

    def __init__(
        self,
        client_id: str,
        signer: Signer,
        *,
        env: Env,
        redirect_uri: str,
        scope: str = "openid fullname",
        authorize_path: str = "/aas/oauth2/ac",
        token_path: str = "/aas/oauth2/te",
        client: Optional[httpx.Client] = None,
        timeout: float = 30.0,
    ) -> None:
        self.client_id = client_id
        self.signer = signer
        self.env = env
        self.redirect_uri = redirect_uri
        self.scope = scope
        self.authorize_path = authorize_path
        self.token_path = token_path
        self._timeout = timeout
        self._client = client
        self._owns_client = client is None

    def _http(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=self._timeout)
        return self._client

    def _client_secret(self, scope: str, timestamp: str, state: str) -> str:
        """Подпись запроса: base64url(КЭП(scope + timestamp + clientId + state))."""
        message = (scope + timestamp + self.client_id + state).encode("utf-8")
        try:
            raw = self.signer.sign(message)
        except Exception as exc:  # noqa: BLE001
            raise AuthError(f"Не удалось подписать запрос авторизации: {exc}") from exc
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    def authorization_url(
        self,
        *,
        state: Optional[str] = None,
        scope: Optional[str] = None,
    ) -> Tuple[str, str]:
        """Сформировать ссылку для входа гражданина в ЕСИА.

        Returns:
            Кортеж ``(url, state)``. ``state`` нужно сохранить и сверить при
            возврате (защита от CSRF).
        """
        scope = scope or self.scope
        state = state or str(uuid.uuid4())
        timestamp = _timestamp()
        params = {
            "client_id": self.client_id,
            "client_secret": self._client_secret(scope, timestamp, state),
            "redirect_uri": self.redirect_uri,
            "scope": scope,
            "response_type": "code",
            "state": state,
            "timestamp": timestamp,
            "access_type": "offline",
        }
        url = f"{self.env.esia}{self.authorize_path}?{urlencode(params)}"
        return url, state

    def _post_token(self, params: Dict[str, str]) -> Token:
        url = f"{self.env.esia}{self.token_path}"
        try:
            resp = self._http().post(
                url,
                data=params,
                headers={
                    "User-Agent": USER_AGENT,
                    "Content-Type": "application/x-www-form-urlencoded",
                },
            )
        except httpx.HTTPError as exc:
            raise AuthError(f"Сетевая ошибка при обмене кода на маркер: {exc}") from exc
        if resp.status_code != 200:
            raise AuthError(f"ЕСИА вернула {resp.status_code}: {resp.text}")
        data = resp.json()
        access = data.get("access_token") or data.get("accessToken")
        if not access:
            raise AuthError(f"В ответе ЕСИА нет access_token: {data}")
        return Token(
            access_token=access,
            expires_in=data.get("expires_in"),
            refresh_token=data.get("refresh_token"),
            raw=data,
        )

    def exchange_code(
        self,
        code: str,
        *,
        state: Optional[str] = None,
        scope: Optional[str] = None,
    ) -> Token:
        """Обменять авторизационный ``code`` на маркер доступа."""
        scope = scope or self.scope
        state = state or str(uuid.uuid4())
        timestamp = _timestamp()
        params = {
            "client_id": self.client_id,
            "client_secret": self._client_secret(scope, timestamp, state),
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": self.redirect_uri,
            "scope": scope,
            "state": state,
            "timestamp": timestamp,
            "token_type": "Bearer",
        }
        return self._post_token(params)

    def refresh(
        self,
        refresh_token: str,
        *,
        state: Optional[str] = None,
        scope: Optional[str] = None,
    ) -> Token:
        """Обновить маркер по ``refresh_token``."""
        scope = scope or self.scope
        state = state or str(uuid.uuid4())
        timestamp = _timestamp()
        params = {
            "client_id": self.client_id,
            "client_secret": self._client_secret(scope, timestamp, state),
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
            "scope": scope,
            "state": state,
            "timestamp": timestamp,
            "token_type": "Bearer",
        }
        return self._post_token(params)

    def close(self) -> None:
        if self._owns_client and self._client is not None:
            self._client.close()
            self._client = None
