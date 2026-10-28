# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025 yellow444 <yellow444@gmail.com>
"""Безопасный OAuth2 Authorization Code поток ЕСИА для граждан.

Для OAuth-запросов всё равно нужна зарегистрированная информационная система
(``client_id``) и её КЭП. Класс создаёт и одноразово проверяет ``state``, а
``exchange_callback`` дополнительно проверяет адрес возврата и ошибки ЕСИА.
"""

from __future__ import annotations

import base64
import secrets
import threading
import time
from typing import Any, Dict, Optional, Tuple
from urllib.parse import parse_qs, urlencode, urlparse

import httpx

from ..const import USER_AGENT, Env
from ..errors import AuthError
from ..signature.base import Signer
from .token import Token, _token_expires_in


def _timestamp() -> str:
    """Метка времени в формате ЕСИА: ``yyyy.MM.dd HH:mm:ss +0000``."""
    return time.strftime("%Y.%m.%d %H:%M:%S +0000", time.gmtime())


def _optional_int(value: Any, field_name: str) -> Optional[int]:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise AuthError(f"Некорректное поле {field_name!r} в ответе ЕСИА") from exc


class AasClient:
    """Клиент OAuth2-авторизации ЕСИА (поток Authorization Code).

    ``authorization_url`` хранит выданный ``state`` в памяти до однократного
    обмена. Для приложения с несколькими процессами сохраните ``state`` в своей
    серверной сессии и передайте его как ``expected_state`` при обработке
    callback. Не храните ``state`` в cookie без серверной проверки целостности.
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
        state_ttl: float = 600.0,
    ) -> None:
        if not client_id:
            raise AuthError("Не указан client_id информационной системы")
        if not scope:
            raise AuthError("OAuth scope не должен быть пустым")
        redirect = urlparse(redirect_uri)
        if redirect.scheme.lower() not in {"http", "https"} or not redirect.netloc:
            raise AuthError("redirect_uri должен быть абсолютным HTTP(S)-адресом")
        if redirect.scheme.lower() != "https" and redirect.hostname not in {
            "127.0.0.1",
            "::1",
            "localhost",
        }:
            raise AuthError("Для внешнего redirect_uri требуется HTTPS")
        if timeout <= 0:
            raise AuthError("timeout должен быть положительным")
        if state_ttl <= 0:
            raise AuthError("state_ttl должен быть положительным")

        self.client_id = client_id
        self.signer = signer
        self.env = env
        self.redirect_uri = redirect_uri
        self.scope = scope
        self.authorize_path = authorize_path
        self.token_path = token_path
        self._timeout = timeout
        self._state_ttl = state_ttl
        self._client = client
        self._owns_client = client is None
        self._pending_states: Dict[str, Tuple[float, str]] = {}
        self._state_lock = threading.Lock()

    def _http(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=self._timeout, follow_redirects=False)
        return self._client

    def _client_secret(self, scope: str, timestamp: str, state: str) -> str:
        """Вернуть base64url КЭП строки ``scope+timestamp+client_id+state``."""
        message = (scope + timestamp + self.client_id + state).encode("utf-8")
        try:
            raw = self.signer.sign(message)
        except Exception as exc:  # noqa: BLE001 - унифицируем ошибки подписантов
            raise AuthError("Не удалось подписать запрос авторизации") from exc
        return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")

    def _purge_expired_states(self, now: float) -> None:
        expired = [
            state
            for state, (created_at, _) in self._pending_states.items()
            if now - created_at > self._state_ttl
        ]
        for state in expired:
            self._pending_states.pop(state, None)

    def authorization_url(
        self,
        *,
        state: Optional[str] = None,
        scope: Optional[str] = None,
    ) -> Tuple[str, str]:
        """Сформировать ссылку входа и зарегистрировать одноразовый ``state``."""
        selected_scope = scope or self.scope
        selected_state = state if state is not None else secrets.token_urlsafe(32)
        if not selected_state:
            raise AuthError("OAuth state не должен быть пустым")
        timestamp = _timestamp()
        params = {
            "client_id": self.client_id,
            "client_secret": self._client_secret(selected_scope, timestamp, selected_state),
            "redirect_uri": self.redirect_uri,
            "scope": selected_scope,
            "response_type": "code",
            "state": selected_state,
            "timestamp": timestamp,
            "access_type": "offline",
        }

        with self._state_lock:
            now = time.monotonic()
            self._purge_expired_states(now)
            if selected_state in self._pending_states:
                raise AuthError("Такой OAuth state уже ожидает callback")
            self._pending_states[selected_state] = (now, selected_scope)

        url = f"{self.env.esia}{self.authorize_path}?{urlencode(params)}"
        return url, selected_state

    def _consume_state(self, state: str, expected_state: Optional[str]) -> Optional[str]:
        if not state:
            raise AuthError("В callback отсутствует OAuth state")
        if expected_state is not None and not secrets.compare_digest(state, expected_state):
            raise AuthError("OAuth state не совпадает: возможна CSRF-атака")

        with self._state_lock:
            now = time.monotonic()
            self._purge_expired_states(now)
            record = self._pending_states.pop(state, None)

        # expected_state позволяет безопасную работу с внешним серверным
        # хранилищем в многопроцессном приложении.
        if record is None and expected_state is None:
            raise AuthError("OAuth state неизвестен, истёк или уже использован")
        return record[1] if record is not None else None

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
            raise AuthError("Сетевая ошибка при обмене кода на маркер") from exc
        if resp.status_code != 200:
            raise AuthError(
                "ЕСИА вернула HTTP {0} при обмене кода на маркер".format(resp.status_code)
            )
        try:
            data = resp.json()
        except ValueError as exc:
            raise AuthError("ЕСИА вернула не-JSON вместо маркера доступа") from exc
        if not isinstance(data, dict):
            raise AuthError("Ответ маркера ЕСИА должен быть JSON-объектом")
        access = data.get("access_token") or data.get("accessToken")
        if not access:
            raise AuthError("В ответе ЕСИА нет обязательного поля access_token")
        declared_ttl = _optional_int(data.get("expires_in"), "expires_in")
        return Token(
            access_token=str(access),
            expires_in=_token_expires_in(str(access), declared_ttl),
            refresh_token=(
                str(data["refresh_token"]) if data.get("refresh_token") is not None else None
            ),
            raw=data,
        )

    def exchange_code(
        self,
        code: str,
        *,
        state: str,
        expected_state: Optional[str] = None,
        scope: Optional[str] = None,
    ) -> Token:
        """Проверить ``state`` и однократно обменять авторизационный код."""
        if not code:
            raise AuthError("Авторизационный code не должен быть пустым")
        issued_scope = self._consume_state(state, expected_state)
        selected_scope = scope or issued_scope or self.scope
        if issued_scope is not None and selected_scope != issued_scope:
            raise AuthError("OAuth scope отличается от использованного при авторизации")
        timestamp = _timestamp()
        params = {
            "client_id": self.client_id,
            "client_secret": self._client_secret(selected_scope, timestamp, state),
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": self.redirect_uri,
            "scope": selected_scope,
            "state": state,
            "timestamp": timestamp,
            "token_type": "Bearer",
        }
        return self._post_token(params)

    def exchange_callback(
        self,
        callback_url: str,
        *,
        expected_state: Optional[str] = None,
        scope: Optional[str] = None,
    ) -> Token:
        """Проверить полный callback URL и обменять содержащийся в нём код."""
        callback = urlparse(callback_url)
        registered = urlparse(self.redirect_uri)
        callback_target = (callback.scheme.lower(), callback.netloc.lower(), callback.path)
        registered_target = (registered.scheme.lower(), registered.netloc.lower(), registered.path)
        if callback_target != registered_target:
            raise AuthError("Callback получен не на зарегистрированный redirect_uri")

        params = parse_qs(callback.query, keep_blank_values=True)
        oauth_error = params.get("error")
        if oauth_error:
            raise AuthError("ЕСИА отклонила авторизацию")

        def one_value(name: str) -> str:
            values = params.get(name, [])
            if len(values) != 1 or not values[0]:
                raise AuthError(f"Callback должен содержать ровно один непустой {name}")
            return values[0]

        return self.exchange_code(
            one_value("code"),
            state=one_value("state"),
            expected_state=expected_state,
            scope=scope,
        )

    def refresh(
        self,
        refresh_token: str,
        *,
        state: Optional[str] = None,
        scope: Optional[str] = None,
    ) -> Token:
        """Обновить маркер по ``refresh_token``."""
        if not refresh_token:
            raise AuthError("refresh_token не должен быть пустым")
        selected_scope = scope or self.scope
        selected_state = state or secrets.token_urlsafe(32)
        timestamp = _timestamp()
        params = {
            "client_id": self.client_id,
            "client_secret": self._client_secret(selected_scope, timestamp, selected_state),
            "refresh_token": refresh_token,
            "grant_type": "refresh_token",
            "scope": selected_scope,
            "state": selected_state,
            "timestamp": timestamp,
            "token_type": "Bearer",
        }
        return self._post_token(params)

    def close(self) -> None:
        """Закрыть созданный экземпляром HTTP-клиент."""
        if self._owns_client and self._client is not None:
            self._client.close()
            self._client = None

    def __enter__(self) -> "AasClient":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
