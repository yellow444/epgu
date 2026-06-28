"""Маркер доступа для организаций (информационных систем) - поток ``ext-app``.

Сценарий не требует участия человека: информационная система подписывает свой
API-Key ГОСТ-подписью и обменивает его на маркер доступа ЕСИА. Именно так
работают банки, госорганы и любые зарегистрированные ИС.
"""

from __future__ import annotations

import base64
from typing import Optional

import httpx

from ..const import USER_AGENT, Env
from ..errors import AuthError
from ..signature.base import Signer
from .token import Token


class OrgTokenProvider:
    """Получает и кэширует маркер ``ext-app`` по API-Key + ГОСТ-подписи.

    Args:
        api_key: API-Key организации-потребителя (из техпортала ЕСИА).
        signer: подписант (КЭП организации), см. :mod:`epgu.signature`.
        env: контур (:data:`epgu.const.TEST` или :data:`epgu.const.PROD`).
        client: внешний ``httpx.Client`` (необязательно).

    Example:
        >>> from epgu import TEST
        >>> from epgu.signature import CryptoProSigner
        >>> provider = OrgTokenProvider(api_key, CryptoProSigner(pin="..."), env=TEST)
        >>> token = provider.get_token()
    """

    def __init__(
        self,
        api_key: str,
        signer: Signer,
        *,
        env: Env,
        client: Optional[httpx.Client] = None,
        timeout: float = 30.0,
    ) -> None:
        if not api_key:
            raise AuthError("Не указан API-Key организации")
        self.api_key = api_key
        self.signer = signer
        self.env = env
        self._timeout = timeout
        self._client = client
        self._owns_client = client is None
        self._token: Optional[Token] = None

    def _http(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=self._timeout)
        return self._client

    @staticmethod
    def _url_safe_signature(raw_der: bytes) -> str:
        """ЕСИА ожидает подпись в формате base64url без выравнивающих ``=``."""
        return base64.urlsafe_b64encode(raw_der).decode("ascii").rstrip("=")

    def fetch(self) -> Token:
        """Запросить новый маркер у ЕСИА (без учёта кэша)."""
        try:
            signature = self._url_safe_signature(self.signer.sign(self.api_key.encode("utf-8")))
        except Exception as exc:  # noqa: BLE001
            raise AuthError(f"Не удалось подписать API-Key: {exc}") from exc

        url = (
            f"{self.env.esia}/esia-rs/api/public/v1/orgs/ext-app/"
            f"{self.api_key}/tkn?signature={signature}"
        )
        try:
            resp = self._http().get(url, headers={"User-Agent": USER_AGENT})
        except httpx.HTTPError as exc:
            raise AuthError(f"Сетевая ошибка при получении маркера: {exc}") from exc

        if resp.status_code != 200:
            raise AuthError(
                f"ЕСИА вернула {resp.status_code} при получении маркера: {resp.text}"
            )
        data = resp.json()
        access = data.get("accessTkn")
        if not access:
            raise AuthError(f"В ответе ЕСИА нет accessTkn: {data}")
        self._token = Token(
            access_token=access,
            expires_in=data.get("expiresIn") or data.get("expires_in"),
            raw=data,
        )
        return self._token

    def get_token(self) -> Token:
        """Вернуть кэшированный маркер или запросить новый при истечении."""
        if self._token is None or self._token.is_expired():
            return self.fetch()
        return self._token

    def close(self) -> None:
        if self._owns_client and self._client is not None:
            self._client.close()
            self._client = None
