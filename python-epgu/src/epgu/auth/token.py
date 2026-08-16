# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025 yellow444 <yellow444@gmail.com>
"""Модель маркера доступа."""

from __future__ import annotations

import base64
import binascii
import json
import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional

_FALLBACK_TOKEN_TTL_SECONDS = 300


def _token_expires_in(access_token: str, declared_ttl: Optional[int]) -> int:
    """Derive a fail-safe local lifetime without trusting JWT for authentication."""

    if declared_ttl is not None:
        return declared_ttl
    try:
        encoded_payload = access_token.split(".")[1]
        padding = "=" * (-len(encoded_payload) % 4)
        payload = json.loads(base64.urlsafe_b64decode(encoded_payload + padding))
        expires_at = float(payload["exp"])
        return max(0, int(expires_at - time.time()))
    except (
        IndexError,
        KeyError,
        TypeError,
        ValueError,
        OverflowError,
        UnicodeDecodeError,
        binascii.Error,
        json.JSONDecodeError,
    ):
        return _FALLBACK_TOKEN_TTL_SECONDS


@dataclass(repr=False)
class Token:
    """Маркер доступа ЕСИА.

    Attributes:
        access_token: сам маркер (передаётся в ``Authorization: Bearer``).
        expires_in: срок жизни в секундах (если известен).
        refresh_token: маркер обновления (для гражданского OAuth-сценария).
        created_at: момент получения (unix-время), для расчёта истечения.
        raw: полный ответ сервера авторизации.
    """

    access_token: str = field(repr=False)
    expires_in: Optional[int] = None
    refresh_token: Optional[str] = field(default=None, repr=False)
    created_at: float = field(default_factory=time.time)
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)

    def __post_init__(self) -> None:
        if not isinstance(self.access_token, str) or not self.access_token:
            raise ValueError("access_token должен быть непустой строкой")
        if self.expires_in is not None and self.expires_in < 0:
            raise ValueError("expires_in должен быть >= 0")

    @property
    def expires_at(self) -> Optional[float]:
        """Unix-время истечения либо ``None`` для маркера без срока жизни."""
        if self.expires_in is None:
            return None
        return self.created_at + self.expires_in

    def is_expired(self, leeway: int = 30) -> bool:
        """True, если маркер истёк (с запасом ``leeway`` секунд)."""
        if leeway < 0:
            raise ValueError("leeway должен быть >= 0")
        exp = self.expires_at
        if exp is None:
            return False
        return time.time() >= (exp - leeway)

    def __repr__(self) -> str:
        """Return diagnostic metadata without exposing bearer credentials."""
        return (
            "Token(access_token=<redacted>, expires_in={!r}, "
            "refresh_token={}, created_at={!r}, raw=<redacted>)"
        ).format(
            self.expires_in,
            "<redacted>" if self.refresh_token else "None",
            self.created_at,
        )

    def __str__(self) -> str:
        """Never render a bearer token implicitly; use ``access_token`` explicitly."""
        return "<redacted-token>"
