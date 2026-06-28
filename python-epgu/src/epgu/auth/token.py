"""Модель маркера доступа."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, Optional


@dataclass
class Token:
    """Маркер доступа ЕСИА.

    Attributes:
        access_token: сам маркер (передаётся в ``Authorization: Bearer``).
        expires_in: срок жизни в секундах (если известен).
        refresh_token: маркер обновления (для гражданского OAuth-сценария).
        created_at: момент получения (unix-время), для расчёта истечения.
        raw: полный ответ сервера авторизации.
    """

    access_token: str
    expires_in: Optional[int] = None
    refresh_token: Optional[str] = None
    created_at: float = field(default_factory=time.time)
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def expires_at(self) -> Optional[float]:
        if self.expires_in is None:
            return None
        return self.created_at + self.expires_in

    def is_expired(self, leeway: int = 30) -> bool:
        """True, если маркер истёк (с запасом ``leeway`` секунд)."""
        exp = self.expires_at
        if exp is None:
            return False
        return time.time() >= (exp - leeway)

    def __str__(self) -> str:  # pragma: no cover
        return self.access_token
