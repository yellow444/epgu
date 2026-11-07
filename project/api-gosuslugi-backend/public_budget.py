"""Бюджет запросов к открытым без входа методам v1 (в памяти процесса).

Ключ это адрес TCP-соединения. ``X-Forwarded-For`` учитывается только если
соединение пришло с адреса из EPGU_TRUSTED_PROXIES (через запятую); тогда
берётся последний адрес цепочки, добавленный этим прокси. Без настройки все
клиенты за одним прокси делят один бюджет: это сознательно строже, чем
доверять подставляемому заголовку.
"""

from __future__ import annotations

import os
import threading
import time
from collections import OrderedDict
from typing import Callable, Optional, Tuple

from fastapi import Request

TRUSTED_PROXIES_ENV = "EPGU_TRUSTED_PROXIES"
RATE_ENV = "EPGU_PUBLIC_RATE_PER_MINUTE"
DEFAULT_RATE = 120
MAX_KEYS = 10_000


def _trusted() -> frozenset:
    raw = os.getenv(TRUSTED_PROXIES_ENV, "")
    return frozenset(p.strip() for p in raw.split(",") if p.strip())


def client_key(request: Request) -> str:
    peer = request.client.host if request.client else "unknown"
    if peer in _trusted():
        chain = [p.strip() for p in request.headers.get("x-forwarded-for", "").split(",") if p.strip()]
        if chain:
            return chain[-1][:64]
    return peer


def _rate() -> int:
    try:
        value = int(os.getenv(RATE_ENV, DEFAULT_RATE))
    except ValueError:
        value = DEFAULT_RATE
    return max(1, value)


class Budget:
    """Скользящее окно в одну минуту на ключ; число ключей ограничено."""

    def __init__(self, clock: Callable[[], float] = time.monotonic) -> None:
        self._clock = clock
        self._lock = threading.Lock()
        self._hits: "OrderedDict[str, Tuple[float, int]]" = OrderedDict()

    def take(self, key: str) -> Optional[int]:
        """None если запрос разрешён, иначе через сколько секунд повторить."""
        now = self._clock()
        rate = _rate()
        with self._lock:
            start, count = self._hits.pop(key, (now, 0))
            if now - start >= 60:
                start, count = now, 0
            if count >= rate:
                self._hits[key] = (start, count)
                return max(1, int(60 - (now - start)) + 1)
            self._hits[key] = (start, count + 1)
            while len(self._hits) > MAX_KEYS:
                self._hits.popitem(last=False)
        return None

    def reset(self) -> None:
        with self._lock:
            self._hits.clear()


budget = Budget()
