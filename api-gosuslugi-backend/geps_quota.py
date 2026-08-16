"""Суточные лимиты ГЭПС: свой счётчик обращений.

Спецификация даёт пять заказов списка уведомлений в сутки и пятнадцать
получений готового результата. Лимит считает сервер, и превышение приходит
как 429, но узнавать об этом от него дорого: попытки не возвращаются, а до
конца суток ждать нечего.

Поэтому обращения считаем сами. Счётчик лежит рядом с остальным состоянием,
на томе, и переживает перезапуск контейнера. Сутки считаем по московскому
времени: именно в нём ЕПГУ показывает даты.
"""

from __future__ import annotations

import json
import os
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Optional

from epgu import geps

DEFAULT_FILE = "/var/lib/epgu-mail/geps-quota.json"
MOSCOW = timezone(timedelta(hours=3))

LIMITS = {
    "search": geps.DAILY_SEARCH_LIMIT,
    "result": geps.DAILY_RESULT_LIMIT,
}

_lock = threading.Lock()


def state_path() -> Path:
    return Path(os.getenv("GEPS_QUOTA_FILE", DEFAULT_FILE))


def today(now: Optional[datetime] = None) -> str:
    moment = now or datetime.now(MOSCOW)
    return moment.astimezone(MOSCOW).date().isoformat()


def _load() -> Dict[str, Any]:
    path = state_path()
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        # Битый файл не должен мешать работать: считаем, что счёт с нуля.
        return {}
    return data if isinstance(data, dict) else {}


def _save(data: Dict[str, Any]) -> None:
    path = state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")


def used(kind: str, now: Optional[datetime] = None) -> int:
    with _lock:
        data = _load()
    day = data.get(today(now)) or {}
    try:
        return int(day.get(kind, 0))
    except (TypeError, ValueError):
        return 0


def remaining(kind: str, now: Optional[datetime] = None) -> int:
    return max(0, LIMITS[kind] - used(kind, now))


def take(kind: str, now: Optional[datetime] = None) -> int:
    """Занять одну попытку. Возвращает остаток.

    Вызывается до обращения к ЕПГУ: сетевой сбой тоже расходует попытку на
    стороне сервера, и считать только удачные было бы враньём.
    """
    if kind not in LIMITS:
        raise KeyError(kind)
    day = today(now)
    with _lock:
        data = _load()
        # Держим только сегодняшний день: вчерашние счётчики ничего не решают.
        counters = dict(data.get(day) or {})
        counters[kind] = int(counters.get(kind, 0) or 0) + 1
        _save({day: counters})
        return max(0, LIMITS[kind] - counters[kind])


def exhausted(kind: str, now: Optional[datetime] = None) -> bool:
    return remaining(kind, now) <= 0


def describe(now: Optional[datetime] = None) -> Dict[str, Any]:
    return {
        "date": today(now),
        "limits": {
            kind: {
                "limit": limit,
                "used": used(kind, now),
                "remaining": remaining(kind, now),
            }
            for kind, limit in LIMITS.items()
        },
    }


def clear() -> None:
    with _lock:
        try:
            state_path().unlink()
        except FileNotFoundError:
            pass
