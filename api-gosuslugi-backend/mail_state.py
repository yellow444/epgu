"""Свой учёт прочитанного по запросам поддержки.

Опираться на флаг \\Seen в IMAP нельзя: оператор может открыть письмо в
телефоне или в вебе, и запрос молча перестанет быть новым, а движение по нему
мы потеряем. Поэтому прочитанность ведётся здесь и меняется только явным
действием в интерфейсе.

Хранится время последнего письма, которое оператор подтвердил по каждому
запросу. Пришло письмо свежее этой отметки - запрос снова непрочитанный.
"""

from __future__ import annotations

import json
import logging
import os
import threading
from pathlib import Path
from typing import Any, Dict, Iterable, List, Mapping

logger = logging.getLogger(__name__)

DEFAULT_FILE = "/var/lib/epgu-mail/mail-state.json"

_lock = threading.Lock()


def state_path() -> Path:
    return Path(os.getenv("MAIL_STATE_FILE", DEFAULT_FILE))


def load() -> Dict[str, str]:
    path = state_path()
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        logger.info("Файл учёта прочитанного нечитаем, начинаем с чистого")
        return {}
    if not isinstance(data, dict):
        return {}
    return {str(key): str(value) for key, value in data.items() if value}


def _save(values: Mapping[str, str]) -> None:
    path = state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(values, ensure_ascii=False, indent=2), encoding="utf-8")


def mark_read(ticket: str, last_at: str) -> Dict[str, str]:
    """Отметить запрос прочитанным по состоянию на указанное письмо."""
    with _lock:
        values = load()
        previous = values.get(ticket, "")
        if last_at > previous:
            values[ticket] = last_at
            _save(values)
        return values


def mark_many(threads: Iterable[Mapping[str, Any]]) -> int:
    """Отметить прочитанными сразу несколько запросов."""
    with _lock:
        values = load()
        changed = 0
        for thread in threads:
            ticket = str(thread.get("ticket", ""))
            last_at = str(thread.get("last_at", ""))
            if not ticket or not last_at:
                continue
            if last_at > values.get(ticket, ""):
                values[ticket] = last_at
                changed += 1
        if changed:
            _save(values)
        return changed


def forget(ticket: str) -> None:
    """Снять отметку: запрос снова считается непрочитанным."""
    with _lock:
        values = load()
        if values.pop(ticket, None) is not None:
            _save(values)


def clear() -> None:
    with _lock:
        try:
            state_path().unlink()
        except FileNotFoundError:
            pass


def annotate(threads: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Проставить каждому запросу признак непрочитанности."""
    seen = load()
    for thread in threads:
        marker = seen.get(thread["ticket"], "")
        thread["seen_at"] = marker
        thread["unread"] = thread.get("last_at", "") > marker
        # Активным считается всё, что ещё в работе: выполненные и закрытые
        # запросы уходят из поля зрения, но остаются доступными фильтром.
        thread["active"] = thread.get("status_kind") not in {"done"}
    return threads
