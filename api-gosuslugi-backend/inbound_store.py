"""Журнал входящих запросов от ЕПГУ и ЕСИА.

Публичный приёмник (``inbound.py``) пишет сюда, операторский API отдаёт
записи в UI. Обмен идёт через файл в общем томе, поэтому приёмник и
операторский API остаются разными процессами: публичный порт не должен
иметь доступа ни к сертификатам, ни к маркеру доступа.

Формат хранения: JSONL, одна запись на строку. Файл ограничен по размеру и
ротируется, чтобы журнал не съел диск на длинном тесте.
"""

from __future__ import annotations

import hashlib
import json
import os
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Mapping, Optional

DEFAULT_JOURNAL = "/var/lib/epgu-inbound/messages.jsonl"

# Заголовки, значения которых в журнал не попадают: там могут быть маркеры
# доступа и подписи. Факт наличия заголовка сохраняем, значение - нет.
SENSITIVE_HEADERS = {
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "api-key",
    "apikey",
    "x-auth-token",
}

_write_lock = threading.Lock()


def journal_path() -> Path:
    return Path(os.getenv("INBOUND_JOURNAL", DEFAULT_JOURNAL))


def max_journal_bytes() -> int:
    return int(os.getenv("INBOUND_JOURNAL_MAX_BYTES", str(32 * 1024 * 1024)))


def max_body_bytes() -> int:
    return int(os.getenv("INBOUND_MAX_BODY", str(1024 * 1024)))


def redact_headers(headers: Mapping[str, str]) -> Dict[str, str]:
    result: Dict[str, str] = {}
    for name, value in headers.items():
        lowered = name.lower()
        if lowered in SENSITIVE_HEADERS:
            result[name] = "скрыто, длина {0}".format(len(value))
        else:
            result[name] = value
    return result


def build_record(
    *,
    method: str,
    path: str,
    query: str,
    client: Optional[str],
    headers: Mapping[str, str],
    body: bytes,
    truncated: bool,
    mnemonic: str,
) -> Dict[str, Any]:
    """Собрать запись журнала. Тело не разбирается, только сохраняется."""
    preview: Optional[str]
    try:
        preview = body.decode("utf-8")
    except UnicodeDecodeError:
        preview = None
    return {
        "id": str(uuid.uuid4()),
        "received_at": datetime.now(timezone.utc).isoformat(timespec="milliseconds"),
        "mnemonic": mnemonic,
        "method": method,
        "path": path,
        "query": query,
        "client": client,
        "headers": redact_headers(headers),
        "content_type": headers.get("content-type", ""),
        "size": len(body),
        "truncated": truncated,
        "body_text": preview,
        "body_sha256": hashlib.sha256(body).hexdigest() if body else None,
    }


def append(record: Mapping[str, Any]) -> None:
    """Дописать запись. Ошибка записи не должна ронять ответ отправителю."""
    path = journal_path()
    line = json.dumps(record, ensure_ascii=False) + "\n"
    with _write_lock:
        path.parent.mkdir(parents=True, exist_ok=True)
        limit = max_journal_bytes()
        try:
            if path.exists() and path.stat().st_size + len(line.encode("utf-8")) > limit:
                path.replace(path.with_suffix(path.suffix + ".1"))
        except OSError:
            pass
        with path.open("a", encoding="utf-8") as handle:
            handle.write(line)


def read_last(limit: int = 100) -> List[Dict[str, Any]]:
    """Последние записи, свежие сверху. Битые строки пропускаются."""
    path = journal_path()
    if not path.exists():
        return []
    try:
        with path.open("r", encoding="utf-8") as handle:
            lines = handle.readlines()
    except OSError:
        return []
    records: List[Dict[str, Any]] = []
    for line in reversed(lines):
        line = line.strip()
        if not line:
            continue
        try:
            records.append(json.loads(line))
        except json.JSONDecodeError:
            continue
        if len(records) >= limit:
            break
    return records


def count() -> int:
    path = journal_path()
    if not path.exists():
        return 0
    try:
        with path.open("r", encoding="utf-8") as handle:
            return sum(1 for line in handle if line.strip())
    except OSError:
        return 0


def clear() -> None:
    """Удалить журнал. Ошибку доступа наверх не глушим: оператор должен
    увидеть, что очистка не прошла, а не считать журнал пустым."""
    path = journal_path()
    with _write_lock:
        for candidate in (path, path.with_suffix(path.suffix + ".1")):
            try:
                candidate.unlink()
            except FileNotFoundError:
                continue
