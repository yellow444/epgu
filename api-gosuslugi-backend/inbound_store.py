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


def max_journal_body_bytes() -> int:
    """Сколько тела попадает в журнал.

    Принять можно мегабайт, но хранить целиком каждое тело незачем: журнал
    ограничен по размеру, и несколько больших запросов вытесняют из него всё
    остальное. В записи всегда остаются настоящий размер и хэш, так что
    обрезка видна и проверяема.
    """
    return int(os.getenv("INBOUND_JOURNAL_BODY_MAX", str(64 * 1024)))


def journal_keep() -> int:
    """Сколько прошлых файлов журнала держим кроме текущего."""
    return max(0, int(os.getenv("INBOUND_JOURNAL_KEEP", "3")))


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
    keep = max_journal_body_bytes()
    stored = body[:keep]
    shortened = len(body) > keep
    try:
        preview = stored.decode("utf-8")
    except UnicodeDecodeError:
        # Обрезали посреди многобайтового символа или тело вообще не текст.
        try:
            preview = stored.decode("utf-8", "ignore") if shortened else None
        except Exception:
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
        "body_stored": len(stored),
        "body_shortened": shortened,
        "body_sha256": hashlib.sha256(body).hexdigest() if body else None,
    }


def _rotate(path: Path) -> None:
    """Сдвинуть журнал: .2 становится .3, .1 становится .2 и так далее.

    Одного запасного файла мало: при потоке мусора две ротации подряд
    затирают всё, что было записано раньше, включая настоящие сообщения.
    """
    keep = journal_keep()
    if keep == 0:
        try:
            path.unlink()
        except FileNotFoundError:
            pass
        return
    oldest = path.with_name(path.name + "." + str(keep))
    try:
        oldest.unlink()
    except FileNotFoundError:
        pass
    for number in range(keep - 1, 0, -1):
        source = path.with_name(path.name + "." + str(number))
        if source.exists():
            source.replace(path.with_name(path.name + "." + str(number + 1)))
    path.replace(path.with_name(path.name + ".1"))


def append(record: Mapping[str, Any]) -> None:
    """Дописать запись. Ошибка записи не должна ронять ответ отправителю."""
    path = journal_path()
    line = json.dumps(record, ensure_ascii=False) + "\n"
    with _write_lock:
        path.parent.mkdir(parents=True, exist_ok=True)
        limit = max_journal_bytes()
        try:
            if path.exists() and path.stat().st_size + len(line.encode("utf-8")) > limit:
                _rotate(path)
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
        candidates = [path]
        candidates += [
            path.with_name(path.name + "." + str(number))
            for number in range(1, journal_keep() + 1)
        ]
        for candidate in candidates:
            try:
                candidate.unlink()
            except FileNotFoundError:
                continue
