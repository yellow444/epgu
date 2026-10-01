"""Хранилище учётных записей установки: аккаунты и сессии.

База SQLite лежит на томе (``AUTH_DB_FILE``). Соединение открывается на одну
операцию, запись идёт в транзакции ``BEGIN IMMEDIATE``: так процесс API и
консольная команда рядом не перетирают друг друга.

Приватные дополнения могут хранить в этой же базе свои таблицы: схема здесь
создаётся через ``CREATE TABLE IF NOT EXISTS`` и чужих таблиц не трогает.
"""

from __future__ import annotations

import json
import os
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, Optional

DEFAULT_FILE = "/var/lib/epgu-mail/auth/auth.sqlite3"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS accounts (
    id TEXT PRIMARY KEY,
    login TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    installation_admin INTEGER NOT NULL DEFAULT 0,
    disabled INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    password_changed_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    account_id TEXT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    created_at REAL NOT NULL,
    last_seen_at REAL NOT NULL,
    expires_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
    seq INTEGER PRIMARY KEY AUTOINCREMENT,
    at TEXT NOT NULL,
    account_id TEXT,
    org_id TEXT,
    action TEXT NOT NULL,
    detail_json TEXT NOT NULL DEFAULT '{}'
);
"""


def db_path() -> Path:
    return Path(os.getenv("AUTH_DB_FILE", DEFAULT_FILE))


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def new_id(prefix: str) -> str:
    return "%s_%s" % (prefix, uuid.uuid4().hex)


def _open() -> sqlite3.Connection:
    path = db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    connection = sqlite3.connect(
        str(path), timeout=10, isolation_level=None, check_same_thread=False
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout = 10000")
    return connection


def initialize() -> None:
    """Создать схему учётных записей. Повторный вызов ничего не меняет."""
    connection = _open()
    try:
        connection.executescript(_SCHEMA)
    finally:
        connection.close()
    try:
        db_path().chmod(0o600)
    except OSError:
        pass


_initialized_for: Optional[str] = None


def initialize_once() -> None:
    """Схема создаётся один раз на путь базы: тесты меняют AUTH_DB_FILE."""
    global _initialized_for
    current = str(db_path())
    if _initialized_for != current or not db_path().exists():
        initialize()
        for hook in list(schema_hooks):
            hook()
        _initialized_for = current


# Дополнения добавляют сюда создание своих таблиц в той же базе.
schema_hooks: list = []


@contextmanager
def read() -> Iterator[sqlite3.Connection]:
    initialize_once()
    connection = _open()
    try:
        yield connection
    finally:
        connection.close()


@contextmanager
def write() -> Iterator[sqlite3.Connection]:
    """Транзакция записи: всё или ничего."""
    initialize_once()
    connection = _open()
    try:
        connection.execute("BEGIN IMMEDIATE")
        try:
            yield connection
        except BaseException:
            connection.execute("ROLLBACK")
            raise
        connection.execute("COMMIT")
    finally:
        connection.close()


def audit(
    connection: sqlite3.Connection,
    action: str,
    *,
    account_id: str = "",
    org_id: str = "",
    detail: Optional[Dict[str, Any]] = None,
) -> None:
    """Журнал действий с учётными записями. Пароли сюда не пишутся."""
    connection.execute(
        "INSERT INTO audit (at, account_id, org_id, action, detail_json) VALUES (?, ?, ?, ?, ?)",
        (
            now_iso(),
            account_id or None,
            org_id or None,
            action,
            json.dumps(detail or {}, ensure_ascii=False, sort_keys=True),
        ),
    )
