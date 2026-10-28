"""Вход в установку: пароли, аккаунты, сессии.

Это собственная учётная запись установки, не ЕСИА и не OAuth. Первый
администратор создаётся локальной командой ``python auth_cli.py create-admin``:
встроенных паролей нет, HTTP-метода для создания первого администратора
тоже нет. Остальных пользователей заводит администратор.

Сервер узнаёт пользователя только по сессии, выданной после проверки пароля.
Токен сессии живёт в HttpOnly cookie, в базе хранится только его хеш.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import os
import re
import secrets
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import auth_store

SESSION_COOKIE = "epgu_session"
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 1024

# Параметры scrypt: стандартная библиотека, соль на каждый пароль.
SCRYPT_N = 2 ** 14
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_LEN = 32

_LOGIN_RE = r"[A-Za-z0-9][A-Za-z0-9._@-]{2,63}"


class AuthError(RuntimeError):
    """Ошибка входа или учётной записи. Текст безопасно показывать пользователю."""


class AccessDenied(RuntimeError):
    """Нет сессии или нет права. Наружу отдаётся без подробностей."""


@dataclass(frozen=True)
class Account:
    id: str
    login: str
    display_name: str
    installation_admin: bool

    def public(self) -> Dict[str, Any]:
        return {
            "id": self.id,
            "login": self.login,
            "display_name": self.display_name,
            "installation_admin": self.installation_admin,
        }


# ---------- пароли ----------


def check_password_policy(password: str) -> None:
    if not isinstance(password, str) or len(password) < MIN_PASSWORD_LENGTH:
        raise AuthError("Пароль короче %d символов" % MIN_PASSWORD_LENGTH)
    if len(password) > MAX_PASSWORD_LENGTH:
        raise AuthError("Пароль слишком длинный")


def hash_password(password: str) -> str:
    check_password_policy(password)
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode("utf-8"), salt=salt, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P, dklen=SCRYPT_LEN
    )
    return "scrypt$%d$%d$%d$%s$%s" % (
        SCRYPT_N,
        SCRYPT_R,
        SCRYPT_P,
        base64.b64encode(salt).decode("ascii"),
        base64.b64encode(digest).decode("ascii"),
    )


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt_b64, digest_b64 = stored.split("$")
        if scheme != "scrypt":
            return False
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(digest_b64)
        if not isinstance(password, str) or len(password) > MAX_PASSWORD_LENGTH:
            return False
        actual = hashlib.scrypt(
            password.encode("utf-8"), salt=salt, n=int(n), r=int(r), p=int(p), dklen=len(expected)
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


# Хеш для несуществующего логина: время ответа не выдаёт, есть ли аккаунт.
_DUMMY_HASH: Optional[str] = None


def _dummy_hash() -> str:
    global _DUMMY_HASH
    if _DUMMY_HASH is None:
        _DUMMY_HASH = hash_password(secrets.token_urlsafe(24))
    return _DUMMY_HASH


# ---------- ограничение попыток ----------


class LoginThrottle:
    """Задержка после неудачных попыток. Память процесса: для локальной
    установки этого достаточно, scrypt сам стоит заметного времени."""

    FREE_ATTEMPTS = 5
    MAX_LOCK_SECONDS = 15 * 60

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._failures: Dict[str, List[float]] = {}

    def _key(self, login: str) -> str:
        return (login or "").strip().casefold()

    def check(self, login: str, now: Optional[float] = None) -> float:
        """Сколько секунд ждать до следующей попытки. 0 - можно пробовать."""
        moment = time.time() if now is None else now
        with self._lock:
            failures = self._failures.get(self._key(login), [])
            if len(failures) < self.FREE_ATTEMPTS:
                return 0.0
            extra = len(failures) - self.FREE_ATTEMPTS
            lock = min(self.MAX_LOCK_SECONDS, 2 ** min(extra, 12))
            return max(0.0, failures[-1] + lock - moment)

    def failed(self, login: str, now: Optional[float] = None) -> None:
        moment = time.time() if now is None else now
        with self._lock:
            items = self._failures.setdefault(self._key(login), [])
            items.append(moment)
            del items[:-50]

    def succeeded(self, login: str) -> None:
        with self._lock:
            self._failures.pop(self._key(login), None)

    def reset(self) -> None:
        with self._lock:
            self._failures.clear()


throttle = LoginThrottle()


# ---------- аккаунты ----------


def _row_to_account(row) -> Account:
    return Account(
        id=row["id"],
        login=row["login"],
        display_name=row["display_name"],
        installation_admin=bool(row["installation_admin"]),
    )


def validate_login(login: str) -> str:
    value = (login or "").strip()
    if not re.fullmatch(_LOGIN_RE, value):
        raise AuthError("Логин: 3-64 символа, латиница, цифры и . _ @ -")
    return value


# Дополнения узнают о новых аккаунтах: например, чтобы включить их в
# организацию. Вызов идёт после записи аккаунта.
account_created_hooks: list = []


def create_account(
    login: str,
    password: str,
    *,
    display_name: str = "",
    installation_admin: bool = False,
    created_by: str = "",
    source: str = "admin",
) -> Account:
    login = validate_login(login)
    password_hash = hash_password(password)
    account_id = auth_store.new_id("acc")
    moment = auth_store.now_iso()
    with auth_store.write() as db:
        if db.execute("SELECT 1 FROM accounts WHERE login = ?", (login,)).fetchone():
            raise AuthError("Аккаунт с таким логином уже есть")
        db.execute(
            "INSERT INTO accounts (id, login, display_name, password_hash, installation_admin,"
            " created_at, password_changed_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                account_id,
                login,
                (display_name or login).strip()[:200],
                password_hash,
                1 if installation_admin else 0,
                moment,
                moment,
            ),
        )
        auth_store.audit(
            db,
            "account.create",
            account_id=created_by or account_id,
            detail={"target": account_id, "installation_admin": bool(installation_admin), "source": source},
        )
    account = get_account(account_id)
    for hook in list(account_created_hooks):
        hook(account, source)
    return account


def get_account(account_id: str) -> Account:
    with auth_store.read() as db:
        row = db.execute(
            "SELECT * FROM accounts WHERE id = ? AND disabled = 0", (account_id,)
        ).fetchone()
    if row is None:
        raise AccessDenied("Аккаунт не найден")
    return _row_to_account(row)


def find_account_by_login(login: str) -> Optional[Account]:
    with auth_store.read() as db:
        row = db.execute(
            "SELECT * FROM accounts WHERE login = ? AND disabled = 0", ((login or "").strip(),)
        ).fetchone()
    return _row_to_account(row) if row else None


def list_accounts() -> List[Dict[str, Any]]:
    with auth_store.read() as db:
        rows = db.execute(
            "SELECT id, login, display_name, installation_admin, disabled, created_at"
            " FROM accounts ORDER BY login COLLATE NOCASE"
        ).fetchall()
    return [
        {
            "account_id": row["id"],
            "login": row["login"],
            "display_name": row["display_name"],
            "installation_admin": bool(row["installation_admin"]),
            "disabled": bool(row["disabled"]),
            "created_at": row["created_at"],
        }
        for row in rows
    ]


def has_installation_admin() -> bool:
    with auth_store.read() as db:
        row = db.execute(
            "SELECT 1 FROM accounts WHERE installation_admin = 1 AND disabled = 0 LIMIT 1"
        ).fetchone()
    return row is not None


def _other_admins(db, account_id: str) -> int:
    return int(
        db.execute(
            "SELECT COUNT(*) FROM accounts WHERE installation_admin = 1 AND disabled = 0 AND id != ?",
            (account_id,),
        ).fetchone()[0]
    )


def change_password(account_id: str, current: str, new: str) -> None:
    with auth_store.read() as db:
        row = db.execute(
            "SELECT password_hash FROM accounts WHERE id = ? AND disabled = 0", (account_id,)
        ).fetchone()
    if row is None or not verify_password(current, row["password_hash"]):
        raise AuthError("Текущий пароль не подошёл")
    new_hash = hash_password(new)
    with auth_store.write() as db:
        db.execute(
            "UPDATE accounts SET password_hash = ?, password_changed_at = ? WHERE id = ?",
            (new_hash, auth_store.now_iso(), account_id),
        )
        # Смена пароля гасит все сессии аккаунта.
        db.execute("DELETE FROM sessions WHERE account_id = ?", (account_id,))
        auth_store.audit(db, "account.password", account_id=account_id)


def set_password(account_id: str, password: str, *, by: str = "") -> None:
    """Новый пароль, назначенный администратором. Сессии аккаунта гаснут."""
    new_hash = hash_password(password)
    with auth_store.write() as db:
        if db.execute("SELECT 1 FROM accounts WHERE id = ?", (account_id,)).fetchone() is None:
            raise AuthError("Аккаунт не найден")
        db.execute(
            "UPDATE accounts SET password_hash = ?, password_changed_at = ? WHERE id = ?",
            (new_hash, auth_store.now_iso(), account_id),
        )
        db.execute("DELETE FROM sessions WHERE account_id = ?", (account_id,))
        auth_store.audit(db, "account.password.reset", account_id=by, detail={"target": account_id})


def set_password_locally(login: str, password: str) -> None:
    """Сброс пароля с консоли установки."""
    new_hash = hash_password(password)
    with auth_store.write() as db:
        row = db.execute("SELECT id FROM accounts WHERE login = ?", (login,)).fetchone()
        if row is None:
            raise AuthError("Аккаунт не найден")
        db.execute(
            "UPDATE accounts SET password_hash = ?, password_changed_at = ?, disabled = 0 WHERE id = ?",
            (new_hash, auth_store.now_iso(), row["id"]),
        )
        db.execute("DELETE FROM sessions WHERE account_id = ?", (row["id"],))
        auth_store.audit(db, "account.password.local_reset", account_id=row["id"])


def set_disabled(account_id: str, disabled: bool, *, by: str = "") -> None:
    with auth_store.write() as db:
        row = db.execute(
            "SELECT installation_admin FROM accounts WHERE id = ?", (account_id,)
        ).fetchone()
        if row is None:
            raise AuthError("Аккаунт не найден")
        if disabled and account_id == by:
            raise AuthError("Нельзя отключить собственную учётную запись")
        if disabled and row["installation_admin"] and not _other_admins(db, account_id):
            raise AuthError("Должен остаться хотя бы один администратор")
        db.execute("UPDATE accounts SET disabled = ? WHERE id = ?", (1 if disabled else 0, account_id))
        if disabled:
            db.execute("DELETE FROM sessions WHERE account_id = ?", (account_id,))
        auth_store.audit(
            db, "account.disable" if disabled else "account.enable", account_id=by,
            detail={"target": account_id},
        )


def disable_account(account_id: str, by: str = "") -> None:
    set_disabled(account_id, True, by=by)


# ---------- сессии ----------


def session_ttl_seconds() -> int:
    try:
        return max(300, int(os.getenv("AUTH_SESSION_TTL", str(12 * 3600))))
    except ValueError:
        return 12 * 3600


def session_idle_seconds() -> int:
    try:
        return max(300, int(os.getenv("AUTH_SESSION_IDLE", str(2 * 3600))))
    except ValueError:
        return 2 * 3600


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def login(login_name: str, password: str, *, now: Optional[float] = None) -> Dict[str, Any]:
    """Проверить пароль и выдать сессию. Возвращает токен и аккаунт."""
    moment = time.time() if now is None else now
    wait = throttle.check(login_name, moment)
    if wait > 0:
        raise AuthError("Слишком много неудачных попыток, повторите через %d с" % int(wait + 1))
    with auth_store.read() as db:
        row = db.execute(
            "SELECT * FROM accounts WHERE login = ? AND disabled = 0",
            ((login_name or "").strip(),),
        ).fetchone()
    stored = row["password_hash"] if row else _dummy_hash()
    valid = verify_password(password or "", stored)
    if row is None or not valid:
        throttle.failed(login_name, moment)
        raise AuthError("Неверный логин или пароль")
    throttle.succeeded(login_name)
    token = secrets.token_urlsafe(32)
    with auth_store.write() as db:
        db.execute("DELETE FROM sessions WHERE expires_at < ?", (moment,))
        db.execute(
            "INSERT INTO sessions (token_hash, account_id, created_at, last_seen_at, expires_at)"
            " VALUES (?, ?, ?, ?, ?)",
            (_token_hash(token), row["id"], moment, moment, moment + session_ttl_seconds()),
        )
    return {"token": token, "account": _row_to_account(row)}


def resolve_session(token: str, *, now: Optional[float] = None) -> Account:
    """Аккаунт по токену сессии. Истёкшая или неизвестная сессия - отказ."""
    if not token or len(token) > 200:
        raise AccessDenied("Нужен вход")
    moment = time.time() if now is None else now
    digest = _token_hash(token)
    with auth_store.write() as db:
        row = db.execute(
            "SELECT s.*, a.disabled FROM sessions s JOIN accounts a ON a.id = s.account_id"
            " WHERE s.token_hash = ?",
            (digest,),
        ).fetchone()
        if row is None:
            raise AccessDenied("Нужен вход")
        if (
            row["disabled"]
            or row["expires_at"] <= moment
            or row["last_seen_at"] + session_idle_seconds() <= moment
        ):
            db.execute("DELETE FROM sessions WHERE token_hash = ?", (digest,))
            raise AccessDenied("Сессия истекла, войдите снова")
        db.execute("UPDATE sessions SET last_seen_at = ? WHERE token_hash = ?", (moment, digest))
        account_id = row["account_id"]
    return get_account(account_id)


def logout(token: str) -> None:
    if not token:
        return
    with auth_store.write() as db:
        db.execute("DELETE FROM sessions WHERE token_hash = ?", (_token_hash(token),))
