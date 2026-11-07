"""Ключи доступа для интеграций (принципал ``integration_client``).

Это отдельный вид доступа, не учётная запись человека: у ключа нет входа в
интерфейс, нет прав администратора и нет сессии. Ключ выдаёт администратор
установки, у ключа есть список разрешений (scopes), срок жизни и неизменяемый
контекст.

Секрет имеет вид ``epgu_ic_<id>_<случайная часть>``. Он показывается один раз
при создании. В базе хранится только SHA-256 секрета. Таблица лежит в той же
базе, что и учётные записи (``auth_store``), чужие таблицы не меняются.

Ключ принадлежит установке, а не человеку, который его выпустил: полномочия
этого человека он не наследует. Поэтому отключение учётной записи
администратора ключ НЕ отзывает, отзыв это отдельное явное действие
(``revoke``).

Установка в контексте ключа не указывается: ключ привязан к единственной базе
этой установки, и поле ``installation`` из запроса не принимается как
доказательство прав.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, FrozenSet, List, Optional

import auth_store
import capabilities

TOKEN_PREFIX = "epgu_ic_"

# Разрешения. Нет ни "admin", ни "*": ключ интеграции не может стать
# администратором и не получает "всё сразу". Набор определён в реестре
# возможностей (capabilities.SCOPES): реестр проверяет по нему свои записи и
# не должен импортировать этот модуль.
SCOPES: FrozenSet[str] = capabilities.SCOPES

# Сроки жизни в днях. Значения ждут решения ревьюера; бессрочных ключей нет.
DEFAULT_TTL_DAYS = 30
MAX_TTL_DAYS = 90

CONTOURS = frozenset({"TEST", "PROD"})
_CONTEXT_KEYS = frozenset({"organization_ref", "contour", "is_ref"})
_NAME_MAX = 100
_HEX_RE = re.compile(r"[0-9a-f]{32}")
# Ссылки на организацию и ИС сравниваются как есть, с учётом регистра:
# мнемоники ИС ЕСИА регистрозависимы, и приведение могло бы склеить две ИС.
# Поэтому значение не нормализуется, а пробелы, управляющие символы и
# прочее вне набора отклоняются.
_REF_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,199}")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS integration_clients (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    prefix TEXT NOT NULL,
    secret_hash TEXT NOT NULL,
    scopes TEXT NOT NULL,
    context TEXT NOT NULL,
    created_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    revoked_at TEXT,
    revoked_by TEXT,
    last_used_at TEXT
);
"""


class IntegrationError(ValueError):
    """Неверные параметры создания ключа. Текст безопасно показывать."""


class IntegrationNotFound(LookupError):
    """Ключа с таким id нет."""


class InvalidToken(RuntimeError):
    """Ключ не принят. Причина (формат, секрет, отзыв, срок) наружу не отдаётся."""

    def __init__(self) -> None:
        super().__init__("invalid_token")


@dataclass(frozen=True)
class IntegrationPrincipal:
    id: str
    name: str
    scopes: FrozenSet[str]
    context: Dict[str, Any] = field(default_factory=dict)
    expires_at: str = ""


# ---------- схема ----------

_ensured_for: Optional[str] = None


def _create_schema() -> None:
    """Создать таблицу ключей. Повторный вызов ничего не меняет."""
    connection = auth_store._open()
    try:
        connection.executescript(_SCHEMA)
    finally:
        connection.close()


# Таблица создаётся вместе со схемой учётных записей.
if _create_schema not in auth_store.schema_hooks:
    auth_store.schema_hooks.append(_create_schema)


def _ensure() -> None:
    """Таблица должна быть и тогда, когда база создана до загрузки модуля."""
    global _ensured_for
    auth_store.initialize_once()
    current = str(auth_store.db_path())
    if _ensured_for != current:
        _create_schema()
        _ensured_for = current


# ---------- вспомогательное ----------


def _now(now: Optional[datetime]) -> datetime:
    moment = now or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment.astimezone(timezone.utc)


def _iso(moment: datetime) -> str:
    return moment.isoformat(timespec="seconds")


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _parse_token(token: Any) -> Optional[str]:
    """id ключа из секрета или None, если формат неверный."""
    if not isinstance(token, str) or not token.startswith(TOKEN_PREFIX) or len(token) > 256:
        return None
    rest = token[len(TOKEN_PREFIX):]
    ident, sep, random_part = rest.partition("_")
    if not sep or not random_part or _HEX_RE.fullmatch(ident) is None:
        return None
    return "ic_" + ident


def _validate_scopes(scopes: Any) -> FrozenSet[str]:
    if isinstance(scopes, (str, bytes)) or not isinstance(scopes, (list, tuple, set, frozenset)):
        raise IntegrationError("Нужен список разрешений")
    if not scopes:
        raise IntegrationError("Список разрешений не может быть пустым")
    for scope in scopes:
        if not isinstance(scope, str) or scope not in SCOPES:
            raise IntegrationError("Неизвестное разрешение")
    return frozenset(scopes)


def _is_ref_value(value: Any) -> bool:
    # fullmatch, а не match с $: иначе проходит значение с переводом строки в конце.
    return isinstance(value, str) and _REF_RE.fullmatch(value) is not None


def _validate_context(context: Any) -> Dict[str, Any]:
    if not isinstance(context, dict):
        raise IntegrationError("Нужен контекст ключа")
    if set(context) - _CONTEXT_KEYS:
        raise IntegrationError("В контексте есть неизвестные поля")
    if not _is_ref_value(context.get("organization_ref")):
        raise IntegrationError("Нужна ссылка на организацию (organization_ref)")
    # Сначала тип: список или объект нельзя проверять через "in" множества,
    # иначе вместо отказа получается TypeError и ответ 500.
    contour = context.get("contour")
    if not isinstance(contour, str) or contour not in CONTOURS:
        raise IntegrationError("Контур должен быть TEST или PROD")
    result: Dict[str, Any] = {
        "organization_ref": context["organization_ref"],
        "contour": context["contour"],
    }
    if "is_ref" in context:
        # Ссылка на информационную систему, например её мнемоника. Не флаг.
        if not _is_ref_value(context["is_ref"]):
            raise IntegrationError("is_ref должен быть ссылкой на ИС строкой")
        result["is_ref"] = context["is_ref"]
    return result


def context_matches(bound: Dict[str, Any], current: Dict[str, Any], *, requires_is: bool) -> bool:
    """Совпадает ли контекст ключа с текущим контекстом операции.

    Сравнение точное. Для операции, привязанной к ИС, ключ без ``is_ref`` не
    подходит: отсутствие ссылки не означает любую ИС. Если ИС указана хотя бы
    с одной стороны, она должна совпасть. Неизвестный или неполный текущий
    контекст не совпадает ни с чем.

    Правило вызывает ``operator_context.authorize``.
    """
    # Обе стороны проверяются одним правилом: невалидный контекст ключа или
    # операции даёт отказ, а не исключение.
    try:
        expected = _validate_context(bound)
        clean = _validate_context(current)
    except IntegrationError:
        return False
    if requires_is and ("is_ref" not in expected or "is_ref" not in clean):
        return False
    keys = ("organization_ref", "contour", "is_ref")
    return all(expected.get(key) == clean.get(key) for key in keys)


def _validate_ttl(ttl_days: Any) -> int:
    if ttl_days is None:
        return DEFAULT_TTL_DAYS
    if isinstance(ttl_days, bool) or not isinstance(ttl_days, int):
        raise IntegrationError("Срок должен быть целым числом дней")
    if ttl_days < 1 or ttl_days > MAX_TTL_DAYS:
        raise IntegrationError("Срок ключа: от 1 до %d дней" % MAX_TTL_DAYS)
    return ttl_days


def _status(row, moment: datetime) -> str:
    if row["revoked_at"]:
        return "revoked"
    if datetime.fromisoformat(row["expires_at"]) <= moment:
        return "expired"
    return "active"


# ---------- операции ----------


def create_client(
    name: str,
    scopes: Any,
    context: Any,
    *,
    created_by: str,
    ttl_days: Optional[int] = None,
    now: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Выпустить ключ. Секрет ``secret`` возвращается только здесь и один раз.

    Контекст сохраняется как есть и потом не меняется. Сверка контекста с
    состоянием оператора здесь не делается: проверка ждёт ответа ревьюера.
    """
    if not isinstance(name, str) or not name.strip() or len(name) > _NAME_MAX:
        raise IntegrationError("Нужно название ключа до %d символов" % _NAME_MAX)
    scope_set = _validate_scopes(scopes)
    clean_context = _validate_context(context)
    days = _validate_ttl(ttl_days)
    moment = _now(now)

    ident = "ic_" + secrets.token_hex(16)
    prefix = TOKEN_PREFIX + ident[len("ic_"):]
    secret = "%s_%s" % (prefix, secrets.token_urlsafe(32))
    expires = moment + timedelta(days=days)
    _ensure()
    with auth_store.write() as db:
        db.execute(
            "INSERT INTO integration_clients (id, name, prefix, secret_hash, scopes, context,"
            " created_by, created_at, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                ident,
                name.strip(),
                prefix,
                _hash(secret),
                json.dumps(sorted(scope_set)),
                json.dumps(clean_context, ensure_ascii=False, sort_keys=True),
                created_by,
                _iso(moment),
                _iso(expires),
            ),
        )
        auth_store.audit(
            db,
            "integration.create",
            account_id=created_by,
            detail={
                "client_id": ident,
                "name": name.strip(),
                "scopes": sorted(scope_set),
                "contour": clean_context["contour"],
                "expires_at": _iso(expires),
            },
        )
    return {
        "id": ident,
        "name": name.strip(),
        "scopes": sorted(scope_set),
        "context": clean_context,
        "expires_at": _iso(expires),
        "secret": secret,
    }


def verify(token: Any, *, now: Optional[datetime] = None) -> IntegrationPrincipal:
    """Проверить секрет по базе. Кэша нет: отзыв действует со следующего вызова."""
    ident = _parse_token(token)
    if ident is None:
        raise InvalidToken()
    moment = _now(now)
    _ensure()
    with auth_store.write() as db:
        row = db.execute("SELECT * FROM integration_clients WHERE id = ?", (ident,)).fetchone()
        stored = row["secret_hash"] if row is not None else "0" * 64
        matches = hmac.compare_digest(stored, _hash(token))
        if row is None or not matches:
            raise InvalidToken()
        if _status(row, moment) != "active":
            raise InvalidToken()
        db.execute(
            "UPDATE integration_clients SET last_used_at = ? WHERE id = ?",
            (_iso(moment), ident),
        )
        return IntegrationPrincipal(
            id=row["id"],
            name=row["name"],
            scopes=frozenset(json.loads(row["scopes"])),
            context=dict(json.loads(row["context"])),
            expires_at=row["expires_at"],
        )


def revoke(client_id: str, *, by: str, now: Optional[datetime] = None) -> None:
    """Отозвать ключ. Повторный отзыв не меняет время первого."""
    moment = _now(now)
    _ensure()
    with auth_store.write() as db:
        row = db.execute(
            "SELECT revoked_at FROM integration_clients WHERE id = ?", (client_id,)
        ).fetchone()
        if row is None:
            raise IntegrationNotFound("Ключ не найден")
        if row["revoked_at"]:
            return
        db.execute(
            "UPDATE integration_clients SET revoked_at = ?, revoked_by = ? WHERE id = ?",
            (_iso(moment), by, client_id),
        )
        auth_store.audit(
            db, "integration.revoke", account_id=by, detail={"client_id": client_id}
        )


def list_clients(*, now: Optional[datetime] = None) -> List[Dict[str, Any]]:
    """Список ключей без секрета и без хеша."""
    moment = _now(now)
    _ensure()
    with auth_store.read() as db:
        rows = db.execute("SELECT * FROM integration_clients ORDER BY created_at, id").fetchall()
    return [
        {
            "id": row["id"],
            "name": row["name"],
            "prefix": row["prefix"],
            "scopes": json.loads(row["scopes"]),
            "context": json.loads(row["context"]),
            "created_by": row["created_by"],
            "created_at": row["created_at"],
            "expires_at": row["expires_at"],
            "revoked_at": row["revoked_at"],
            "revoked_by": row["revoked_by"],
            "last_used_at": row["last_used_at"],
            "status": _status(row, moment),
        }
        for row in rows
    ]
