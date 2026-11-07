"""Контекст оператора для машинного доступа (ключи интеграций).

Публичная редакция: один контекст оператора на установку. У backend нет
надёжного источника сведений об организации и ИС, поэтому их явно задаёт
администратор установки - это *привязка оператора* (``operator_binding``,
одна строка). Контекст запроса выводится из этой привязки, сверенной с живым
состоянием оператора (выбранный сертификат, контур по адресам ЕСИА и
витрины), а НЕ из самого ключа: ключ с контекстом не может подтвердить себя
сам собой. Ключ сравнивается с этим контекстом отдельным шагом
(``authorize``).

Живое состояние даёт провайдер (``set_state_provider``), его регистрирует
``app.py``: модуль не знает про глобальные переменные приложения.

Секретов здесь нет: ни маркера ЕСИА, ни PIN, ни ключей API, ни секрета
интеграции. ``OperatorContext`` их не содержит.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Callable, Dict, Optional

import auth_store
import config
import integration_auth

# Коды причин, по которым контекст недоступен (попадают в ответ 409).
NO_PROVIDER = "no_provider"
NO_BINDING = "no_binding"
NO_CERTIFICATE = "no_certificate"
CERTIFICATE_MISMATCH = "certificate_mismatch"
UNKNOWN_CONTOUR = "unknown_contour"
CONTOUR_MISMATCH = "contour_mismatch"

# Отпечаток сертификата: 40 шестнадцатеричных знаков. Регистр шестнадцатеричной
# записи значения не меняет, поэтому приведение к верхнему регистру безопасно
# (в отличие от ссылок на организацию и ИС, которые регистрозависимы).
_THUMBPRINT_RE = re.compile(r"[0-9A-Fa-f]{40}")

# Контур по результату config.detect_environment для живых адресов.
_CONTOUR_BY_ENVIRONMENT = {"test": "TEST", "test-beta": "TEST", "prod": "PROD"}

_SCHEMA = """
CREATE TABLE IF NOT EXISTS operator_binding (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    organization_ref TEXT NOT NULL,
    is_ref TEXT,
    contour TEXT NOT NULL,
    certificate_thumbprint TEXT NOT NULL,
    updated_by TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS operator_binding_epoch (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    epoch INTEGER NOT NULL
);
"""


class BindingError(ValueError):
    """Недопустимое значение привязки. Текст безопасно показывать."""


class ContextUnavailable(RuntimeError):
    """Контекст оператора сейчас не определить; ``reason`` - код причины."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class ContextMismatch(RuntimeError):
    """Контекст ключа не совпадает с контекстом оператора."""

    def __init__(self) -> None:
        super().__init__("context_mismatch")


@dataclass(frozen=True)
class OperatorBinding:
    organization_ref: str
    is_ref: Optional[str]
    contour: str
    certificate_thumbprint: str
    updated_by: str
    updated_at: str
    # Версия привязки: растёт при каждой установке и снятии. Удаление и повторное
    # создание тех же значений даёт новую версию, поэтому по значениям одним
    # их не отличить.
    epoch: int = 0

    def public(self) -> Dict[str, Any]:
        return {
            "organization_ref": self.organization_ref,
            "is_ref": self.is_ref,
            "contour": self.contour,
            "certificate_thumbprint": self.certificate_thumbprint,
            "updated_by": self.updated_by,
            "updated_at": self.updated_at,
            "epoch": self.epoch,
        }


@dataclass(frozen=True)
class LiveState:
    """Живое состояние оператора, снятое провайдером за один вызов."""

    certificate_thumbprint: Optional[str]
    generation: int
    esia_host: str
    svcdev_host: str


@dataclass(frozen=True, repr=False)
class OperatorContext:
    """Снимок контекста оператора. Только эти поля, секретов нет."""

    contour: str
    organization_ref: str
    is_ref: Optional[str]
    certificate_thumbprint: str
    generation: int
    binding_epoch: int

    def __repr__(self) -> str:
        return (
            "OperatorContext(contour=%r, organization_ref=%r, is_ref=%r, "
            "certificate_thumbprint=%r, generation=%r, binding_epoch=%r)"
            % (self.contour, self.organization_ref, self.is_ref,
               self.certificate_thumbprint, self.generation, self.binding_epoch)
        )

    def public(self) -> Dict[str, Any]:
        return {
            "contour": self.contour,
            "organization_ref": self.organization_ref,
            "is_ref": self.is_ref,
            "certificate_thumbprint": self.certificate_thumbprint,
            "generation": self.generation,
            "binding_epoch": self.binding_epoch,
        }


# ---------- схема ----------

_ensured_for: Optional[str] = None


def _create_schema() -> None:
    """Создать таблицу привязки. Повторный вызов ничего не меняет."""
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


# ---------- привязка ----------


def _validate(organization_ref: Any, is_ref: Any, contour: Any, thumbprint: Any) -> Dict[str, Any]:
    # Правила ссылок те же, что у контекста ключа (integration_auth). Сначала
    # проверяется тип, потом принадлежность множеству: список или объект нельзя
    # искать через "in" множества, иначе вместо отказа получится TypeError.
    if not integration_auth._is_ref_value(organization_ref):
        raise BindingError("Нужна ссылка на организацию (organization_ref)")
    if not isinstance(contour, str) or contour not in integration_auth.CONTOURS:
        raise BindingError("Контур должен быть TEST или PROD")
    if not isinstance(thumbprint, str) or _THUMBPRINT_RE.fullmatch(thumbprint) is None:
        raise BindingError("Отпечаток сертификата: 40 шестнадцатеричных знаков")
    if is_ref is not None and not integration_auth._is_ref_value(is_ref):
        raise BindingError("is_ref должен быть ссылкой на ИС строкой")
    return {
        "organization_ref": organization_ref,
        "is_ref": is_ref,
        "contour": contour,
        "certificate_thumbprint": thumbprint.upper(),
    }


def _from_row(row) -> OperatorBinding:
    return OperatorBinding(
        organization_ref=row["organization_ref"],
        is_ref=row["is_ref"],
        contour=row["contour"],
        certificate_thumbprint=row["certificate_thumbprint"],
        updated_by=row["updated_by"],
        updated_at=row["updated_at"],
        epoch=int(row["epoch"]),
    )


def current_epoch(db) -> int:
    """Версия привязки внутри чужой транзакции (0, если привязку не задавали)."""
    row = db.execute("SELECT epoch FROM operator_binding_epoch WHERE id = 1").fetchone()
    return int(row[0]) if row is not None else 0


def _bump_epoch(db) -> int:
    """Увеличить версию в той же транзакции, что меняет привязку."""
    db.execute(
        "INSERT INTO operator_binding_epoch (id, epoch) VALUES (1, 1)"
        " ON CONFLICT(id) DO UPDATE SET epoch = epoch + 1"
    )
    return current_epoch(db)


def get_binding() -> Optional[OperatorBinding]:
    """Текущая привязка или None, если её не задавали.

    Привязка и её версия читаются одним запросом, поэтому видны согласованно.
    """
    _ensure()
    with auth_store.read() as db:
        row = db.execute(
            "SELECT b.*, COALESCE((SELECT epoch FROM operator_binding_epoch WHERE id = 1), 0)"
            " AS epoch FROM operator_binding b WHERE b.id = 1"
        ).fetchone()
    return _from_row(row) if row is not None else None


def set_binding(
    organization_ref: Any,
    contour: Any,
    certificate_thumbprint: Any,
    *,
    is_ref: Any = None,
    by: str,
) -> OperatorBinding:
    """Задать привязку (заменяет прежнюю). Значения проверяются до записи."""
    clean = _validate(organization_ref, is_ref, contour, certificate_thumbprint)
    _ensure()
    moment = auth_store.now_iso()
    with auth_store.write() as db:
        db.execute(
            "INSERT INTO operator_binding (id, organization_ref, is_ref, contour,"
            " certificate_thumbprint, updated_by, updated_at) VALUES (1, ?, ?, ?, ?, ?, ?)"
            " ON CONFLICT(id) DO UPDATE SET organization_ref = excluded.organization_ref,"
            " is_ref = excluded.is_ref, contour = excluded.contour,"
            " certificate_thumbprint = excluded.certificate_thumbprint,"
            " updated_by = excluded.updated_by, updated_at = excluded.updated_at",
            (clean["organization_ref"], clean["is_ref"], clean["contour"],
             clean["certificate_thumbprint"], by, moment),
        )
        epoch = _bump_epoch(db)
        auth_store.audit(db, "operator_binding.set", account_id=by, detail=dict(clean))
    return OperatorBinding(updated_by=by, updated_at=moment, epoch=epoch, **clean)


def clear_binding(by: str) -> bool:
    """Снять привязку. True, если она была."""
    _ensure()
    with auth_store.write() as db:
        removed = db.execute("DELETE FROM operator_binding WHERE id = 1").rowcount > 0
        if removed:
            _bump_epoch(db)
            auth_store.audit(db, "operator_binding.clear", account_id=by, detail={})
    return removed


# ---------- живое состояние ----------

_provider: Optional[Callable[[], LiveState]] = None


def set_state_provider(provider: Optional[Callable[[], LiveState]]) -> None:
    """Зарегистрировать функцию, возвращающую ``LiveState``. None снимает её."""
    global _provider
    _provider = provider


def capture() -> OperatorContext:
    """Снимок контекста оператора: привязка плюс живое состояние.

    Функция синхронная и не содержит ``await``: все чтения живого состояния
    идут одним вызовом без переключения. Вызывающий на цикле событий получает
    согласованный вид, потому что методы, меняющие это состояние
    (``set_current_certificate``, ``/session/clear``), тоже ``async`` и
    выполняются на том же цикле: между чтениями они вклиниться не могут. Из
    потока пула такая гарантия не действует.

    Результат это снимок на момент вызова. Пользоваться им дальше можно только
    как данными этого момента, а не как признаком того, что состояние не
    изменилось.
    """
    if _provider is None:
        raise ContextUnavailable(NO_PROVIDER)
    binding = get_binding()
    state = _provider()
    if binding is None:
        raise ContextUnavailable(NO_BINDING)
    if not isinstance(state, LiveState):
        raise ContextUnavailable(NO_PROVIDER)
    selected = state.certificate_thumbprint
    if not isinstance(selected, str) or not selected:
        raise ContextUnavailable(NO_CERTIFICATE)
    if selected.upper() != binding.certificate_thumbprint:
        raise ContextUnavailable(CERTIFICATE_MISMATCH)
    environment = config.detect_environment(state.esia_host, state.svcdev_host)
    contour = _CONTOUR_BY_ENVIRONMENT.get(environment)
    if contour is None:
        raise ContextUnavailable(UNKNOWN_CONTOUR)
    if contour != binding.contour:
        raise ContextUnavailable(CONTOUR_MISMATCH)
    return OperatorContext(
        contour=contour,
        organization_ref=binding.organization_ref,
        is_ref=binding.is_ref,
        certificate_thumbprint=binding.certificate_thumbprint,
        generation=state.generation,
        binding_epoch=binding.epoch,
    )


def authorize(principal: integration_auth.IntegrationPrincipal, *, requires_is: bool) -> OperatorContext:
    """Снимок контекста оператора, если контекст ключа ему равен.

    Сравнивается контекст ключа с контекстом из привязки и живого состояния,
    а не ключ с самим собой.
    """
    snapshot = capture()
    current: Dict[str, Any] = {
        "organization_ref": snapshot.organization_ref,
        "contour": snapshot.contour,
    }
    if snapshot.is_ref is not None:
        current["is_ref"] = snapshot.is_ref
    if not integration_auth.context_matches(principal.context, current, requires_is=requires_is):
        raise ContextMismatch()
    return snapshot
