"""Планы внешних операций: prepare, approve, execute на исполнителе.

Это локальный механизм. Встроенных исполнителей в ядре нет вообще: исполнитель
регистрируется только явно (``register_executor``), в тестах его ставит
fixture. Без исполнителя prepare и execute отвечают 503 ``executor_unavailable``
и ничего не вызывают. Реальных адресов, подписи и ключей API здесь нет.

Порядок жизни плана:

1. ``prepare`` только записывает неизменяемый план: ключ, возможность,
   адресат, байты, контекст оператора с версией привязки, список внешних
   вызовов и срок. Исполнитель не вызывается, номер не резервируется.
2. ``approve`` выполняет человек (администратор по обычной сессии) после
   точного предпросмотра. Хеш плана пересчитывается из сохранённых байтов.
3. ``execute`` проверяет одобрение, целостность, ключ, контекст и версию
   привязки, затем одной транзакцией захватывает план (approved -> inflight)
   и только после захвата вызывает исполнитель.

Статусы: planned, approved, inflight, succeeded, failed, unknown. Разрешены
только переходы planned -> approved -> inflight -> succeeded|failed|unknown;
остальные отклоняет и триггер базы. inflight никогда не возвращается в
approved: после обрыва процесса ``recover_inflight`` переводит его в unknown.

Гарантии и их границы (см. также docstring ``ExecutionContext``):

- Захват атомарен относительно других записей в базу (``BEGIN IMMEDIATE``):
  из двух конкурентных захватов успешен один. В тот же UPDATE входят ключ
  (не отозван, не истёк), срок плана, версия и значения привязки.
- Сертификат, поколение сессии и контур живут в памяти процесса, а не в базе,
  в SQL их проверить нельзя. Их проверка стоит синхронно перед транзакцией
  захвата, без ``await`` между ними. Это защищает от методов, меняющих такое
  состояние на том же цикле событий (они ``async``). От потока пула, который
  изменил бы это состояние, защиты нет.
- После захвата отзыв ключа или смена привязки не останавливают исполнителя
  сами. Исполнитель обязан вызывать ``ExecutionContext.start_call`` перед
  каждым внешним вызовом; между проверкой и началом вызова остаётся окно,
  которое ядро закрыть не может (проверка не блокирует базу и поток пула).
- Время захвата берётся после получения блокировки записи, внутри той же
  транзакции: ожидание другого писателя не продлевает срок плана и ключа.
- Политика целевой возможности (``implemented``, условия, права) входит в
  план и его хеш и проверяется при prepare, при execute и перед каждым
  внешним вызовом. Возможность с условием, которое ядро ещё не проверяет
  (membership, license, esia_token и т. п.), не исполняется вовсе.
- Журнал шагов (``operation_plan_steps``) пишется по ходу исполнения
  отдельными транзакциями: начат вызов, завершён, точно не отправлен. После
  неизвестного исхода или обрыва процесса в плане остаются известные
  завершённые вызовы со ссылками для сверки и начатые вызовы с
  неизвестным исходом. Ни один из них автоматически не повторяется.
  Ядро проверяет у ссылки только длину и алфавит и не может отличить
  идентификатор от секрета: передать несекретное значение из разрешённого
  поля обязан исполнитель. Это часть приёмки каждого реального исполнителя.

Секретов здесь нет: ни маркера ЕСИА, ни PIN, ни ключей API, ни секрета
интеграции. Объект сессии отдаёт только провайдер ``set_session_provider``,
и он не попадает ни в repr, ни в план, ни в журнал.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import inspect
import json
import logging
import re
import secrets
import threading
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Dict, List, Optional, Protocol, Tuple

import auth_store
import capabilities
import integration_auth
import operator_context

logger = logging.getLogger(__name__)

PLANNED = "planned"
APPROVED = "approved"
INFLIGHT = "inflight"
SUCCEEDED = "succeeded"
FAILED = "failed"
UNKNOWN = "unknown"
STATUSES = (PLANNED, APPROVED, INFLIGHT, SUCCEEDED, FAILED, UNKNOWN)

PLAN_TTL = timedelta(minutes=10)
MAX_PAYLOAD_BYTES = 1_000_000
MAX_ATTACHMENTS = 5
MAX_TOTAL_BYTES = 2_000_000

_ATTACHMENT_NAME_RE = re.compile(r"[A-Za-z0-9._-]{1,100}")
_IDEMPOTENCY_KEY_RE = re.compile(r"[A-Za-z0-9._:-]{8,128}")
_CALL_NAME_RE = re.compile(r"[a-z][a-z0-9_]{0,63}")
_REASON_RE = re.compile(r"[A-Za-z0-9_.:-]{1,64}")
_PLAN_ID_RE = re.compile(r"plan_[0-9a-f]{32}")

_CONTEXT_KEYS = (
    "contour", "organization_ref", "is_ref", "certificate_thumbprint", "generation",
    "binding_epoch",
)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS operation_plans (
    id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    capability_id TEXT NOT NULL,
    idempotency_key TEXT NOT NULL UNIQUE,
    request_hash TEXT NOT NULL,
    plan_hash TEXT NOT NULL,
    target TEXT NOT NULL,
    payload BLOB NOT NULL,
    payload_sha256 TEXT NOT NULL,
    attachments TEXT NOT NULL,
    context TEXT NOT NULL,
    external_calls TEXT NOT NULL,
    target_policy TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN
        ('planned', 'approved', 'inflight', 'succeeded', 'failed', 'unknown')),
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    approved_by TEXT,
    approved_at TEXT,
    approved_hash TEXT,
    claimed_at TEXT,
    finished_at TEXT,
    result TEXT,
    error_code TEXT
);
CREATE TABLE IF NOT EXISTS operation_plan_attachments (
    plan_id TEXT NOT NULL REFERENCES operation_plans(id),
    idx INTEGER NOT NULL,
    name TEXT NOT NULL,
    content BLOB NOT NULL,
    PRIMARY KEY (plan_id, idx)
);
CREATE TABLE IF NOT EXISTS operation_plan_steps (
    plan_id TEXT NOT NULL REFERENCES operation_plans(id),
    seq INTEGER NOT NULL,
    name TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('started', 'completed', 'not_sent')),
    reference TEXT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    PRIMARY KEY (plan_id, name)
);
CREATE TRIGGER IF NOT EXISTS operation_plans_transition
BEFORE UPDATE OF status ON operation_plans
WHEN NEW.status <> OLD.status AND NOT (
    (OLD.status = 'planned' AND NEW.status = 'approved')
    OR (OLD.status = 'approved' AND NEW.status = 'inflight')
    OR (OLD.status = 'inflight' AND NEW.status IN ('succeeded', 'failed', 'unknown'))
)
BEGIN
    SELECT RAISE(ABORT, 'illegal_transition');
END;
"""


# ---------- ошибки ----------


class OperationError(Exception):
    """Ошибка плана: код и статус HTTP. Текст ``detail`` безопасно показывать."""

    code = "operation_error"
    http_status = 500
    default_detail = "ошибка операции"

    def __init__(self, detail: str = "") -> None:
        self.detail = detail or self.default_detail
        super().__init__(self.detail)


class InvalidRequest(OperationError, ValueError):
    code = "invalid_parameter"
    http_status = 400
    default_detail = "недопустимое значение"


class ExecutorUnavailable(OperationError):
    code = "executor_unavailable"
    http_status = 503
    default_detail = "исполнитель для этой операции не настроен"


class IdempotencyConflict(OperationError):
    code = "idempotency_conflict"
    http_status = 409
    default_detail = "ключ идемпотентности уже использован для другого запроса"


class PlanNotFound(OperationError):
    code = "plan_not_found"
    http_status = 404
    default_detail = "план не найден"


class PlanExpired(OperationError):
    code = "plan_expired"
    http_status = 410
    default_detail = "срок плана истёк"


class PlanHashMismatch(OperationError):
    code = "plan_hash_mismatch"
    http_status = 409
    default_detail = "хеш плана не совпадает с утверждённым"


class PlanStateError(OperationError):
    code = "plan_state"
    http_status = 409
    default_detail = "план в другом состоянии"


class PlanInflight(PlanStateError):
    code = "plan_inflight"
    default_detail = "план уже исполняется"


class CredentialInvalid(OperationError):
    code = "unauthenticated"
    http_status = 401
    default_detail = "invalid_token"


class ScopeMissing(OperationError):
    # Тот же ответ, что у маршрута без нужного права (integration_api).
    code = "forbidden"
    http_status = 403
    default_detail = "insufficient_scope"


class PolicyChanged(OperationError):
    code = "policy_changed"
    http_status = 409
    default_detail = "политика целевой возможности изменилась после подготовки плана"


class OutcomeUnknown(OperationError):
    code = "outcome_unknown"
    http_status = 502
    default_detail = (
        "результат внешней операции неизвестен; повтор не выполняется, нужна ручная сверка"
    )

    def __init__(self, plan_id: str, completed: Tuple[str, ...] = (),
                 uncertain: Tuple[str, ...] = ()) -> None:
        text = self.default_detail
        if completed:
            text += "; точно выполнены: " + ", ".join(completed)
        if uncertain:
            text += "; исход неизвестен: " + ", ".join(uncertain)
        super().__init__(text)
        # Тот же отчёт из журнала, что записан в план: клиенту не нужно разбирать detail.
        self.outcome = {
            "plan_id": plan_id,
            "completed_calls": list(completed),
            "uncertain_calls": list(uncertain),
        }


def _safe_reason(reason: Any) -> str:
    # Причину задаёт исполнитель: в ответ и журнал идёт только короткий код.
    if isinstance(reason, str) and _REASON_RE.fullmatch(reason):
        return reason
    return "unspecified"


class ExecutionAborted(OperationError):
    """Внешний вызов точно не начинался. Базовый класс ``NotSent`` и ``ContextChanged``.

    ``completed`` перечисляет внешние вызовы, которые к этому моменту уже
    выполнены (например, резервирование номера перед отказом на следующем шаге).
    """

    error_code = "aborted"
    label = "исполнение прервано"

    def __init__(self, reason: str = "", completed: Tuple[str, ...] = ()) -> None:
        self.reason = _safe_reason(reason)
        self.completed = tuple(name for name in completed if isinstance(name, str))
        super().__init__(self._text())

    def _text(self) -> str:
        text = "%s: %s" % (self.label, self.reason)
        if self.completed:
            text += "; уже выполнены внешние вызовы: " + ", ".join(self.completed)
        return text

    def with_completed(self, completed: Tuple[str, ...]) -> "ExecutionAborted":
        self.completed = tuple(completed)
        self.detail = self._text()
        self.args = (self.detail,)
        return self


class NotSent(ExecutionAborted):
    """Исполнитель отказался до начала внешнего вызова. Статус плана failed."""

    code = "execution_failed"
    http_status = 409
    error_code = "not_sent"
    label = "внешний вызов не начат"


class ContextChanged(ExecutionAborted):
    """Контекст, ключ или привязка изменились. Внешний вызов не начат."""

    code = "context_changed"
    http_status = 409
    error_code = "context_changed"
    label = "контекст оператора изменился"


# ---------- исполнители ----------


@dataclass(frozen=True)
class ExternalCall:
    name: str
    side_effects: Tuple[str, ...]


class Executor(Protocol):
    """Исполнитель одной возможности.

    ``external_calls`` перечисляет ВСЕ внешние вызовы операции по порядку.
    Перед каждым внешним вызовом исполнитель обязан вызвать
    ``ctx.start_call(name)`` без ``await`` между ним и началом вызова, а после
    известного завершения ``ctx.mark_done(name, reference)``. ``NotSent`` и
    ``ContextChanged`` означают, что текущий вызов точно не начинался. Любое
    другое исключение ядро считает неопределённым исходом (unknown) начатых
    и незавершённых вызовов и ни один вызов не повторяет.
    """

    capability_id: str
    external_calls: Tuple[ExternalCall, ...]

    async def run(
        self,
        ctx: "ExecutionContext",
        payload: bytes,
        attachments: Tuple[Tuple[str, bytes], ...],
        target: str,
    ) -> Dict[str, Any]: ...


_executors: Dict[str, Any] = {}
_executors_lock = threading.Lock()


def register_executor(executor: Any) -> None:
    """Зарегистрировать исполнителя. Нарушение условий это ValueError."""
    cap_id = getattr(executor, "capability_id", None)
    calls = getattr(executor, "external_calls", None)
    if not isinstance(cap_id, str) or not cap_id:
        raise ValueError("у исполнителя нет capability_id")
    cap = capabilities.get(cap_id)
    if cap is None:
        raise ValueError("возможность %r не найдена в реестре" % cap_id)
    if cap.machine != "target":
        raise ValueError("%s: исполнитель допускается только для machine=target" % cap_id)
    if cap.mcp_profile is not capabilities.McpProfile.NONE:
        raise ValueError("%s: у возможности с исполнителем mcp_profile должен быть none" % cap_id)
    if cap.effect not in (capabilities.Effect.READ_EXTERNAL, capabilities.Effect.WRITE_EXTERNAL):
        raise ValueError("%s: исполнитель нужен только внешней операции" % cap_id)
    problem = _policy_problem(cap)
    if problem is not None:
        raise ValueError("%s: возможность не допускается к исполнению (%s)" % (cap_id, problem))
    if not isinstance(calls, tuple) or not calls or not all(
        isinstance(call, ExternalCall) for call in calls
    ):
        raise ValueError("%s: external_calls должен быть непустым кортежем ExternalCall" % cap_id)
    names = [call.name for call in calls]
    if len(set(names)) != len(names) or not all(
        isinstance(name, str) and _CALL_NAME_RE.fullmatch(name) for name in names
    ):
        raise ValueError("%s: имена внешних вызовов неверны или повторяются" % cap_id)
    union = set()
    for call in calls:
        if not isinstance(call.side_effects, tuple) or not set(call.side_effects) <= (
            capabilities.SIDE_EFFECTS
        ):
            raise ValueError("%s: неизвестные побочные эффекты вызова %s" % (cap_id, call.name))
        union |= set(call.side_effects)
    if union != set(cap.side_effects):
        raise ValueError("%s: побочные эффекты вызовов не совпадают с возможностью" % cap_id)
    if not inspect.iscoroutinefunction(getattr(executor, "run", None)):
        raise ValueError("%s: run должен быть асинхронным методом" % cap_id)
    validator = getattr(executor, "validate_input", None)
    if validator is not None and (not callable(validator) or inspect.iscoroutinefunction(validator)):
        raise ValueError("%s: validate_input должен быть синхронной проверкой без эффектов" % cap_id)
    with _executors_lock:
        if cap_id in _executors:
            raise ValueError("%s: исполнитель уже зарегистрирован" % cap_id)
        _executors[cap_id] = executor


def unregister_executor(capability_id: str) -> bool:
    """Снять исполнителя. True, если он был."""
    with _executors_lock:
        return _executors.pop(capability_id, None) is not None


def get_executor(capability_id: str) -> Optional[Any]:
    with _executors_lock:
        return _executors.get(capability_id)


def _any_executor() -> bool:
    with _executors_lock:
        return bool(_executors)


def _calls_json(executor: Any) -> List[Dict[str, Any]]:
    return [
        {"name": call.name, "side_effects": list(call.side_effects)}
        for call in executor.external_calls
    ]


# ---------- политика целевой возможности ----------

# Условия целевой возможности, которые конвейер плана действительно проверяет:
# базовые (ключ, привязка, сертификат, контур, контекст) и is_bound. Любое
# другое условие (membership, license, esia_token и прочие) ядро пока не
# проверяет, и возможность с ним не исполняется: ни prepare, ни execute.
TARGET_GATES = frozenset({*capabilities.BASE_MACHINE_GATES, "is_bound"})
# Право этапа плана. Остальные права целевой возможности нужны на обоих этапах.
STAGE_SCOPES = {"prepare": "external:prepare", "execute": "external:execute"}


def target_policy(cap: capabilities.Capability) -> Dict[str, Any]:
    """Политика целевой возможности в том виде, в каком она входит в план и хеш."""
    return {
        "capability_id": cap.id,
        "effect": cap.effect.value,
        "implemented": cap.implemented,
        "machine": cap.machine,
        "mcp_profile": cap.mcp_profile.value,
        "scopes": sorted(cap.scopes),
        "gates": sorted(cap.gates),
        "side_effects": sorted(cap.side_effects),
    }


def _policy_problem(cap: Optional[capabilities.Capability]) -> Optional[str]:
    """Почему целевую возможность исполнять нельзя, или None. Fail-closed."""
    if cap is None:
        return "capability_missing"
    if not cap.implemented:
        return "not_implemented"
    if cap.machine != "target":
        return "machine_not_target"
    if cap.mcp_profile is not capabilities.McpProfile.NONE:
        return "mcp_profile"
    if cap.effect not in (capabilities.Effect.READ_EXTERNAL, capabilities.Effect.WRITE_EXTERNAL):
        return "not_external"
    if not set(cap.gates) <= TARGET_GATES:
        return "unsupported_gates"
    return None


def stage_scopes(cap: capabilities.Capability, stage: str) -> frozenset:
    """Права ключа, нужные на этапе ``stage`` (prepare или execute) целевой возможности."""
    own = set(cap.scopes) - set(STAGE_SCOPES.values())
    return frozenset({STAGE_SCOPES[stage], *own})


def _require_scopes(
    principal: integration_auth.IntegrationPrincipal, cap: capabilities.Capability, stage: str
) -> None:
    if not stage_scopes(cap, stage) <= set(principal.scopes):
        raise ScopeMissing()


# ---------- сессия и контекст исполнения ----------

_session_provider: Optional[Callable[[], Any]] = None


def set_session_provider(provider: Optional[Callable[[], Any]]) -> None:
    """Зарегистрировать функцию, отдающую объект сессии оператора. None снимает её.

    Объект сессии ядро никуда не записывает: ни в план, ни в журнал, ни в repr.
    """
    global _session_provider
    _session_provider = provider


def _clock() -> datetime:
    return datetime.now(timezone.utc)


def _now_iso() -> str:
    return _clock().isoformat(timespec="seconds")


def _context_diff(planned: Dict[str, Any], live: operator_context.OperatorContext) -> Optional[str]:
    """Имя первого отличающегося поля контекста вида ``<поле>_changed`` или None."""
    current = live.public()
    for key in _CONTEXT_KEYS:
        if planned.get(key) != current.get(key):
            return key + "_changed"
    return None


def _credential_problem(client_id: str) -> Optional[str]:
    """Причина, по которой ключ уже нельзя использовать, или None. Без ``await``."""
    integration_auth._ensure()
    with auth_store.read() as db:
        row = db.execute(
            "SELECT revoked_at, expires_at FROM integration_clients WHERE id = ?", (client_id,)
        ).fetchone()
    if row is None:
        return "credential_missing"
    if row["revoked_at"]:
        return "credential_revoked"
    if row["expires_at"] <= _now_iso():
        return "credential_expired"
    return None


@dataclass(frozen=True, repr=False)
class ExecutionContext:
    """Снимок контекста захваченного плана для исполнителя.

    Содержит только идентификаторы и ``OperatorContext``. Провайдер сессии
    закрыт: в repr, сравнение и сериализацию он не входит.

    ``ensure_current`` синхронный. Он заново читает ключ, привязку и версию,
    живое состояние (сертификат, поколение, контур), политику целевой
    возможности и сравнивает со снимком плана. Гарантия действует лишь при
    вызове непосредственно перед внешним вызовом и без ``await`` между ними:
    тогда методы на цикле событий, меняющие сертификат или поколение,
    вклиниться не могут. Отзыв ключа и смену привязки из потока пула эта
    проверка не исключает, остаётся окно между проверкой и началом вызова.

    ``start_call`` делает ту же проверку и сразу записывает в журнал шагов,
    что вызов начат. ``mark_done`` записывает известное завершение и
    безопасную ссылку для сверки. Журнал пишется в базу сразу, а не после
    исполнения, поэтому переживает обрыв процесса.
    """

    plan_id: str
    client_id: str
    context: operator_context.OperatorContext
    _provider: Optional[Callable[[], Any]] = field(default=None, repr=False, compare=False)
    capability_id: str = ""
    target_policy: Dict[str, Any] = field(default_factory=dict, repr=False, compare=False)
    call_names: Tuple[str, ...] = ()

    def __repr__(self) -> str:
        return "ExecutionContext(plan_id=%r, client_id=%r, context=%r)" % (
            self.plan_id, self.client_id, self.context,
        )

    def ensure_current(self) -> None:
        problem = _credential_problem(self.client_id)
        if problem is not None:
            raise ContextChanged(problem)
        try:
            live = operator_context.capture()
        except operator_context.ContextUnavailable as err:
            raise ContextChanged(err.reason) from None
        reason = _context_diff(self.context.public(), live)
        if reason is not None:
            raise ContextChanged(reason)
        if self.capability_id:
            cap = capabilities.get(self.capability_id)
            if _policy_problem(cap) is not None or target_policy(cap) != self.target_policy:
                raise ContextChanged("policy_changed")

    def start_call(self, name: str) -> None:
        """Проверить контекст и записать в журнал, что внешний вызов ``name`` начат.

        Вызывается непосредственно перед внешним вызовом, без ``await`` между
        ними. Неизвестное или повторное имя это ``NotSent``: вызов не начат.
        Начатый раньше вызов без отметки ``mark_done`` это нарушение порядка:
        его исход неизвестен, и ядро завершает план как unknown.
        """
        # Порядок важен: незавершённый прежний вызов проверяется до любой
        # причины отказа, иначе отказ пометил бы его как не отправленный.
        _journal_check(self.plan_id)
        if name not in self.call_names:
            raise NotSent("unknown_call")
        self.ensure_current()
        if not _journal_start(self.plan_id, name):
            raise NotSent("call_already_recorded")

    def mark_done(self, name: str, reference: Optional[str] = None) -> None:
        """Записать известное завершение вызова ``name`` и ссылку для сверки.

        Ссылка это короткий идентификатор (номер, id у адресата), не ответ
        целиком. Запись вне алфавита ``[A-Za-z0-9._:/-]`` или длиннее
        128 знаков не сохраняется. Этот фильтр не распознаёт секреты:
        строка вида токена его проходит. Исполнитель обязан передавать
        только несекретное значение из разрешённого поля ответа адресата.
        """
        if name not in self.call_names:
            logger.warning("operation plan %s: mark_done for an undeclared call", self.plan_id)
            return
        _journal_done(self.plan_id, name, reference)

    def done(self) -> Tuple[str, ...]:
        return tuple(step["name"] for step in _journal(self.plan_id) if step["state"] == "completed")

    def session(self) -> Any:
        """Объект сессии от провайдера. Без провайдера внешний вызов не начинается."""
        if self._provider is None:
            raise NotSent("session_provider_unavailable")
        return self._provider()


# ---------- схема ----------

_ensured_for: Optional[str] = None


def _create_schema() -> None:
    """Создать таблицы планов. Повторный вызов ничего не меняет."""
    connection = auth_store._open()
    try:
        connection.executescript(_SCHEMA)
    finally:
        connection.close()


# Таблицы создаются вместе со схемой учётных записей.
if _create_schema not in auth_store.schema_hooks:
    auth_store.schema_hooks.append(_create_schema)


def _ensure() -> None:
    """Таблицы должны быть и тогда, когда база создана до загрузки модуля."""
    global _ensured_for
    auth_store.initialize_once()
    current = str(auth_store.db_path())
    if _ensured_for != current:
        _create_schema()
        _ensured_for = current


# ---------- хеши ----------


def _digest(value: Any) -> str:
    text = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _same(left: Any, right: Any) -> bool:
    if not isinstance(left, str) or not isinstance(right, str):
        return False
    return hmac.compare_digest(left.encode("utf-8"), right.encode("utf-8"))


def _body(
    *,
    client_id: str,
    capability_id: str,
    target: str,
    payload: bytes,
    attachments: Tuple[Tuple[str, bytes], ...],
    context: Dict[str, Any],
    external_calls: List[Dict[str, Any]],
    policy: Dict[str, Any],
) -> Dict[str, Any]:
    """Содержимое плана для хеша. Хеши и размеры считаются по байтам, не по записям."""
    return {
        "client_id": client_id,
        "capability_id": capability_id,
        "target": target,
        "payload_sha256": _sha256(payload),
        "attachments": [
            {"name": name, "sha256": _sha256(content), "size": len(content)}
            for name, content in attachments
        ],
        "context": {key: context.get(key) for key in _CONTEXT_KEYS},
        "external_calls": external_calls,
        "target_policy": policy,
    }


def _plan_hash(plan_id: str, expires_at: str, body: Dict[str, Any]) -> str:
    return _digest({**body, "plan_id": plan_id, "expires_at": expires_at})


# ---------- план ----------


@dataclass(frozen=True, repr=False)
class Plan:
    id: str
    client_id: str
    capability_id: str
    request_hash: str
    plan_hash: str
    target: str
    payload: bytes
    attachments: Tuple[Tuple[str, bytes], ...]
    context: Dict[str, Any]
    external_calls: List[Dict[str, Any]]
    target_policy: Dict[str, Any]
    status: str
    created_at: str
    expires_at: str
    approved_by: Optional[str]
    approved_at: Optional[str]
    approved_hash: Optional[str]
    claimed_at: Optional[str]
    finished_at: Optional[str]
    result: Any
    error_code: Optional[str]
    steps: List[Dict[str, Any]] = field(default_factory=list)

    def __repr__(self) -> str:
        # Байты и вложения в repr не входят.
        return "Plan(id=%r, capability_id=%r, status=%r, plan_hash=%r)" % (
            self.id, self.capability_id, self.status, self.plan_hash,
        )

    def recompute_hash(self) -> str:
        """Хеш плана, пересчитанный из сохранённых байтов и полей."""
        body = _body(
            client_id=self.client_id, capability_id=self.capability_id, target=self.target,
            payload=self.payload, attachments=self.attachments, context=self.context,
            external_calls=self.external_calls, policy=self.target_policy,
        )
        return _plan_hash(self.id, self.expires_at, body)

    def attachment_info(self) -> List[Dict[str, Any]]:
        return [
            {"name": name, "sha256": _sha256(content), "size": len(content)}
            for name, content in self.attachments
        ]


def _load(db, plan_id: str) -> Optional[Plan]:
    row = db.execute("SELECT * FROM operation_plans WHERE id = ?", (plan_id,)).fetchone()
    if row is None:
        return None
    parts = db.execute(
        "SELECT name, content FROM operation_plan_attachments WHERE plan_id = ? ORDER BY idx",
        (plan_id,),
    ).fetchall()
    return Plan(
        id=row["id"],
        client_id=row["client_id"],
        capability_id=row["capability_id"],
        request_hash=row["request_hash"],
        plan_hash=row["plan_hash"],
        target=row["target"],
        payload=bytes(row["payload"]),
        attachments=tuple((part["name"], bytes(part["content"])) for part in parts),
        context=dict(json.loads(row["context"])),
        external_calls=list(json.loads(row["external_calls"])),
        target_policy=dict(json.loads(row["target_policy"])),
        status=row["status"],
        created_at=row["created_at"],
        expires_at=row["expires_at"],
        approved_by=row["approved_by"],
        approved_at=row["approved_at"],
        approved_hash=row["approved_hash"],
        claimed_at=row["claimed_at"],
        finished_at=row["finished_at"],
        result=json.loads(row["result"]) if row["result"] is not None else None,
        error_code=row["error_code"],
        steps=_steps(db, plan_id),
    )


def get_plan(plan_id: str) -> Optional[Plan]:
    """План по id или None."""
    if not isinstance(plan_id, str) or _PLAN_ID_RE.fullmatch(plan_id) is None:
        return None
    _ensure()
    with auth_store.read() as db:
        return _load(db, plan_id)


def preview(plan: Plan) -> Dict[str, Any]:
    """Предпросмотр без байтов: то, что видит машина по своему плану."""
    return {
        "capability_id": plan.capability_id,
        "target": plan.target,
        "payload_sha256": _sha256(plan.payload),
        "payload_size": len(plan.payload),
        "attachments": plan.attachment_info(),
        "context": {key: plan.context.get(key) for key in _CONTEXT_KEYS},
        "external_calls": [
            {"name": call["name"], "side_effects": list(call["side_effects"])}
            for call in plan.external_calls
        ],
        "target_policy": dict(plan.target_policy),
    }


def plan_view(plan: Plan) -> Dict[str, Any]:
    """Машинный вид плана."""
    return {
        "plan_id": plan.id,
        "plan_hash": plan.plan_hash,
        "status": plan.status,
        "expires_at": plan.expires_at,
        "preview": preview(plan),
        "result": plan.result,
        "error_code": plan.error_code,
        "steps": [dict(step) for step in plan.steps],
    }


def admin_view(plan: Plan) -> Dict[str, Any]:
    """Точный предпросмотр для человека: включает байты и вложения."""
    info = plan.attachment_info()
    return {
        **plan_view(plan),
        "client_id": plan.client_id,
        "created_at": plan.created_at,
        "approved_by": plan.approved_by,
        "approved_at": plan.approved_at,
        "hash_verified": _same(plan.recompute_hash(), plan.plan_hash),
        "payload_b64": base64.b64encode(plan.payload).decode("ascii"),
        "attachment_contents": [
            {**meta, "content_b64": base64.b64encode(content).decode("ascii")}
            for meta, (_name, content) in zip(info, plan.attachments)
        ],
    }


# ---------- prepare ----------


def _executor_for(capability_id: Any) -> Tuple[Any, capabilities.Capability]:
    """Исполнитель и возможность с допустимой политикой, иначе ошибка 503."""
    executor = get_executor(capability_id) if isinstance(capability_id, str) else None
    if executor is None:
        raise ExecutorUnavailable()
    cap = capabilities.get(capability_id)
    problem = _policy_problem(cap)
    if problem is not None:
        raise ExecutorUnavailable("целевая возможность не допускается к исполнению: " + problem)
    return executor, cap


def _validate_input(
    target: Any,
    payload: Any,
    attachments: Any,
    idempotency_key: Any,
) -> Tuple[bytes, Tuple[Tuple[str, bytes], ...]]:
    if not isinstance(idempotency_key, str) or _IDEMPOTENCY_KEY_RE.fullmatch(idempotency_key) is None:
        raise InvalidRequest("idempotency_key: от 8 до 128 знаков из A-Za-z0-9._:-")
    if not integration_auth._is_ref_value(target):
        raise InvalidRequest("target должен быть ссылкой на адресата или объект")
    if not isinstance(payload, (bytes, bytearray)) or len(payload) > MAX_PAYLOAD_BYTES:
        raise InvalidRequest("payload: до %d байт" % MAX_PAYLOAD_BYTES)
    if not isinstance(attachments, (list, tuple)) or len(attachments) > MAX_ATTACHMENTS:
        raise InvalidRequest("вложений не больше %d" % MAX_ATTACHMENTS)
    total = len(payload)
    names = set()
    clean: List[Tuple[str, bytes]] = []
    for item in attachments:
        if not (isinstance(item, (list, tuple)) and len(item) == 2):
            raise InvalidRequest("вложение: пара (имя, байты)")
        name, content = item
        if not isinstance(name, str) or _ATTACHMENT_NAME_RE.fullmatch(name) is None:
            raise InvalidRequest("имя вложения: 1-100 знаков из A-Za-z0-9._-")
        if name in names:
            raise InvalidRequest("имена вложений не должны повторяться")
        if not isinstance(content, (bytes, bytearray)):
            raise InvalidRequest("содержимое вложения должно быть байтами")
        names.add(name)
        total += len(content)
        clean.append((name, bytes(content)))
    if total > MAX_TOTAL_BYTES:
        raise InvalidRequest("суммарный размер до %d байт" % MAX_TOTAL_BYTES)
    return bytes(payload), tuple(clean)


def prepare(
    principal: integration_auth.IntegrationPrincipal,
    snapshot: operator_context.OperatorContext,
    capability_id: str,
    target: str,
    payload: bytes,
    attachments: Any,
    idempotency_key: str,
) -> Tuple[Plan, bool]:
    """Записать план. Возвращает (план, создан_ли_новый).

    run исполнителя НЕ вызывается, ни один внешний вызов не выполняется, номер не
    резервируется. Опциональный validate_input только проверяет содержимое без
    эффектов, до записи плана. Тот же ключ идемпотентности с тем же запросом от того же
    ключа интеграции возвращает существующий план.

    Права и условия целевой возможности проверяются здесь же: план для
    операции, которую ключ исполнить не вправе, не записывается.
    """
    executor, cap = _executor_for(capability_id)
    _require_scopes(principal, cap, "prepare")
    if "is_bound" in cap.gates:
        snapshot = operator_context.authorize(principal, requires_is=True)
    clean_payload, clean_attachments = _validate_input(
        target, payload, attachments, idempotency_key
    )
    validator = getattr(executor, "validate_input", None)
    if validator is not None:
        try:
            validation_result = validator(clean_payload, clean_attachments, target)
        except InvalidRequest:
            raise
        except Exception:
            raise InvalidRequest("вход не прошёл проверку исполнителя") from None
        if validation_result is not None:
            if inspect.iscoroutine(validation_result):
                validation_result.close()
            raise InvalidRequest("проверка исполнителя должна завершаться без результата")
    context = snapshot.public()
    calls = _calls_json(executor)
    policy = target_policy(cap)
    body = _body(
        client_id=principal.id, capability_id=capability_id, target=target,
        payload=clean_payload, attachments=clean_attachments, context=context,
        external_calls=calls, policy=policy,
    )
    request_hash = _digest(body)
    _ensure()
    created = _clock()
    plan_id = "plan_" + secrets.token_hex(16)
    expires_at = (created + PLAN_TTL).isoformat(timespec="seconds")
    plan_hash = _plan_hash(plan_id, expires_at, body)
    with auth_store.write() as db:
        existing = db.execute(
            "SELECT id, client_id, request_hash FROM operation_plans WHERE idempotency_key = ?",
            (idempotency_key,),
        ).fetchone()
        if existing is not None:
            if existing["client_id"] != principal.id or not _same(
                existing["request_hash"], request_hash
            ):
                raise IdempotencyConflict()
            plan = _load(db, existing["id"])
            assert plan is not None
            return plan, False
        db.execute(
            "INSERT INTO operation_plans (id, client_id, capability_id, idempotency_key,"
            " request_hash, plan_hash, target, payload, payload_sha256, attachments, context,"
            " external_calls, target_policy, status, created_at, expires_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                plan_id, principal.id, capability_id, idempotency_key, request_hash, plan_hash,
                target, clean_payload, body["payload_sha256"],
                json.dumps(body["attachments"], ensure_ascii=False, sort_keys=True),
                json.dumps(body["context"], ensure_ascii=False, sort_keys=True),
                json.dumps(calls, ensure_ascii=False, sort_keys=True),
                json.dumps(policy, ensure_ascii=False, sort_keys=True),
                PLANNED, created.isoformat(timespec="seconds"), expires_at,
            ),
        )
        for idx, (name, content) in enumerate(clean_attachments):
            db.execute(
                "INSERT INTO operation_plan_attachments (plan_id, idx, name, content)"
                " VALUES (?, ?, ?, ?)",
                (plan_id, idx, name, content),
            )
        auth_store.audit(
            db,
            "operation_plan.prepare",
            detail={
                "plan_id": plan_id,
                "client_id": principal.id,
                "capability_id": capability_id,
                "target": target,
                "plan_hash": plan_hash,
                "payload_sha256": body["payload_sha256"],
                "payload_size": len(clean_payload),
                "attachments": len(clean_attachments),
            },
        )
        plan = _load(db, plan_id)
        assert plan is not None
        return plan, True


# ---------- approve ----------


def approve(plan_id: str, plan_hash: str, account_id: str) -> Plan:
    """Одобрение человеком. Только planned, не истёкший, с хешем из пересчёта.

    Одобряет администратор установки, и это может быть тот же человек, что
    выпустил ключ интеграции (self-approval). Это одобрение человеком по
    точному предпросмотру, а не независимое согласование «в четыре глаза».
    Целевые условия и права возможности одобрение не заменяет.
    """
    _ensure()
    if not isinstance(plan_id, str) or _PLAN_ID_RE.fullmatch(plan_id) is None:
        raise PlanNotFound()
    with auth_store.write() as db:
        plan = _load(db, plan_id)
        if plan is None:
            raise PlanNotFound()
        if plan.status != PLANNED:
            raise PlanStateError()
        moment = _now_iso()
        if plan.expires_at <= moment:
            raise PlanExpired()
        recomputed = plan.recompute_hash()
        if not (_same(plan_hash, recomputed) and _same(plan_hash, plan.plan_hash)):
            raise PlanHashMismatch()
        changed = db.execute(
            "UPDATE operation_plans SET status = ?, approved_by = ?, approved_at = ?,"
            " approved_hash = ? WHERE id = ? AND status = ?",
            (APPROVED, account_id, moment, recomputed, plan_id, PLANNED),
        ).rowcount
        if changed != 1:
            raise PlanStateError()
        auth_store.audit(
            db,
            "operation_plan.approve",
            account_id=account_id,
            detail={
                "plan_id": plan_id,
                "client_id": plan.client_id,
                "capability_id": plan.capability_id,
                "plan_hash": recomputed,
            },
        )
        approved = _load(db, plan_id)
        assert approved is not None
        return approved


# ---------- захват и завершение ----------


def claim_plan(
    plan_id: str,
    approved_hash: str,
    client_id: str,
    context: operator_context.OperatorContext,
) -> int:
    """Точка захвата: approved -> inflight одной транзакцией. Возвращает rowcount.

    Условия в самом UPDATE: план этого ключа, статус approved, хеш одобрения,
    срок плана, версия и значения привязки, ключ не отозван и не истёк. Из двух конкурентных
    вызовов rowcount 1 только у одного. Сертификат, поколение и контур в базе
    не хранятся и здесь не проверяются (см. docstring модуля).

    Момент для сроков берётся уже внутри транзакции, после ``BEGIN IMMEDIATE``:
    время ожидания чужой записи не продлевает срок плана и ключа.
    """
    _ensure()
    with auth_store.write() as db:
        moment = _now_iso()
        changed = db.execute(
            "UPDATE operation_plans SET status = 'inflight', claimed_at = ?"
            " WHERE id = ? AND client_id = ? AND status = 'approved' AND approved_hash = ?"
            " AND expires_at > ?"
            " AND (SELECT epoch FROM operator_binding_epoch WHERE id = 1) = ?"
            " AND EXISTS (SELECT 1 FROM operator_binding WHERE id = 1 AND organization_ref = ?"
            " AND contour = ? AND certificate_thumbprint = ? AND is_ref IS ?)"
            " AND EXISTS (SELECT 1 FROM integration_clients WHERE id = ? AND revoked_at IS NULL"
            " AND expires_at > ?)",
            (
                moment, plan_id, client_id, approved_hash, moment, context.binding_epoch,
                context.organization_ref, context.contour, context.certificate_thumbprint,
                context.is_ref, client_id, moment,
            ),
        ).rowcount
        if changed == 1:
            auth_store.audit(
                db, "operation_plan.claim",
                detail={"plan_id": plan_id, "client_id": client_id},
            )
        return changed


def _explain_claim_failure(plan_id: str, client_id: str) -> OperationError:
    """Точная причина отказа захвата: повторное чтение плана после rowcount 0."""
    plan = get_plan(plan_id)
    if plan is None or plan.client_id != client_id:
        return PlanNotFound()
    if plan.status == INFLIGHT:
        return PlanInflight()
    if plan.status != APPROVED:
        return PlanStateError()
    if plan.expires_at <= _now_iso():
        return PlanExpired()
    if _credential_problem(client_id) is not None:
        return CredentialInvalid()
    if not _same(plan.approved_hash, plan.recompute_hash()):
        return PlanHashMismatch()
    binding = operator_context.get_binding()
    if binding is None:
        return ContextChanged("binding_removed")
    if binding.epoch != plan.context.get("binding_epoch"):
        return ContextChanged("binding_epoch_changed")
    return ContextChanged("binding_changed")


# ---------- журнал шагов ----------

_REFERENCE_RE = re.compile(r"[A-Za-z0-9._:/-]{1,128}")


def _steps(db, plan_id: str) -> List[Dict[str, Any]]:
    rows = db.execute(
        "SELECT name, state, reference, started_at, finished_at FROM operation_plan_steps"
        " WHERE plan_id = ? ORDER BY seq",
        (plan_id,),
    ).fetchall()
    return [dict(row) for row in rows]


def _journal(plan_id: str) -> List[Dict[str, Any]]:
    with auth_store.read() as db:
        return _steps(db, plan_id)


def _safe_reference(reference: Any) -> Optional[str]:
    if reference is None:
        return None
    if isinstance(reference, str) and _REFERENCE_RE.fullmatch(reference):
        return reference
    logger.warning("operation plan step: reference rejected, only a short id is stored")
    return None


def _check_journal_state(db, plan_id: str) -> None:
    plan = db.execute("SELECT status FROM operation_plans WHERE id = ?", (plan_id,)).fetchone()
    if plan is None or plan["status"] != INFLIGHT:
        raise ContextChanged("plan_not_inflight")
    if db.execute(
        "SELECT 1 FROM operation_plan_steps WHERE plan_id = ? AND state = 'started'", (plan_id,)
    ).fetchone() is not None:
        raise RuntimeError("предыдущий внешний вызов начат, но его исход не записан")


def _journal_check(plan_id: str) -> None:
    """План ещё inflight, и нет начатого вызова без записанного исхода."""
    with auth_store.read() as db:
        _check_journal_state(db, plan_id)


def _journal_start(plan_id: str, name: str) -> bool:
    """Записать начало вызова. False, если этот вызов уже есть в журнале.

    Запись идёт только пока план inflight: после восстановления (unknown)
    журнал не пополняется, и вызов не начинается.
    """
    with auth_store.write() as db:
        _check_journal_state(db, plan_id)
        if db.execute(
            "SELECT 1 FROM operation_plan_steps WHERE plan_id = ? AND name = ?", (plan_id, name)
        ).fetchone() is not None:
            return False
        seq = db.execute(
            "SELECT COUNT(*) FROM operation_plan_steps WHERE plan_id = ?", (plan_id,)
        ).fetchone()[0]
        db.execute(
            "INSERT INTO operation_plan_steps (plan_id, seq, name, state, started_at)"
            " VALUES (?, ?, ?, 'started', ?)",
            (plan_id, seq, name, _now_iso()),
        )
    return True


def _journal_done(plan_id: str, name: str, reference: Any) -> None:
    """Записать известное завершение. Без start_call шаг записывается сразу завершённым."""
    ref = _safe_reference(reference)
    moment = _now_iso()
    with auth_store.write() as db:
        changed = db.execute(
            "UPDATE operation_plan_steps SET state = 'completed', reference = ?, finished_at = ?"
            " WHERE plan_id = ? AND name = ? AND state = 'started'",
            (ref, moment, plan_id, name),
        ).rowcount
        if changed:
            return
        if db.execute(
            "SELECT 1 FROM operation_plan_steps WHERE plan_id = ? AND name = ?", (plan_id, name)
        ).fetchone() is not None:
            logger.warning("operation plan %s: step %s is already finished", plan_id, name)
            return
        seq = db.execute(
            "SELECT COUNT(*) FROM operation_plan_steps WHERE plan_id = ?", (plan_id,)
        ).fetchone()[0]
        db.execute(
            "INSERT INTO operation_plan_steps"
            " (plan_id, seq, name, state, reference, started_at, finished_at)"
            " VALUES (?, ?, ?, 'completed', ?, ?, ?)",
            (plan_id, seq, name, ref, moment, moment),
        )


def _mark_not_sent(db, plan_id: str) -> None:
    # Исполнитель подтвердил (NotSent, ContextChanged), что начатый вызов не ушёл.
    db.execute(
        "UPDATE operation_plan_steps SET state = 'not_sent', finished_at = ?"
        " WHERE plan_id = ? AND state = 'started'",
        (_now_iso(), plan_id),
    )


def _outcome(db, plan_id: str) -> Dict[str, List[str]]:
    """Известные завершённые вызовы и начатые вызовы с неизвестным исходом."""
    steps = _steps(db, plan_id)
    return {
        "completed_calls": [step["name"] for step in steps if step["state"] == "completed"],
        "uncertain_calls": [step["name"] for step in steps if step["state"] == "started"],
    }


def _finish(
    plan_id: str,
    status: str,
    *,
    error_code: Optional[str] = None,
    result: Optional[Dict[str, Any]] = None,
    not_sent: bool = False,
) -> Dict[str, List[str]]:
    """Завершение отдельной транзакцией: inflight -> succeeded, failed или unknown.

    Для failed и unknown результат собирается из журнала шагов той же
    транзакцией. Возвращает этот отчёт (completed_calls, uncertain_calls).
    """
    with auth_store.write() as db:
        if not_sent:
            _mark_not_sent(db, plan_id)
        outcome = _outcome(db, plan_id)
        if status == FAILED:
            result = {"completed_calls": outcome["completed_calls"]} if outcome["completed_calls"] else None
        elif status == UNKNOWN:
            result = outcome
        encoded = json.dumps(result, ensure_ascii=False, sort_keys=True) if result is not None else None
        changed = db.execute(
            "UPDATE operation_plans SET status = ?, finished_at = ?, result = ?, error_code = ?"
            " WHERE id = ? AND status = 'inflight'",
            (status, _now_iso(), encoded, error_code, plan_id),
        ).rowcount
        if changed == 1:
            auth_store.audit(
                db, "operation_plan.finish",
                detail={"plan_id": plan_id, "status": status, "error_code": error_code or ""},
            )
    if changed != 1:
        logger.warning("operation plan %s: finish %s skipped, status is not inflight", plan_id, status)
    return outcome


def recover_inflight() -> int:
    """Все inflight -> unknown (``interrupted``). Вызывается при старте приложения.

    В approved такой план не возвращается никогда: внешний вызов мог быть
    принят. Результатом становится отчёт журнала шагов: известные завершённые
    вызовы и начатые с неизвестным исходом. Если файла базы ещё нет,
    восстанавливать нечего, и он не создаётся.
    """
    if not auth_store.db_path().exists():
        return 0
    _ensure()
    moment = _now_iso()
    with auth_store.write() as db:
        rows = db.execute("SELECT id FROM operation_plans WHERE status = 'inflight'").fetchall()
        for row in rows:
            outcome = json.dumps(_outcome(db, row["id"]), ensure_ascii=False, sort_keys=True)
            db.execute(
                "UPDATE operation_plans SET status = 'unknown', finished_at = ?, error_code = ?,"
                " result = ? WHERE id = ? AND status = 'inflight'",
                (moment, "interrupted", outcome, row["id"]),
            )
            auth_store.audit(
                db, "operation_plan.recover",
                detail={"plan_id": row["id"], "status": UNKNOWN, "error_code": "interrupted"},
            )
    return len(rows)


# ---------- execute ----------


def _replay(plan: Plan) -> Dict[str, Any]:
    return {"plan_id": plan.id, "status": plan.status, "result": plan.result}


async def execute(
    principal: integration_auth.IntegrationPrincipal, plan_id: str, plan_hash: str
) -> Dict[str, Any]:
    """Исполнить одобренный план на исполнителе. Выполняется на цикле событий.

    До захвата проверки идут синхронно, без ``await``: между проверкой живого
    состояния и транзакцией захвата управление не уходит другим задачам цикла.
    Исполнитель получает только ``ExecutionContext`` захваченного снимка.
    """
    if not _any_executor():
        raise ExecutorUnavailable()
    _ensure()
    # ---- до захвата: ни одного await ----
    plan = get_plan(plan_id)
    if plan is None or plan.client_id != principal.id:
        raise PlanNotFound()
    if plan.status == SUCCEEDED:
        if not _same(plan_hash, plan.approved_hash):
            raise PlanHashMismatch()
        return _replay(plan)
    if plan.status == INFLIGHT:
        raise PlanInflight()
    if plan.status in (FAILED, UNKNOWN):
        raise PlanStateError()
    moment = _now_iso()
    if plan.expires_at <= moment:
        raise PlanExpired()
    if plan.status != APPROVED:
        raise PlanStateError()
    recomputed = plan.recompute_hash()
    if not (
        _same(plan_hash, plan.approved_hash)
        and _same(plan.approved_hash, recomputed)
        and _same(plan.plan_hash, recomputed)
    ):
        raise PlanHashMismatch()
    executor, cap = _executor_for(plan.capability_id)
    if _calls_json(executor) != plan.external_calls:
        raise ExecutorUnavailable("исполнитель изменился после подготовки плана")
    # Политика целевой возможности проверяется заново: старый план не обходит
    # добавленное условие, снятый допуск или недостающее право.
    if target_policy(cap) != plan.target_policy:
        raise PolicyChanged()
    _require_scopes(principal, cap, "execute")
    snapshot = operator_context.authorize(principal, requires_is="is_bound" in cap.gates)
    reason = _context_diff(plan.context, snapshot)
    if reason is not None:
        raise ContextChanged(reason)
    if claim_plan(plan.id, plan.approved_hash, principal.id, snapshot) != 1:
        raise _explain_claim_failure(plan.id, principal.id)

    # ---- план захвачен: дальше только исполнитель ----
    known = tuple(call["name"] for call in plan.external_calls)
    ctx = ExecutionContext(
        plan.id, plan.client_id, snapshot, _provider=_session_provider,
        capability_id=plan.capability_id, target_policy=dict(plan.target_policy),
        call_names=known,
    )
    try:
        result = await executor.run(ctx, plan.payload, plan.attachments, plan.target)
    except ExecutionAborted as err:
        for name in err.completed:
            if name in known:
                _journal_done(plan.id, name, None)
        outcome = _finish(plan.id, FAILED, error_code=err.error_code, not_sent=True)
        err.with_completed(tuple(outcome["completed_calls"]))
        logger.info("operation plan %s failed: %s", plan.id, err.error_code)
        raise
    except BaseException as err:
        # Начатый вызов мог уйти: исход неизвестен, повтора нет.
        outcome = _finish(plan.id, UNKNOWN, error_code="outcome_unknown")
        logger.warning("operation plan %s outcome unknown: %s", plan.id, type(err).__name__)
        if isinstance(err, (asyncio.CancelledError, KeyboardInterrupt, SystemExit)):
            raise
        raise OutcomeUnknown(
            plan.id, tuple(outcome["completed_calls"]), tuple(outcome["uncertain_calls"])) from None
    problem = None
    if not isinstance(result, dict):
        problem = "result is not an object"
    else:
        try:
            json.dumps(result, ensure_ascii=False, sort_keys=True)
        except (TypeError, ValueError):
            problem = "result is not serializable"
    if problem is not None:
        outcome = _finish(plan.id, UNKNOWN, error_code="outcome_unknown")
        logger.warning("operation plan %s outcome unknown: %s", plan.id, problem)
        raise OutcomeUnknown(
            plan.id, tuple(outcome["completed_calls"]), tuple(outcome["uncertain_calls"]))
    _finish(plan.id, SUCCEEDED, result=result)
    logger.info("operation plan %s succeeded", plan.id)
    return {"plan_id": plan.id, "status": SUCCEEDED, "result": result}
