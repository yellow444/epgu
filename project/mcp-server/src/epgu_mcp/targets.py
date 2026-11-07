"""Каталог целевых tools операций: описание будущих tools, а не действующие tools.

Здесь описаны ``plan_prepare``, ``plan_get`` и ``plan_execute`` (status=target,
available=false). У описания нет handler: из него нельзя получить ToolSpec, и
ни один штатный профиль (knowledge, read, operate) их не выдаёт через
list_tools или call_tool. Имена зарезервированы: ``add_tool`` и ``merge``
отказывают tool с таким именем в любом профиле, в том числе из расширения.
Исполняемые спецификации строит только ``operations.py`` из этого каталога для
явно собранного тестового сервера на mock backend; включение в штатный профиль
это отдельное решение, а не следствие этого описания.

Выходные схемы строгие (additionalProperties=false) и описывают результат
явной проекции ``operations.py``, а не ответ backend как есть.

Будущий вызов идёт только через HTTP-клиент backend
(``epgu.integration.IntegrationClient``) с ключом интеграции, который задаёт
конфигурация процесса. Ключ, cookie человека и одобрение не являются
аргументами tool. Одобрение и предпросмотр администратора (operation.approve,
operation.review) не становятся tools ни в каком профиле. Прямого доступа к
базе, глобального состояния backend и локальной подписи у этих tools нет.

Аннотации описывают характер действия и не заменяют политику backend:
scopes, привязку оператора, хеш плана и одобрение проверяет сервер.
"""
from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from typing import Any

TARGET_STATUS = "target"

# Подстроки, которых не может быть в имени аргумента целевого tool.
FORBIDDEN_ARGUMENT_PARTS = (
    "approve", "admin", "review", "cookie", "session", "credential", "secret",
    "token", "bearer", "authorization", "password", "pin", "api_key", "apikey",
    "private_key", "certificate", "thumbprint", "signature", "base_url", "url",
)

_PLAN_ID = {
    "type": "string", "pattern": "^plan_[0-9a-f]{32}$",
    "description": "Идентификатор плана из plan_prepare.",
}
_HEX64 = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
_STR = {"type": "string"}
_STR_LIST = {"type": "array", "items": _STR}
_NSTR = {"type": ["string", "null"]}
_NAME = {"type": "string", "pattern": "^[a-z][a-z0-9_]{0,63}$"}
_NAME_LIST = {"type": "array", "items": _NAME}
_STATUS = {"enum": ["planned", "approved", "inflight", "succeeded", "failed", "unknown"]}


def _strict(props: dict[str, Any], required: list[str]) -> dict[str, Any]:
    return {"type": "object", "properties": props, "required": required, "additionalProperties": False}


def _out(props: dict[str, Any]) -> dict[str, Any]:
    """Выход проекции: все поля обязательны, лишних нет."""
    return _strict(props, list(props))


# Что проекция не выдала: результат исполнителя без описанных полей и ссылки шагов.
_WITHHELD = {"type": "array", "items": {"enum": ["result", "step_references"]}, "uniqueItems": True}

# Результат плана: null, журнал вызовов (failed, unknown) или плоские поля, описанные
# для возможности в проекции. Вложенных объектов и сырого ответа исполнителя нет.
_SCALAR = {"anyOf": [{"type": "string", "maxLength": 256}, {"type": "boolean"}, {"type": "integer"},
                     {"type": "null"}]}
_RESULT = {"anyOf": [
    {"type": "null"},
    {"type": "object", "properties": {"completed_calls": _NAME_LIST, "uncertain_calls": _NAME_LIST},
     "additionalProperties": False},
    {"type": "object", "maxProperties": 32, "propertyNames": {"pattern": "^[a-z][a-z0-9_]{0,63}$"},
     "additionalProperties": _SCALAR},
]}


_PREVIEW = _out(
    {
        "capability_id": _STR,
        "target": _STR,
        "payload_sha256": _HEX64,
        "payload_size": {"type": "integer", "minimum": 0},
        "attachments": {
            "type": "array",
            "items": _out({"name": _STR, "sha256": _HEX64, "size": {"type": "integer", "minimum": 0}}),
        },
        "context": _out(
            {
                "contour": _STR, "organization_ref": _STR, "is_ref": _NSTR,
                "certificate_thumbprint": _STR, "generation": {"type": "integer"},
                "binding_epoch": {"type": "integer"},
            },
        ),
        "external_calls": {
            "type": "array",
            "items": _out({"name": _NAME, "side_effects": _STR_LIST}),
        },
        "target_policy": _out(
            {
                "capability_id": _STR, "effect": _STR, "implemented": {"type": "boolean"},
                "machine": _STR, "mcp_profile": _STR, "scopes": _STR_LIST, "gates": _STR_LIST,
                "side_effects": _STR_LIST,
            },
        ),
    },
)

# Проекция PlanOut backend: без байтов документа и без полей администратора.
_PLAN_PROPS = {
    "plan_id": _PLAN_ID,
    "plan_hash": _HEX64,
    "status": _STATUS,
    "expires_at": _STR,
    "preview": _PREVIEW,
    "result": _RESULT,
    "error_code": _NSTR,
    "steps": {
        "type": "array",
        "items": _out(
            {"name": _NAME, "state": {"enum": ["started", "completed", "not_sent"]},
             "reference": _NSTR, "started_at": _STR, "finished_at": _NSTR},
        ),
    },
    "withheld": _WITHHELD,
}
_PLAN = _out(_PLAN_PROPS)
_PREPARE_OUT = _out({**_PLAN_PROPS, "created": {"type": "boolean"}})

# Результат исполнения не копируется: его проекция читается через plan_get.
_EXECUTE_OUT = _out({"plan_id": _PLAN_ID, "status": {"const": "succeeded"}, "withheld": _WITHHELD})

# Пределы повторяют operations.py (payload до 1 000 000 байт, все вложения вместе до
# 2 000 000, не больше 5 вложений). Окончательно их проверяет backend.
def _b64(max_bytes: int) -> dict[str, Any]:
    return {"type": "string", "contentEncoding": "base64", "maxLength": 4 * -(-max_bytes // 3)}


# Коды ошибок, которые tool отдаёт как результат с isError=true: коды problem+json
# backend, коды HTTP-клиента 4a (transport_error, unexpected_response) и
# configuration_error адаптера (нет или неверна конфигурация, запрос не отправлялся).
_COMMON_ERRORS = ("invalid_parameter", "unauthenticated", "forbidden", "rate_limited",
                  "context_unavailable", "context_mismatch", "transport_error",
                  "unexpected_response", "configuration_error")


@dataclass(frozen=True)
class TargetTool:
    """Описание будущего tool. Исполняемой части нет."""

    name: str
    title: str
    description: str
    capability_id: str
    profile: str
    scopes: tuple[str, ...]
    input_schema: dict[str, Any] = field(repr=False)
    output_schema: dict[str, Any] = field(repr=False)
    read_only: bool
    destructive: bool
    idempotent: bool
    open_world: bool
    error_codes: tuple[str, ...]
    status: str = TARGET_STATUS
    available: bool = False

    def __post_init__(self) -> None:
        if self.status != TARGET_STATUS or self.available is not False:
            raise ValueError(f"{self.name}: целевой tool не может быть доступен")

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        return json.loads(json.dumps(data))


TARGET_TOOLS: tuple[TargetTool, ...] = (
    TargetTool(
        name="plan_prepare",
        title="Подготовка плана операции",
        description=(
            "Записывает на backend план внешней операции и возвращает его предпросмотр. "
            "Исполнитель не вызывается. План исполняется только после одобрения человеком "
            "в интерфейсе. Повтор с тем же idempotency_key и тем же телом возвращает тот же "
            "план (created=false); ключ при повторе не меняется."
        ),
        capability_id="operation.prepare",
        profile="operate",
        scopes=("external:prepare",),
        input_schema=_strict(
            {
                "capability_id": {"type": "string", "minLength": 1, "maxLength": 1000},
                "target": {"type": "string", "minLength": 1, "maxLength": 1000},
                "payload_b64": _b64(1_000_000),
                "attachments": {
                    "type": "array", "maxItems": 5,
                    "items": _strict({"name": {"type": "string", "pattern": "^[A-Za-z0-9._-]{1,100}$"},
                                      "content_b64": _b64(2_000_000)}, ["name", "content_b64"]),
                },
                "idempotency_key": {"type": "string", "pattern": "^[A-Za-z0-9._:-]{8,128}$"},
            },
            ["capability_id", "target", "payload_b64", "idempotency_key"],
        ),
        output_schema=_PREPARE_OUT,
        # Пишет локальный план: не read-only. Внешних вызовов нет.
        read_only=False, destructive=False, idempotent=True, open_world=False,
        error_codes=(*_COMMON_ERRORS, "idempotency_conflict", "executor_unavailable"),
    ),
    TargetTool(
        name="plan_get",
        title="План операции",
        description=(
            "Свой план со статусом, результатом и журналом шагов. Байтов документа нет; "
            "результат и ссылки шагов выдаются только в описанных полях, остальное "
            "отмечено в withheld. После неизвестного исхода execute это единственный способ уточнить состояние; "
            "ошибка чтения не отменяет неизвестный исход."
        ),
        capability_id="operation.plan.get",
        profile="operate",
        scopes=("external:prepare",),
        input_schema=_strict({"plan_id": _PLAN_ID}, ["plan_id"]),
        output_schema=_PLAN,
        read_only=True, destructive=False, idempotent=True, open_world=False,
        error_codes=(*_COMMON_ERRORS, "plan_not_found"),
    ),
    TargetTool(
        name="plan_execute",
        title="Исполнение одобренного плана",
        description=(
            "Исполняет план, одобренный человеком, с хешем этого плана. Результат после "
            "успеха читается через plan_get. Повтора нет ни при каком исходе. При outcome_unknown (в том числе без ответа сервера) внешняя "
            "операция могла выполниться: сверить состояние через plan_get, не вызывать "
            "execute снова."
        ),
        capability_id="operation.execute",
        profile="operate",
        scopes=("external:execute",),
        input_schema=_strict({"plan_id": _PLAN_ID, "plan_hash": _HEX64}, ["plan_id", "plan_hash"]),
        output_schema=_EXECUTE_OUT,
        read_only=False, destructive=True, idempotent=False, open_world=True,
        # transport_error и unexpected_response у execute приходят как outcome_unknown
        # клиента: сервер мог исполнить план.
        error_codes=(*_COMMON_ERRORS, "plan_not_found", "plan_state", "plan_inflight",
                     "plan_hash_mismatch", "plan_expired", "policy_changed", "context_changed",
                     "execution_failed", "executor_unavailable", "outcome_unknown"),
    ),
)

RESERVED_NAMES = frozenset(t.name for t in TARGET_TOOLS)


def catalog() -> list[dict[str, Any]]:
    """Копия каталога как данные (изменение копии не влияет на каталог)."""
    return [t.to_dict() for t in TARGET_TOOLS]
