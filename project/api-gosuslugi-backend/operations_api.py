"""HTTP-часть планов внешних операций (prepare, approve, execute).

Машинные маршруты (ключ интеграции, Bearer; cookie не принимается) регистрируются
в ``auth_api.machine_endpoints`` и зависят от ``machine_api.require_machine``
своей возможности:

- ``POST /v1/operations/plans`` - prepare, только записывает план;
- ``GET /v1/operations/plans/{plan_id}`` - свой план;
- ``POST /v1/operations/plans/{plan_id}/execute`` - исполнение одобренного плана.

Человеческие маршруты (обычная сессия, ``auth_api.require_admin``; ключ их не
открывает и в MCP их нет):

- ``GET /v1/admin/operations/plans/{plan_id}`` - точный предпросмотр с байтами;
- ``POST /v1/admin/operations/plans/{plan_id}/approve`` - одобрение.

Встроенных исполнителей нет: без зарегистрированного исполнителя prepare и
execute отвечают 503 ``executor_unavailable``. Ошибки идут как problem+json.
"""

from __future__ import annotations

import base64
import binascii
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, Path, Request, Response
from pydantic import BaseModel, ConfigDict, Field, StrictStr

import auth_api
import machine_api
import operations
import operator_context
from auth import Account
from v1_errors import NO_STORE_HEADERS, PROBLEM_MEDIA_TYPE, problem_schema, V1Error, set_version_header

PLAN_ID = r"^plan_[0-9a-f]{32}$"
# Запас по длине записи base64: настоящий предел по байтам проверяет operations (400).
_B64_LIMIT = 8_000_000

_PROBLEM_SCHEMA = problem_schema()


def _problem(description: str) -> Dict[str, Any]:
    return {"description": description,
            "content": {PROBLEM_MEDIA_TYPE: {"schema": _PROBLEM_SCHEMA}}}


_PLAN_PROBLEMS: Dict[int, Dict[str, Any]] = {
    400: _problem("Недопустимое значение (invalid_parameter)"),
    403: _problem("У ключа нет нужного разрешения маршрута или целевой операции "
                  "(forbidden, insufficient_scope)"),
    404: _problem("План не найден (plan_not_found)"),
    409: _problem(
        "Контекст оператора недоступен (context_unavailable) или не совпадает с контекстом "
        "ключа (context_mismatch), контекст или привязка изменились (context_changed), хеш "
        "плана не совпадает (plan_hash_mismatch), план в другом состоянии (plan_state), "
        "план уже исполняется (plan_inflight), ключ идемпотентности занят другим запросом "
        "(idempotency_conflict), исполнитель отказал до начала вызова (execution_failed), "
        "политика целевой возможности изменилась после подготовки (policy_changed)"
    ),
    410: _problem("Срок плана истёк (plan_expired)"),
    422: _problem("Тело или параметр не того типа или формы"),
    502: _problem("Результат внешней операции неизвестен (outcome_unknown), повтор не выполняется. "
                  "Поле outcome: plan_id, точно выполненные вызовы (completed_calls) и вызовы "
                  "с неизвестным исходом (uncertain_calls) из журнала шагов"),
    503: _problem("Исполнитель не настроен или целевая возможность не допускается к "
                  "исполнению (executor_unavailable)"),
}
_ADMIN_PLAN_PROBLEMS: Dict[int, Dict[str, Any]] = {
    401: _problem("Нужен вход"),
    403: _problem("Нужны права администратора установки"),
    404: _problem("План не найден (plan_not_found)"),
    409: _problem("Хеш не совпадает (plan_hash_mismatch) или план в другом состоянии (plan_state)"),
    410: _problem("Срок плана истёк (plan_expired)"),
    422: _problem("Тело или параметр не того типа или формы"),
}


# ---------- модели ----------


class AttachmentIn(BaseModel):
    # Строгие типы на границе: без приведения. Значения проверяет operations (400).
    model_config = ConfigDict(extra="forbid")

    name: StrictStr
    content_b64: StrictStr = Field(max_length=_B64_LIMIT)


class PrepareIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    capability_id: StrictStr = Field(max_length=1000)
    target: StrictStr = Field(max_length=1000)
    payload_b64: StrictStr = Field(max_length=_B64_LIMIT)
    attachments: List[AttachmentIn] = Field(default_factory=list, max_length=50)
    idempotency_key: StrictStr = Field(max_length=1000)


class PlanHashIn(BaseModel):
    model_config = ConfigDict(extra="forbid")

    plan_hash: StrictStr = Field(max_length=256)


class AttachmentInfo(BaseModel):
    name: str
    sha256: str
    size: int


class ExternalCallOut(BaseModel):
    name: str
    side_effects: List[str]


class PlanContextOut(BaseModel):
    contour: str
    organization_ref: str
    is_ref: Optional[str] = None
    certificate_thumbprint: str
    generation: int
    binding_epoch: int


class TargetPolicyOut(BaseModel):
    capability_id: str
    effect: str
    implemented: bool
    machine: str
    mcp_profile: str
    scopes: List[str]
    gates: List[str]
    side_effects: List[str]


class PreviewOut(BaseModel):
    capability_id: str
    target: str
    payload_sha256: str
    payload_size: int
    attachments: List[AttachmentInfo]
    context: PlanContextOut
    external_calls: List[ExternalCallOut]
    target_policy: TargetPolicyOut


class StepOut(BaseModel):
    name: str
    state: str
    reference: Optional[str] = None
    started_at: str
    finished_at: Optional[str] = None


class PlanOut(BaseModel):
    plan_id: str
    plan_hash: str
    status: str
    expires_at: str
    preview: PreviewOut
    result: Optional[Dict[str, Any]] = None
    error_code: Optional[str] = None
    steps: List[StepOut] = Field(default_factory=list)


class AdminAttachment(AttachmentInfo):
    content_b64: str


class AdminPlanOut(PlanOut):
    client_id: str
    created_at: str
    approved_by: Optional[str] = None
    approved_at: Optional[str] = None
    hash_verified: bool
    payload_b64: str
    attachment_contents: List[AdminAttachment]


class ExecuteOut(BaseModel):
    plan_id: str
    status: str
    result: Optional[Dict[str, Any]] = None


# ---------- перевод ошибок ----------


def _v1(err: operations.OperationError) -> V1Error:
    headers = None
    outcome = None
    if isinstance(err, operations.OutcomeUnknown):
        outcome = err.outcome
    if isinstance(err, operations.CredentialInvalid):
        headers = {"WWW-Authenticate": "Bearer"}
    elif isinstance(err, operations.ScopeMissing):
        headers = {"WWW-Authenticate": 'Bearer error="insufficient_scope"'}
    return V1Error(err.code, err.http_status, err.detail, headers=headers, outcome=outcome)


def _context_error(err: Exception) -> V1Error:
    if isinstance(err, operator_context.ContextUnavailable):
        return V1Error(machine_api.CONTEXT_UNAVAILABLE, 409, err.reason)
    return V1Error(machine_api.CONTEXT_MISMATCH, 409, machine_api._MISMATCH_DETAIL)


def _decode(value: str, what: str, limit: int) -> bytes:
    # Длина записи проверяется до разбора: гигантскую строку не раскодируем.
    if len(value) > ((limit + 2) // 3) * 4:
        raise operations.InvalidRequest("%s: слишком большой размер" % what)
    try:
        return base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError):
        raise operations.InvalidRequest("%s: нужна запись base64" % what) from None


def _principal(request: Request):
    return request.state.integration


# ---------- машинные маршруты ----------


def machine_router() -> APIRouter:
    router = APIRouter(
        prefix="/v1/operations", tags=["v1-operations"],
        dependencies=[Depends(set_version_header)],
        responses={**machine_api.MACHINE_PROBLEMS, **_PLAN_PROBLEMS},
    )

    @router.post("/plans", response_model=PlanOut, status_code=200,
                 responses={201: {"model": PlanOut, "description": "Новый план записан"}},
                 summary="Подготовить план внешней операции (только запись плана)",
                 description="Исполнитель не вызывается, внешние действия не выполняются, номер "
                             "не резервируется. План исполняется только после одобрения человеком. "
                             "201 для нового плана, 200 при повторе по ключу идемпотентности.")
    def prepare_plan(
        body: PrepareIn,
        request: Request,
        response: Response,
        snapshot: operator_context.OperatorContext = Depends(
            machine_api.require_machine("operation.prepare")),
    ):
        try:
            payload = _decode(body.payload_b64, "payload_b64", operations.MAX_PAYLOAD_BYTES)
            attachments = [
                (item.name, _decode(item.content_b64, "content_b64", operations.MAX_TOTAL_BYTES))
                for item in body.attachments
            ]
            plan, created = operations.prepare(
                _principal(request), snapshot, body.capability_id, body.target, payload,
                attachments, body.idempotency_key,
            )
        except (operator_context.ContextUnavailable, operator_context.ContextMismatch) as err:
            raise _context_error(err) from None
        except operations.OperationError as err:
            raise _v1(err)
        response.status_code = 201 if created else 200
        return operations.plan_view(plan)

    @router.get("/plans/{plan_id}", response_model=PlanOut,
                summary="Свой план внешней операции",
                dependencies=[Depends(machine_api.require_machine("operation.plan.get"))])
    def plan_get(request: Request, plan_id: str = Path(pattern=PLAN_ID)):
        plan = operations.get_plan(plan_id)
        # Чужой план неотличим от несуществующего.
        if plan is None or plan.client_id != _principal(request).id:
            raise _v1(operations.PlanNotFound())
        return operations.plan_view(plan)

    @router.post("/plans/{plan_id}/execute", response_model=ExecuteOut,
                 summary="Исполнить одобренный план",
                 description="Только план в статусе approved с тем же хешем. Повтор после "
                             "успеха возвращает тот же результат без вызова исполнителя.")
    async def plan_execute(
        body: PlanHashIn,
        request: Request,
        plan_id: str = Path(pattern=PLAN_ID),
        snapshot: operator_context.OperatorContext = Depends(
            machine_api.require_machine("operation.execute")),
    ):
        try:
            return await operations.execute(_principal(request), plan_id, body.plan_hash)
        except (operator_context.ContextUnavailable, operator_context.ContextMismatch) as err:
            raise _context_error(err) from None
        except operations.OperationError as err:
            raise _v1(err)

    for route in router.routes:
        auth_api.machine_endpoints.add(route.endpoint)
    return router


# ---------- человеческие маршруты ----------


def _no_store(response: Response) -> None:
    # В предпросмотре точные байты и вложения, там могут быть личные данные:
    # ответ не должны сохранять ни браузер, ни посредник.
    response.headers.update(NO_STORE_HEADERS)


def admin_router() -> APIRouter:
    router = APIRouter(
        prefix="/v1/admin/operations", tags=["v1-admin-operations"],
        dependencies=[Depends(set_version_header), Depends(_no_store)],
        responses=_ADMIN_PLAN_PROBLEMS,
    )

    @router.get("/plans/{plan_id}", response_model=AdminPlanOut,
                summary="Точный предпросмотр плана для одобрения")
    def review(plan_id: str = Path(pattern=PLAN_ID), account: Account = Depends(auth_api.require_admin)):
        plan = operations.get_plan(plan_id)
        if plan is None:
            raise _v1(operations.PlanNotFound())
        return operations.admin_view(plan)

    @router.post("/plans/{plan_id}/approve", response_model=AdminPlanOut,
                 summary="Одобрить план (только человек по сессии)",
                 description="Хеш плана пересчитывается из сохранённых байтов. Ключ "
                             "интеграции и MCP одобрить план не могут. Одобряет администратор "
                             "установки, в том числе план ключа, который он сам выпустил: это "
                             "одобрение человеком, а не независимое согласование.")
    def approve(
        body: PlanHashIn,
        plan_id: str = Path(pattern=PLAN_ID),
        account: Account = Depends(auth_api.require_admin),
    ):
        try:
            plan = operations.approve(plan_id, body.plan_hash, account.id)
        except operations.OperationError as err:
            raise _v1(err)
        return operations.admin_view(plan)

    return router
