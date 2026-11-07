"""Машинный доступ: контекст оператора для интеграций и привязка оператора.

- ``require_machine(capability_id)`` - зависимость для методов, которые вызывает
  интеграция по ключу. Допускается только ``enforced``-возможность реестра.
  Порядок: ключ (Bearer, cookie не принимается) и его разрешения из реестра,
  затем контекст оператора (``operator_context.authorize``). Ошибки идут как
  problem+json: 401 и 403 от ключа, 409 ``context_unavailable`` (причина в
  ``detail``) и 409 ``context_mismatch``.
- ``machine_router()`` - ``GET /v1/operator/context``. Маршрут регистрируется
  в ``auth_api.machine_endpoints``: только он обходит проверку cookie сессии,
  и только явно, не по префиксу пути.
- ``operator_binding_admin_router()`` - привязка оператора для администратора
  установки по обычной сессии. Ключ интеграции эти методы не открывает.
  Привязка это ручное утверждение администратора установки. Она не доказывает
  членство или права в ЕСИА и не подтверждает организацию сертификатом или
  API-Key Госуслуг; перед внешним исполнением её нельзя считать проверкой прав.

Зависимость ``require_machine`` асинхронная: проверка контекста выполняется на
цикле событий, где же идут асинхронные методы, меняющие сертификат и сессию.
Проверка ключа (запись в базу) уходит в пул потоков.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, ConfigDict

import auth_api
import capabilities
import integration_api
import operator_context
from auth import Account
from v1_errors import PROBLEM_MEDIA_TYPE, problem_schema, V1Error, set_version_header

CONTEXT_UNAVAILABLE = "context_unavailable"
CONTEXT_MISMATCH = "context_mismatch"
_MISMATCH_DETAIL = "контекст ключа не совпадает с контекстом оператора"

# Где проверяется каждое условие допуска из capabilities.ENFORCED_GATES.
# Набор ключей обязан совпадать с ENFORCED_GATES: новое условие нельзя
# объявить проверяемым, не подключив его здесь.
GATE_CHECKS: Dict[str, str] = {
    "integration_credential": "require_integration: ключ, срок, отзыв и scopes",
    "operator_binding": "operator_context.capture: привязка оператора задана",
    "certificate_match": "operator_context.capture: выбранный сертификат равен привязке",
    "contour_match": "operator_context.capture: контур живых хостов равен привязке",
    "context_match": "operator_context.authorize: контекст ключа равен контексту оператора",
    "is_bound": "operator_context.authorize(requires_is=True): ключ привязан к ИС",
    "plan_record": "operations.prepare: план только записывается, исполнитель не вызывается",
    "human_approval": "operations.approve/execute: исполняется только план в статусе approved",
    "plan_integrity": "operations.execute: хеши байтов и плана равны утверждённым",
    "binding_epoch": "operations.execute и claim_plan: версия привязки и контекст равны плану",
    "execution_claim": "operations.claim_plan: атомарный захват approved -> inflight",
}
if set(GATE_CHECKS) != capabilities.ENFORCED_GATES:
    raise RuntimeError("machine_api.GATE_CHECKS не совпадает с capabilities.ENFORCED_GATES")


def require_machine(capability_id: str) -> Callable[[Request], Any]:
    """Зависимость для машинного маршрута возможности ``capability_id``.

    Возможность должна быть в реестре с режимом ``enforced``: разрешения и
    условия берутся из неё, а не из аргументов маршрута. Объявление ещё раз
    проверяется здесь: каждое условие должно быть в ``GATE_CHECKS``,
    ``implemented`` истинно, изменяющая операция объявила условия плана. Иначе
    ошибка при сборке маршрута, а не успешный ответ. Условия плана проверяет
    ``operations`` внутри самого маршрута, не эта зависимость.
    """
    cap = capabilities.get(capability_id)
    if cap is None or cap.machine != "enforced":
        raise ValueError("require_machine: возможность не найдена или не enforced")
    capabilities.check_enforced(cap)
    unchecked = sorted(set(cap.gates) - set(GATE_CHECKS))
    if unchecked:
        raise ValueError(f"require_machine: условия {unchecked} не проверяются")
    check_key = integration_api.require_integration(*cap.scopes)
    requires_is = "is_bound" in cap.gates

    async def dependency(request: Request) -> operator_context.OperatorContext:
        # Ключ и разрешения: 401 и 403 вместе с WWW-Authenticate.
        principal = await run_in_threadpool(check_key, request)
        try:
            snapshot = operator_context.authorize(principal, requires_is=requires_is)
        except operator_context.ContextUnavailable as err:
            raise V1Error(CONTEXT_UNAVAILABLE, 409, err.reason) from None
        except operator_context.ContextMismatch:
            raise V1Error(CONTEXT_MISMATCH, 409, _MISMATCH_DETAIL) from None
        request.state.integration = principal
        request.state.operator_context = snapshot
        return snapshot

    # По этой отметке тесты сверяют маршрут с его возможностью.
    dependency.capability_id = cap.id
    return dependency


_PROBLEM_SCHEMA = problem_schema()


def _problem(description: str) -> Dict[str, Any]:
    return {"description": description,
            "content": {PROBLEM_MEDIA_TYPE: {"schema": _PROBLEM_SCHEMA}}}


MACHINE_PROBLEMS: Dict[int, Dict[str, Any]] = {
    401: _problem("Нужен ключ интеграции (Authorization: Bearer)"),
    403: _problem("У ключа нет нужного разрешения"),
    409: _problem(
        "Контекст оператора недоступен (context_unavailable, причина в detail) "
        "или не совпадает с контекстом ключа (context_mismatch)"
    ),
}
ADMIN_PROBLEMS: Dict[int, Dict[str, Any]] = {
    401: _problem("Нужен вход"),
    403: _problem("Нужны права администратора установки"),
    422: _problem("Тело не того типа или формы"),
}


class OperatorContextOut(BaseModel):
    contour: str
    organization_ref: str
    is_ref: Optional[str] = None
    certificate_thumbprint: str
    generation: int
    binding_epoch: int


def machine_router() -> APIRouter:
    router = APIRouter(
        prefix="/v1/operator", tags=["v1-operator"],
        dependencies=[Depends(set_version_header)], responses=MACHINE_PROBLEMS,
    )

    @router.get("/context", response_model=OperatorContextOut,
                summary="Контекст оператора для интеграции (ключ интеграции)")
    async def operator_context_get(
        snapshot: operator_context.OperatorContext = Depends(require_machine("operator.context")),
    ):
        return snapshot.public()

    for route in router.routes:
        auth_api.machine_endpoints.add(route.endpoint)
    return router


class OperatorBindingIn(BaseModel):
    # Строгие типы на границе: bool, число и список не приводятся к строке.
    # Значения проверяет operator_context (400).
    model_config = ConfigDict(extra="forbid", strict=True)

    organization_ref: str
    contour: str
    certificate_thumbprint: str
    is_ref: Optional[str] = None


class OperatorBindingOut(BaseModel):
    organization_ref: str
    is_ref: Optional[str] = None
    contour: str
    certificate_thumbprint: str
    updated_by: str
    updated_at: str
    epoch: int


class OperatorBindingCleared(BaseModel):
    removed: bool


_BINDING_NOTE = (
    "Ручное утверждение администратора установки: какая организация, ИС, контур "
    "и сертификат считаются контекстом оператора. Это не проверка членства или "
    "прав в ЕСИА и не подтверждение организации сертификатом или API-Key Госуслуг."
)


def operator_binding_admin_router() -> APIRouter:
    router = APIRouter(
        prefix="/v1/admin/operator-binding", tags=["v1-admin-operator-binding"],
        dependencies=[Depends(set_version_header)], responses=ADMIN_PROBLEMS,
    )

    @router.get("", response_model=OperatorBindingOut,
                responses={404: _problem("Привязка не задана")},
                summary="Привязка оператора")
    def binding_get(account: Account = Depends(auth_api.require_admin)):
        binding = operator_context.get_binding()
        if binding is None:
            raise HTTPException(status_code=404, detail="Привязка оператора не задана")
        return binding.public()

    @router.put("", response_model=OperatorBindingOut,
                responses={400: _problem("Недопустимое значение привязки")},
                summary="Задать привязку оператора",
                description=_BINDING_NOTE)
    def binding_set(
        request: OperatorBindingIn, account: Account = Depends(auth_api.require_admin)
    ):
        try:
            binding = operator_context.set_binding(
                request.organization_ref,
                request.contour,
                request.certificate_thumbprint,
                is_ref=request.is_ref,
                by=account.id,
            )
        except operator_context.BindingError as err:
            raise HTTPException(status_code=400, detail=str(err)) from err
        return binding.public()

    @router.delete("", response_model=OperatorBindingCleared, summary="Снять привязку оператора")
    def binding_clear(account: Account = Depends(auth_api.require_admin)):
        return {"removed": operator_context.clear_binding(account.id)}

    return router
