"""HTTP-часть ключей интеграций.

- ``require_integration(*scopes)`` - зависимость для методов, которые вызывает
  интеграция. Читает только ``Authorization: Bearer epgu_ic_...``. Cookie
  сессии человека здесь не принимается, как и ключ интеграции не принимается
  там, где нужна сессия.
- ``integration_admin_router()`` - выпуск, список и отзыв ключей для
  администратора установки по обычной сессии. Внешний путь
  /api/v1/admin/integrations: префикс /api добавляет root_path приложения.
  Изменяющие запросы с чужого Origin отсекает общий middleware приложения.
  Операции описаны в OpenAPI и в реестре возможностей как ``admin`` без
  профиля MCP: наличие HTTP-операции не делает её инструментом MCP.

Ошибки идут в формате v1 (problem+json, код ``invalid_parameter``): 422, если
тело не того типа или формы (строгие типы, без приведения ``true`` к 1), и
400, если значение допустимого типа не проходит правила ключа.

В этом срезе ``require_integration`` ни к одному существующему методу не
подключён.
"""

from __future__ import annotations

from typing import Any, Callable, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Request, Response
from pydantic import BaseModel, ConfigDict

import auth_api
import integration_auth
from auth import Account
from v1_errors import PROBLEM_MEDIA_TYPE, problem_schema, set_version_header

INVALID_TOKEN = "invalid_token"
INSUFFICIENT_SCOPE = "insufficient_scope"
CLIENT_ID = r"^ic_[0-9a-f]{32}$"


def _unauthorized() -> HTTPException:
    return HTTPException(
        status_code=401, detail=INVALID_TOKEN, headers={"WWW-Authenticate": "Bearer"}
    )


def _bearer(request: Request) -> Optional[str]:
    header = request.headers.get("authorization", "")
    scheme, _, value = header.partition(" ")
    if scheme.lower() != "bearer":
        return None
    return value.strip() or None


def require_integration(*scopes: str) -> Callable[[Request], integration_auth.IntegrationPrincipal]:
    """Зависимость: действующий ключ интеграции со всеми перечисленными разрешениями."""
    unknown = [scope for scope in scopes if scope not in integration_auth.SCOPES]
    if unknown:
        raise ValueError("Неизвестное разрешение в require_integration")
    needed = frozenset(scopes)

    def dependency(request: Request) -> integration_auth.IntegrationPrincipal:
        token = _bearer(request)
        if token is None:
            raise _unauthorized()
        try:
            principal = integration_auth.verify(token)
        except integration_auth.InvalidToken:
            raise _unauthorized() from None
        if not needed <= principal.scopes:
            raise HTTPException(
                status_code=403,
                detail=INSUFFICIENT_SCOPE,
                headers={"WWW-Authenticate": 'Bearer error="insufficient_scope"'},
            )
        request.state.integration = principal
        return principal

    return dependency


_PROBLEM_SCHEMA = problem_schema()


def _problem(description: str) -> Dict[str, Any]:
    return {"description": description,
            "content": {PROBLEM_MEDIA_TYPE: {"schema": _PROBLEM_SCHEMA}}}


ADMIN_PROBLEMS: Dict[int, Dict[str, Any]] = {
    401: _problem("Нужен вход"),
    403: _problem("Нужны права администратора установки"),
    404: _problem("Ключ не найден"),
    422: _problem("Тело или параметр не того типа или формы"),
}


class IntegrationCreate(BaseModel):
    # Строгие типы на границе: без них pydantic превращает true в 1 и "30" в 30
    # до проверок integration_auth. Значения проверяет integration_auth (400).
    model_config = ConfigDict(extra="forbid", strict=True)

    name: str
    scopes: List[str]
    context: Dict[str, Any]
    ttl_days: Optional[int] = None


class IntegrationCreated(BaseModel):
    id: str
    name: str
    scopes: List[str]
    context: Dict[str, Any]
    expires_at: str
    secret: str


class IntegrationItem(BaseModel):
    id: str
    name: str
    prefix: str
    scopes: List[str]
    context: Dict[str, Any]
    created_by: str
    created_at: str
    expires_at: str
    revoked_at: Optional[str] = None
    revoked_by: Optional[str] = None
    last_used_at: Optional[str] = None
    status: str


class IntegrationList(BaseModel):
    integrations: List[IntegrationItem]


class IntegrationRevoked(BaseModel):
    id: str
    revoked: bool


def integration_admin_router() -> APIRouter:
    router = APIRouter(
        prefix="/v1/admin/integrations", tags=["v1-admin-integrations"],
        dependencies=[Depends(set_version_header)], responses=ADMIN_PROBLEMS,
    )

    @router.post("", response_model=IntegrationCreated,
                 responses={400: _problem("Недопустимое значение разрешений, срока или контекста")},
                 summary="Выпуск ключа интеграции (секрет показывается один раз)")
    def integrations_create(
        request: IntegrationCreate, response: Response,
        account: Account = Depends(auth_api.require_admin),
    ):
        # Секрет выдаётся один раз: ответ не должны сохранять ни клиент, ни посредник.
        response.headers["Cache-Control"] = "no-store"
        response.headers["Pragma"] = "no-cache"
        try:
            return integration_auth.create_client(
                request.name,
                request.scopes,
                request.context,
                created_by=account.id,
                ttl_days=request.ttl_days,
            )
        except integration_auth.IntegrationError as err:
            raise HTTPException(status_code=400, detail=str(err)) from err

    @router.get("", response_model=IntegrationList, summary="Список ключей интеграций без секретов")
    def integrations_list(account: Account = Depends(auth_api.require_admin)):
        return {"integrations": integration_auth.list_clients()}

    @router.post("/{client_id}/revoke", response_model=IntegrationRevoked,
                 summary="Отзыв ключа интеграции")
    def integrations_revoke(
        client_id: str = Path(pattern=CLIENT_ID),
        account: Account = Depends(auth_api.require_admin),
    ):
        try:
            integration_auth.revoke(client_id, by=account.id)
        except integration_auth.IntegrationNotFound as err:
            raise HTTPException(status_code=404, detail=str(err)) from err
        return {"id": client_id, "revoked": True}

    return router
