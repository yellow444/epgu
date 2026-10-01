"""HTTP-методы входа и проверка сессии для всего приложения.

``require_login`` подключается к приложению как общая зависимость: любой
метод, кроме короткого списка открытых, требует действующую сессию. Открыты
только проверка здоровья и сам вход.

Дополнения расширяют поведение через списки ниже, не меняя этот модуль:

- ``authorizers`` - дополнительные проверки после входа (например, членство
  в организации); функция получает запрос и аккаунт и бросает HTTPException;
- ``session_extensions`` - поля, которые добавляются к описанию сессии;
- ``mode_extensions`` - поля, которые добавляются к ``/auth/mode``.
"""

from __future__ import annotations

import os
from typing import Any, Callable, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Path, Request, Response
from pydantic import BaseModel, Field

import auth
from auth import AccessDenied, Account

# Открытые без входа пути (после снятия префикса прокси /api).
EXEMPT_PATHS = {"/health", "/hc", "/auth/login", "/auth/logout", "/auth/mode"}

authorizers: List[Callable[[Request, Account], None]] = []
session_extensions: List[Callable[[Account], Dict[str, Any]]] = []
mode_extensions: List[Callable[[], Dict[str, Any]]] = []

ACCOUNT_ID = r"^acc_[0-9a-f]{32}$"


class LoginRequest(BaseModel):
    login: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=1024)


class PasswordRequest(BaseModel):
    current: str = Field(min_length=1, max_length=1024)
    new: str = Field(min_length=1, max_length=1024)


class AccountCreate(BaseModel):
    login: str = Field(min_length=3, max_length=64)
    password: str = Field(min_length=1, max_length=1024)
    display_name: str = Field(default="", max_length=200)
    installation_admin: bool = False


class AccountPassword(BaseModel):
    password: str = Field(min_length=1, max_length=1024)


class AccountDisabled(BaseModel):
    disabled: bool


def route_path(request: Request) -> str:
    """Путь без root_path: приложение живёт за прокси под /api."""
    path = request.scope.get("path", "") or "/"
    root = request.scope.get("root_path", "") or ""
    if root and path.startswith(root + "/"):
        path = path[len(root):]
    elif root and path == root:
        path = "/"
    return path


def _resolve(request: Request) -> Account:
    cached = getattr(request.state, "account", None)
    if isinstance(cached, Account):
        return cached
    token = request.cookies.get(auth.SESSION_COOKIE, "")
    try:
        account = auth.resolve_session(token)
    except AccessDenied as err:
        raise HTTPException(status_code=401, detail=str(err) or "Нужен вход") from err
    request.state.account = account
    return account


def require_login(request: Request) -> Optional[Account]:
    """Общая зависимость приложения: сессия обязательна, кроме открытых путей."""
    if route_path(request) in EXEMPT_PATHS:
        return None
    account = _resolve(request)
    for check in list(authorizers):
        check(request, account)
    return account


def current_account(request: Request) -> Account:
    """Аккаунт текущего запроса для методов, которым он нужен явно."""
    return _resolve(request)


def require_admin(account: Account = Depends(current_account)) -> Account:
    if not account.installation_admin:
        raise HTTPException(status_code=403, detail="Нужны права администратора")
    return account


def session_payload(account: Account) -> Dict[str, Any]:
    payload: Dict[str, Any] = {"account": account.public()}
    for extend in list(session_extensions):
        payload.update(extend(account) or {})
    return payload


def _set_cookie(response: Response, token: str) -> None:
    response.set_cookie(
        auth.SESSION_COOKIE,
        token,
        httponly=True,
        samesite="strict",
        secure=os.getenv("AUTH_COOKIE_SECURE", "").lower() in {"1", "true", "yes"},
        path="/",
        max_age=auth.session_ttl_seconds(),
    )


def auth_router() -> APIRouter:
    router = APIRouter(tags=["auth"])

    @router.get("/auth/mode")
    def auth_mode():
        """Что нужно интерфейсу до входа. Без данных пользователей."""
        result: Dict[str, Any] = {
            "auth": True,
            "bootstrap_required": not auth.has_installation_admin(),
        }
        for extend in list(mode_extensions):
            result.update(extend() or {})
        return result

    @router.post("/auth/login")
    def auth_login(request: LoginRequest, response: Response):
        try:
            result = auth.login(request.login, request.password)
        except auth.AuthError as err:
            raise HTTPException(status_code=401, detail=str(err)) from err
        _set_cookie(response, result["token"])
        return session_payload(result["account"])

    @router.post("/auth/logout")
    def auth_logout(request: Request, response: Response):
        auth.logout(request.cookies.get(auth.SESSION_COOKIE, ""))
        response.delete_cookie(auth.SESSION_COOKIE, path="/")
        return {"logged_out": True}

    @router.get("/auth/session")
    def auth_session(account: Account = Depends(current_account)):
        return session_payload(account)

    @router.post("/auth/password")
    def auth_password(
        request: PasswordRequest, response: Response, account: Account = Depends(current_account)
    ):
        try:
            auth.change_password(account.id, request.current, request.new)
        except auth.AuthError as err:
            raise HTTPException(status_code=400, detail=str(err)) from err
        response.delete_cookie(auth.SESSION_COOKIE, path="/")
        return {"changed": True, "relogin": True}

    @router.get("/auth/accounts")
    def accounts_list(account: Account = Depends(require_admin)):
        return {"accounts": auth.list_accounts()}

    @router.post("/auth/accounts")
    def accounts_create(request: AccountCreate, account: Account = Depends(require_admin)):
        try:
            created = auth.create_account(
                request.login,
                request.password,
                display_name=request.display_name,
                installation_admin=request.installation_admin,
                created_by=account.id,
                source="admin",
            )
        except auth.AuthError as err:
            raise HTTPException(status_code=400, detail=str(err)) from err
        return created.public()

    @router.post("/auth/accounts/{account_id}/password")
    def accounts_password(
        request: AccountPassword,
        account_id: str = Path(pattern=ACCOUNT_ID),
        account: Account = Depends(require_admin),
    ):
        try:
            auth.set_password(account_id, request.password, by=account.id)
        except auth.AuthError as err:
            raise HTTPException(status_code=400, detail=str(err)) from err
        return {"changed": True}

    @router.post("/auth/accounts/{account_id}/disabled")
    def accounts_disabled(
        request: AccountDisabled,
        account_id: str = Path(pattern=ACCOUNT_ID),
        account: Account = Depends(require_admin),
    ):
        try:
            auth.set_disabled(account_id, request.disabled, by=account.id)
        except auth.AuthError as err:
            raise HTTPException(status_code=400, detail=str(err)) from err
        return {"account_id": account_id, "disabled": request.disabled}

    return router
