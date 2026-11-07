"""Общие ошибки API v1: application/problem+json (RFC 9457) и версия ответов.

Формат касается только путей v1. Остальные методы приложения отвечают как
раньше (``{"detail": ...}``): обработчики здесь передают их стандартным
обработчикам FastAPI без изменений.
"""

from typing import Any, Dict, List, Optional

from fastapi import FastAPI, Request, Response
from fastapi.exception_handlers import (
    http_exception_handler,
    request_validation_exception_handler,
)
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from starlette.exceptions import HTTPException as StarletteHTTPException

V1_PREFIX = "/v1"
API_VERSION_HEADER = "X-EPGU-API-Version"
API_VERSION = "1"
PROBLEM_MEDIA_TYPE = "application/problem+json"
PROBLEM_TYPE_BASE = "https://epgu.local/problems/"

_STATUS_CODES = {
    400: "invalid_parameter",
    401: "unauthenticated",
    403: "forbidden",
    404: "not_found",
    405: "method_not_allowed",
    422: "invalid_parameter",
    429: "rate_limited",
}
_STATUS_TITLES = {
    "invalid_parameter": "Недопустимый параметр",
    "unauthenticated": "Нужен вход",
    "forbidden": "Доступ запрещён",
    "not_found": "Не найдено",
    "method_not_allowed": "Метод не поддерживается",
    "internal_error": "Внутренняя ошибка",
    "rate_limited": "Слишком много запросов",
    "dataset_unavailable": "Набор знаний недоступен",
    "context_unavailable": "Контекст оператора недоступен",
    "context_mismatch": "Контекст ключа не совпадает с контекстом оператора",
    "context_changed": "Контекст оператора изменился с момента подготовки плана",
    "plan_not_found": "План не найден",
    "plan_expired": "Срок плана истёк",
    "plan_hash_mismatch": "Хеш плана не совпадает",
    "plan_state": "План в другом состоянии",
    "plan_inflight": "План уже исполняется",
    "idempotency_conflict": "Ключ идемпотентности уже использован для другого запроса",
    "execution_failed": "Исполнение не началось",
    "outcome_unknown": "Результат внешней операции неизвестен",
    "executor_unavailable": "Исполнитель недоступен",
    "policy_changed": "Политика целевой операции изменилась с момента подготовки плана",
}


class ProblemOutcome(BaseModel):
    """Частичный результат при ``outcome_unknown``: отчёт сервера из журнала шагов."""

    plan_id: str
    completed_calls: List[str]
    uncertain_calls: List[str]


class Problem(BaseModel):
    """Тело ошибки v1 (для описания в OpenAPI)."""

    type: str
    title: str
    status: int
    code: str
    detail: str
    errors: Optional[List[Dict[str, Any]]] = None
    # Только у outcome_unknown. Ответ адресата, payload и стек сюда не попадают.
    outcome: Optional[ProblemOutcome] = None


def _inline_defs(node: Any, defs: Dict[str, Any]) -> Any:
    if isinstance(node, dict):
        ref = node.get("$ref", "")
        if isinstance(ref, str) and ref.startswith("#/$defs/"):
            return _inline_defs(defs[ref[len("#/$defs/"):]], defs)
        return {key: _inline_defs(value, defs) for key, value in node.items()}
    if isinstance(node, list):
        return [_inline_defs(value, defs) for value in node]
    return node


def problem_schema() -> Dict[str, Any]:
    """Схема ``Problem`` для ``responses`` OpenAPI без ссылок ``#/$defs``.

    Вложенные модели раскрываются на месте: внутри документа OpenAPI ссылка
    ``#/$defs/...`` никуда не ведёт.
    """
    schema = Problem.model_json_schema()
    defs = schema.pop("$defs", {})
    return _inline_defs(schema, defs)


class V1Error(Exception):
    """Собственная ошибка маршрутов v1: код, статус и пояснение."""

    def __init__(self, code: str, status: int, detail: str,
                 errors: Optional[List[Dict[str, Any]]] = None,
                 headers: Optional[Dict[str, str]] = None,
                 outcome: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(detail)
        self.code = code
        self.status = status
        self.detail = detail
        self.errors = errors
        self.headers = headers
        self.outcome = outcome


def _app_path(request: Request) -> str:
    path = request.scope.get("path", "") or "/"
    root = request.scope.get("root_path", "") or ""
    if root and path.startswith(root + "/"):
        path = path[len(root):]
    return path


def is_v1_path(request: Request) -> bool:
    """Путь запроса относится к v1 (приложение живёт за прокси под /api)."""
    path = _app_path(request)
    return path == V1_PREFIX or path.startswith(V1_PREFIX + "/")


# Предпросмотр планов несёт точные байты, поэтому и ответ об ошибке на этих
# путях не кешируется: зависимость роутера до обработчика ошибок не доходит.
NO_STORE_PREFIXES = ("/v1/admin/operations/",)
NO_STORE_HEADERS = {"Cache-Control": "no-store", "Pragma": "no-cache"}


def _cache_headers(request: Request) -> Dict[str, str]:
    path = _app_path(request)
    no_store = path.startswith(NO_STORE_PREFIXES) or path == "/v1/knowledge/connection-card/evaluate"
    return dict(NO_STORE_HEADERS) if no_store else {}


def problem_response(status: int, code: str, detail: str,
                     errors: Optional[List[Dict[str, Any]]] = None,
                     headers: Optional[Dict[str, str]] = None,
                     outcome: Optional[Dict[str, Any]] = None) -> JSONResponse:
    body: Dict[str, Any] = {
        "type": PROBLEM_TYPE_BASE + code,
        "title": _STATUS_TITLES.get(code, code),
        "status": status,
        "code": code,
        "detail": detail,
    }
    if errors:
        body["errors"] = errors
    if outcome is not None:
        body["outcome"] = ProblemOutcome(**outcome).model_dump()
    out = {API_VERSION_HEADER: API_VERSION, **(headers or {})}
    return JSONResponse(body, status_code=status, media_type=PROBLEM_MEDIA_TYPE, headers=out)


def set_version_header(response: Response) -> None:
    """Зависимость роутеров v1: заголовок версии на успешных ответах."""
    response.headers[API_VERSION_HEADER] = API_VERSION


async def _v1_error_handler(request: Request, exc: V1Error) -> JSONResponse:
    headers = {**(exc.headers or {}), **_cache_headers(request)}
    return problem_response(exc.status, exc.code, exc.detail, exc.errors, headers, exc.outcome)


async def _http_exception_handler(request: Request, exc: StarletteHTTPException):
    if not is_v1_path(request):
        return await http_exception_handler(request, exc)
    code = _STATUS_CODES.get(exc.status_code, "internal_error" if exc.status_code >= 500 else "error")
    detail = exc.detail if isinstance(exc.detail, str) else str(exc.detail)
    return problem_response(exc.status_code, code, detail,
                            headers={**(exc.headers or {}), **_cache_headers(request)})


async def _validation_handler(request: Request, exc: RequestValidationError):
    if not is_v1_path(request):
        return await request_validation_exception_handler(request, exc)
    errors = [
        {"loc": [str(part) for part in err.get("loc", ())], "msg": str(err.get("msg", ""))}
        for err in exc.errors()
    ]
    return problem_response(422, "invalid_parameter", "Недопустимые параметры запроса", errors,
                            headers=_cache_headers(request))


def install_error_handlers(app: FastAPI) -> None:
    """Подключить обработчики, ограниченные путями v1 (остальные не меняются)."""
    app.add_exception_handler(V1Error, _v1_error_handler)
    app.add_exception_handler(StarletteHTTPException, _http_exception_handler)
    app.add_exception_handler(RequestValidationError, _validation_handler)
