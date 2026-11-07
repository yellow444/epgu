"""API v1: чтение справочной базы знаний и реестра возможностей.

Данные справочные: это не разрешение оператора и не исполняемый коннектор.

Два роутера:

- ``/v1/knowledge/*`` открыт без входа: статические публичные знания
  и каталог встроенных возможностей ядра. Маршруты открываются поштучно
  через ``auth_api.public_endpoints``, без исключения на весь префикс.
  Чистый POST-расчёт карточки открывается отдельным public_post_endpoints;
  он не проверяет внешние системы и не изменяет состояние.
  Запросы ограничены бюджетом ``public_budget``;
- ``/v1/capabilities*`` требует входа: это эффективный реестр установки,
  включая регистрации private.

Ошибки маршрутов v1 отдаются как application/problem+json (так же описаны
в OpenAPI), ответы несут заголовок ``X-EPGU-API-Version: 1``.
"""

from typing import Any, Dict, List, Literal, Optional

from epgu_knowledge import (
    ConnectionCard,
    KnowledgeBase,
    KnowledgeError,
    ManualPath,
    NotFound,
    connection_card_input_schema,
    connection_card_output_schema,
    connection_card_schema,
    load,
    load_connection_card,
    load_manual_path,
)
from epgu_knowledge import limits as L
from fastapi import APIRouter, Body, Depends, Query, Request, Response
from fastapi import Path as ApiPath
from fastapi.responses import JSONResponse
from pydantic import BaseModel, ConfigDict, Field

import auth_api
import capabilities
import public_budget
from v1_errors import (
    API_VERSION,
    API_VERSION_HEADER,
    PROBLEM_MEDIA_TYPE,
    V1Error,
    install_error_handlers,
    problem_schema,
    set_version_header,
)

_PROBLEM_SCHEMA = problem_schema()


def _problem(description: str) -> Dict[str, Any]:
    # Без "model": иначе FastAPI описывает тело как application/json.
    return {"description": description,
            "content": {PROBLEM_MEDIA_TYPE: {"schema": _PROBLEM_SCHEMA}}}


_COMMON_PROBLEMS: Dict[int, Dict[str, Any]] = {
    404: _problem("Не найдено"),
    422: _problem("Недопустимый параметр"),
}
PUBLIC_PROBLEMS: Dict[int, Dict[str, Any]] = {
    **_COMMON_PROBLEMS,
    429: _problem("Превышен бюджет запросов без входа; см. Retry-After"),
    503: _problem("Набор знаний недоступен"),
}
AUTH_PROBLEMS: Dict[int, Dict[str, Any]] = {
    401: _problem("Нужен вход"),
    403: _problem("Доступ запрещён"),
    **_COMMON_PROBLEMS,
}

Domain = Literal[L.DOMAINS]  # type: ignore[valid-type]
Officiality = Literal[L.OFFICIALITY]  # type: ignore[valid-type]
_ID_PATH: Dict[str, Any] = {"min_length": 1, "max_length": L.MAX_ID_LEN}


class _Open(BaseModel):
    # Поля набора знаний могут расширяться; неизвестные не отбрасываем.
    model_config = ConfigDict(extra="allow")


class Coverage(_Open):
    status: str
    capabilities: List[str]
    note: str


class RouteSummary(_Open):
    id: str
    title: str
    summary: str
    domain: str
    coverage: Coverage
    entry_node: str
    node_count: int


class NodeLink(_Open):
    to: str
    label: str


class Node(_Open):
    id: str
    title: str
    body: str
    checks: List[str]
    sources: List[str]
    next: List[NodeLink]
    warning: Optional[str] = None
    layout: Dict[str, int]


class Route(_Open):
    id: str
    title: str
    summary: str
    domain: str
    coverage: Coverage
    entry_node: str
    nodes: List[Node]


class Incoming(BaseModel):
    model_config = ConfigDict(populate_by_name=True)
    from_: str = Field(alias="from")
    label: str


class Source(_Open):
    id: str
    title: str
    url: str
    section: str
    kind_label: str
    officiality: str
    checked_at: str
    version: Optional[str] = None
    sha256: Optional[str] = None
    redistribution: str


class NodeDetail(Node):
    incoming: List[Incoming]
    sources_resolved: List[Source]


class UsedBy(_Open):
    route: str
    node: str


class SourceDetail(Source):
    used_by: List[UsedBy]


class Note(_Open):
    id: str
    title: str
    status: str
    text: str
    sources: List[str]


class Meta(_Open):
    schema_version: str
    dataset: Dict[str, Any]
    counts: Dict[str, int]


class RoutesList(BaseModel):
    items: List[RouteSummary]


class SourcesList(BaseModel):
    items: List[Source]


class NotesList(BaseModel):
    items: List[Note]


class SearchItem(_Open):
    type: str
    route_id: Optional[str] = None
    node_id: Optional[str] = None
    id: str
    title: str
    snippet: str
    score: float
    source_ids: List[str]


class SearchPage(BaseModel):
    items: List[SearchItem]
    next_cursor: Optional[str] = None


class CapabilityModel(BaseModel):
    id: str
    title: str
    effect: str
    api: List[str]
    ui: Optional[str] = None
    implemented: bool
    edition: str
    mcp_profile: str
    requires: List[str]
    notes: str
    scopes: List[str] = []
    gates: List[str] = []
    side_effects: List[str] = []
    machine: str = "none"


class CapabilitiesList(BaseModel):
    items: List[CapabilityModel]


def _kb() -> KnowledgeBase:
    try:
        return load()
    except KnowledgeError:
        # Подробности не уходят клиенту: набор знаний поставляется с пакетом.
        raise V1Error("dataset_unavailable", 503, "набор знаний недоступен") from None


def _manual_path() -> ManualPath:
    try:
        return load_manual_path()
    except KnowledgeError:
        raise V1Error("dataset_unavailable", 503, "ручной маршрут недоступен") from None


def _connection_card() -> ConnectionCard:
    try:
        return load_connection_card()
    except KnowledgeError:
        raise V1Error("dataset_unavailable", 503, "карточка недоступна") from None


def _bad(exc: Exception) -> V1Error:
    """Ошибка пакета знаний или проверки параметров -> ошибка v1."""
    if isinstance(exc, NotFound):
        return V1Error("not_found", 404, exc.message)
    if isinstance(exc, KnowledgeError):
        return V1Error(exc.code, 422, exc.message)
    return V1Error("invalid_parameter", 422, str(exc))


def public_rate_limit(request: Request) -> None:
    retry = public_budget.budget.take(public_budget.client_key(request))
    if retry is not None:
        raise V1Error("rate_limited", 429, "слишком много запросов без входа",
                      headers={"Retry-After": str(retry)})


def public_knowledge_router() -> APIRouter:
    router = APIRouter(
        prefix="/v1/knowledge", tags=["v1-knowledge"],
        dependencies=[Depends(set_version_header), Depends(public_rate_limit)],
        responses=PUBLIC_PROBLEMS,
    )

    @router.get("", response_model=Meta, summary="Сведения о наборе знаний")
    def knowledge_meta(kb: KnowledgeBase = Depends(_kb)):
        return kb.meta()

    @router.get("/dataset", response_model=Dict[str, Any],
                summary="Весь набор знаний (формат knowledge.v1)",
                responses={304: {"description": "Набор не изменился (If-None-Match)"}})
    def dataset(request: Request, kb: KnowledgeBase = Depends(_kb)):
        # Интерфейс обновляет встроенную копию одним запросом; ETag это content_sha256.
        etag = f'"{kb.content_sha256}"'
        headers = {"ETag": etag, "Cache-Control": "public, max-age=300", API_VERSION_HEADER: API_VERSION}
        if request.headers.get("if-none-match") == etag:
            return Response(status_code=304, headers=headers)
        return JSONResponse(kb.dataset(), headers=headers)

    @router.get("/manual-path", response_model=Dict[str, Any],
                summary="Ручной маршрут: кабинеты, шаги, поля и пустой шаблон письма",
                responses={304: {"description": "Набор не изменился (If-None-Match)"}})
    def manual_path(request: Request, manual: ManualPath = Depends(_manual_path)):
        # Значения организации метод не принимает: их вводит человек у себя.
        etag = f'"{manual.content_sha256}"'
        headers = {"ETag": etag, "Cache-Control": "public, max-age=300", API_VERSION_HEADER: API_VERSION}
        if request.headers.get("if-none-match") == etag:
            return Response(status_code=304, headers=headers)
        return JSONResponse(manual.document(), headers=headers)

    @router.get("/connection-card", response_model=None,
                summary="Правила справочной карточки TEST",
                responses={200: {"content": {"application/json": {"schema": connection_card_schema()}}},
                           304: {"description": "Правила не изменились (If-None-Match)"}})
    def connection_card(request: Request, card: ConnectionCard = Depends(_connection_card)):
        etag = f'"{card.content_sha256}"'
        headers = {"ETag": etag, "Cache-Control": "public, max-age=300", API_VERSION_HEADER: API_VERSION}
        if request.headers.get("if-none-match") == etag:
            return Response(status_code=304, headers=headers)
        return JSONResponse(card.document(), headers=headers)

    @router.post("/connection-card/evaluate", response_model=None,
                 summary="Разбор отметок человека, без проверки кабинета и без действий",
                 openapi_extra={"requestBody": {"required": True, "content": {
                     "application/json": {"schema": connection_card_input_schema()}}}},
                 responses={200: {"content": {"application/json": {"schema": connection_card_output_schema()}}}})
    def connection_card_evaluate(payload: Any = Body(...), card: ConnectionCard = Depends(_connection_card)):
        try:
            result = card.evaluate(payload)
        except KnowledgeError as exc:
            raise _bad(exc)
        return JSONResponse(result, headers={"Cache-Control": "no-store", "Pragma": "no-cache",
                                             API_VERSION_HEADER: API_VERSION})

    @router.get("/routes", response_model=RoutesList, summary="Маршруты")
    def routes_list(kb: KnowledgeBase = Depends(_kb)):
        return {"items": kb.list_routes()}

    @router.get("/routes/{route_id}", response_model=Route, summary="Маршрут")
    def route_get(route_id: str = ApiPath(..., **_ID_PATH), kb: KnowledgeBase = Depends(_kb)):
        try:
            return kb.get_route(route_id)
        except (KnowledgeError, ValueError) as exc:
            raise _bad(exc)

    @router.get("/routes/{route_id}/nodes/{node_id}", response_model=NodeDetail,
                summary="Узел маршрута")
    def node_get(route_id: str = ApiPath(..., **_ID_PATH),
                 node_id: str = ApiPath(..., **_ID_PATH),
                 kb: KnowledgeBase = Depends(_kb)):
        try:
            return kb.get_node(route_id, node_id)
        except (KnowledgeError, ValueError) as exc:
            raise _bad(exc)

    @router.get("/sources", response_model=SourcesList, summary="Источники")
    def sources_list(officiality: Optional[Officiality] = Query(None),
                     kb: KnowledgeBase = Depends(_kb)):
        try:
            return {"items": kb.list_sources(officiality)}
        except (KnowledgeError, ValueError) as exc:
            raise _bad(exc)

    @router.get("/sources/{source_id}", response_model=SourceDetail, summary="Источник")
    def source_get(source_id: str = ApiPath(..., **_ID_PATH), kb: KnowledgeBase = Depends(_kb)):
        try:
            return kb.get_source(source_id)
        except (KnowledgeError, ValueError) as exc:
            raise _bad(exc)

    @router.get("/notes", response_model=NotesList, summary="Заметки")
    def notes_list(kb: KnowledgeBase = Depends(_kb)):
        return {"items": kb.list_notes()}

    @router.get("/search", response_model=SearchPage, summary="Поиск")
    def search(q: str = Query(..., min_length=1, max_length=L.MAX_QUERY_LEN, pattern=r"\S",
                              description="Запрос; все слова должны найтись"),
               limit: int = Query(L.DEFAULT_LIMIT, ge=L.MIN_LIMIT, le=L.MAX_LIMIT),
               cursor: Optional[str] = Query(None, min_length=1, max_length=L.MAX_CURSOR_LEN,
                                             description="Непрозрачный курсор"),
               domain: Optional[Domain] = Query(None),
               kb: KnowledgeBase = Depends(_kb)):
        try:
            return kb.search(q, limit=limit, cursor=cursor, domain=domain)
        except (KnowledgeError, ValueError) as exc:
            raise _bad(exc)

    @router.get("/capabilities", response_model=CapabilitiesList,
                summary="Каталог возможностей ядра (статический)")
    def capability_catalog():
        return {"items": [c.to_dict() for c in capabilities.catalog()]}

    for route in router.routes:
        if route.endpoint is connection_card_evaluate:
            auth_api.public_post_endpoints.add(route.endpoint)
        else:
            auth_api.public_endpoints.add(route.endpoint)
    return router


def capabilities_router() -> APIRouter:
    router = APIRouter(
        prefix="/v1", tags=["v1-capabilities"],
        dependencies=[Depends(set_version_header)], responses=AUTH_PROBLEMS,
    )

    @router.get("/capabilities", response_model=CapabilitiesList,
                summary="Реестр возможностей установки")
    def capabilities_list():
        return {"items": [c.to_dict() for c in capabilities.items()]}

    @router.get("/capabilities/{capability_id}", response_model=CapabilityModel,
                summary="Возможность")
    def capability_get(capability_id: str = ApiPath(..., min_length=1, max_length=128)):
        cap = capabilities.get(capability_id)
        if cap is None:
            raise V1Error("not_found", 404, f"возможность {capability_id!r} не найдена")
        return cap.to_dict()

    return router


def mount(app) -> None:
    """Подключить роутеры v1 и обработчики ошибок, ограниченные путями v1."""
    install_error_handlers(app)
    app.include_router(public_knowledge_router())
    app.include_router(capabilities_router())
