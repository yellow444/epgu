"""Реестр возможностей: полнота, эффекты, границы MCP-профилей, API."""

import dataclasses

import pytest
from fastapi import APIRouter, FastAPI
from fastapi import routing as fastapi_routing
from fastapi.testclient import TestClient

import capabilities
from capabilities import UI_ONLY, Capability, Effect, McpProfile

# Пути, которые не являются возможностями ядра: служебная документация API.
_NOT_CAPABILITIES = {"/openapi.json", "/docs", "/redoc", "/docs/oauth2-redirect"}
_IMPLICIT_METHODS = {"HEAD", "OPTIONS"}


@pytest.fixture()
def client():
    import app as application

    return TestClient(application.app)


@pytest.fixture()
def clean_registry(monkeypatch):
    monkeypatch.setattr(capabilities, "_private", [])


def _mounted_operations(app):
    """Все фактически смонтированные HTTP-операции, независимо от OpenAPI.

    Обходит и вложенные роутеры, и маршруты с ``include_in_schema=False``.
    В FastAPI 0.141 подключённые роутеры хранятся не плоским списком, поэтому
    обход идёт через публичный ``iter_route_contexts``; в старых версиях
    достаточно ``app.routes``.
    """
    iterate = getattr(fastapi_routing, "iter_route_contexts", None)
    contexts = iterate(app.routes) if iterate else app.routes
    ops = set()
    for context in contexts:
        path, methods = getattr(context, "path", None), getattr(context, "methods", None)
        if not path or not methods or path in _NOT_CAPABILITIES:
            continue
        for method in set(methods) - _IMPLICIT_METHODS:
            ops.add(f"{method.upper()} {path}")
    return ops


def _app_operations():
    import app as application

    return _mounted_operations(application.app)


def _openapi_operations():
    import app as application

    return {
        f"{method.upper()} {path}"
        for path, methods in application.app.openapi()["paths"].items()
        if path not in _NOT_CAPABILITIES
        for method in methods
    }


def _declared_operations():
    return {op for cap in capabilities.items() for op in cap.api}


def test_ids_unique_and_effects_valid():
    caps = capabilities.items()
    ids = [c.id for c in caps]
    assert len(ids) == len(set(ids))
    allowed = {e.value for e in Effect}
    for cap in caps:
        assert cap.effect.value in allowed, cap.id
        assert cap.edition == "public"


def test_every_http_route_of_the_app_is_covered():
    missing = _app_operations() - _declared_operations()
    assert not missing, f"маршруты без возможности в реестре: {sorted(missing)}"


def test_hidden_route_without_capability_is_detected():
    # Регрессия: маршрут, скрытый из OpenAPI и подключённый вложенным роутером,
    # всё равно виден проверке полноты.
    inner = APIRouter(prefix="/inner", include_in_schema=False)

    @inner.post("/hidden")
    def hidden():
        return {}

    outer = APIRouter(prefix="/v1")
    outer.include_router(inner)
    probe = FastAPI()
    probe.include_router(outer)
    assert "POST /v1/inner/hidden" in _mounted_operations(probe)
    assert "/v1/inner/hidden" not in probe.openapi()["paths"]
    assert "POST /v1/inner/hidden" not in _declared_operations()


def test_no_mounted_route_is_hidden_from_openapi():
    # API-first: каждая операция описана в OpenAPI; исключения только служебные.
    assert _app_operations() == _openapi_operations()


def test_integration_admin_is_admin_without_mcp():
    for cap_id in ("integration.create", "integration.list", "integration.revoke"):
        cap = capabilities.get(cap_id)
        assert cap is not None, cap_id
        assert cap.effect is Effect.ADMIN and cap.mcp_profile is McpProfile.NONE
        assert "installation_admin" in cap.requires


def test_every_declared_api_path_exists():
    unknown = _declared_operations() - _app_operations()
    assert not unknown, f"в реестре есть несуществующие маршруты: {sorted(unknown)}"


def test_ui_only_gap_is_explicit():
    no_api = {c.id for c in capabilities.items() if not c.api}
    assert no_api == set(UI_ONLY), "возможность без API должна быть явно в UI_ONLY"
    for cap in capabilities.items():
        if cap.id in UI_ONLY:
            assert "только в UI, API нет" in cap.notes, cap.id


def test_dangerous_effects_never_in_knowledge_or_read_profiles():
    for cap in capabilities.items():
        if cap.effect in (Effect.WRITE_EXTERNAL, Effect.ADMIN):
            assert cap.mcp_profile not in (McpProfile.KNOWLEDGE, McpProfile.READ), cap.id


def test_stage1_only_knowledge_has_mcp_profile():
    for cap in capabilities.items():
        if cap.mcp_profile is McpProfile.KNOWLEDGE:
            assert cap.effect is Effect.KNOWLEDGE, cap.id
        else:
            assert cap.mcp_profile is McpProfile.NONE, cap.id


def test_dangerous_capability_cannot_be_published_to_safe_profile():
    for effect in ("write_external", "admin"):
        for profile in ("knowledge", "read"):
            with pytest.raises(ValueError):
                Capability(id="x.y", title="t", effect=effect, mcp_profile=profile)


def test_register_adds_and_rejects_duplicates(clean_registry):
    cap = Capability(id="private.thing", title="Частная возможность", effect="read_local",
                     api=("GET /private/thing",), mcp_profile="read")
    capabilities.register(cap)
    assert capabilities.get("private.thing") == cap
    with pytest.raises(ValueError):
        capabilities.register(cap)
    with pytest.raises(ValueError):
        capabilities.register(dataclasses.replace(cap, id="order.push"))


def test_items_returns_copies(clean_registry):
    first = capabilities.items()
    first.pop()
    first[0] = None
    assert len(capabilities.items()) == len(capabilities.items())
    assert capabilities.items()[0] is not None
    with pytest.raises(dataclasses.FrozenInstanceError):
        capabilities.items()[0].id = "changed"


def test_knowledge_capabilities_are_implemented_on_v1_paths():
    knowledge = [c for c in capabilities.items() if c.id.startswith("knowledge.") and c.api]
    assert knowledge
    for cap in knowledge:
        assert cap.implemented
        assert all(op.split(" ", 1)[1].startswith("/v1/knowledge") for op in cap.api), cap.id


def test_capabilities_endpoints(client):
    body = client.get("/v1/capabilities").json()
    ids = {c["id"] for c in body["items"]}
    assert {"order.push", "knowledge.search", "capabilities.list"} <= ids
    for item in body["items"]:
        assert item["effect"] in {e.value for e in Effect}
        assert isinstance(item["api"], list) and isinstance(item["requires"], list)
    one = client.get("/v1/capabilities/order.push")
    assert one.status_code == 200
    assert one.json()["effect"] == "write_external"
    assert one.json()["mcp_profile"] == "none"
    assert client.get("/v1/capabilities/order.push").headers["X-EPGU-API-Version"] == "1"
