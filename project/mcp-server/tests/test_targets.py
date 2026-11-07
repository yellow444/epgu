"""Каталог целевых tools операций: описан, но не выдаётся ни одним профилем."""
from __future__ import annotations

import ast
import json
from dataclasses import fields
from typing import Any

import anyio
import pytest
from jsonschema import Draft202012Validator
from mcp import Client
from mcp.shared.exceptions import MCPError

from conftest import MCP_ROOT, SNAPSHOT, TOOL_NAMES
from epgu_mcp import extensions, targets
from epgu_mcp.registry import AVAILABLE_PROFILES, PROFILES, ProfileViolation, ToolRegistry, ToolSpec
from epgu_mcp.server import build_registry, build_server, load_knowledge
from epgu_mcp.targets import FORBIDDEN_ARGUMENT_PARTS, RESERVED_NAMES, TARGET_TOOLS, TargetTool

NAMES = {"plan_prepare", "plan_get", "plan_execute"}
PLAN_ID = "plan_" + "0" * 32
HASH = "a" * 64
EMPTY_IN = {"type": "object", "properties": {}, "additionalProperties": False}


def by_name() -> dict[str, TargetTool]:
    return {t.name: t for t in TARGET_TOOLS}


def snapshot_items() -> dict[str, dict[str, Any]]:
    return {c["id"]: c for c in json.loads(SNAPSHOT.read_text(encoding="utf-8"))["items"]}


def property_names(schema: Any) -> list[str]:
    """Все имена свойств схемы на любой глубине."""
    found: list[str] = []
    if isinstance(schema, dict):
        for key, value in schema.items():
            if key == "properties" and isinstance(value, dict):
                found.extend(value)
            found.extend(property_names(value))
    elif isinstance(schema, list):
        for value in schema:
            found.extend(property_names(value))
    return found


def objects(schema: Any) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    if isinstance(schema, dict):
        if schema.get("type") == "object":
            found.append(schema)
        for value in schema.values():
            found.extend(objects(value))
    elif isinstance(schema, list):
        for value in schema:
            found.extend(objects(value))
    return found


# ------------------------------------------------------------ сам каталог

def test_catalog_has_exactly_the_three_target_tools_and_none_is_available():
    assert {t.name for t in TARGET_TOOLS} == NAMES == RESERVED_NAMES
    for t in TARGET_TOOLS:
        assert t.status == "target" and t.available is False, t.name
        assert t.profile in PROFILES and t.profile not in AVAILABLE_PROFILES, t.name
    assert [d["available"] for d in targets.catalog()] == [False, False, False]


def test_description_has_no_executable_part():
    assert "handler" not in {f.name for f in fields(TargetTool)}
    for t in TARGET_TOOLS:
        assert not callable(getattr(t, "handler", None)), t.name
    # Каталог нельзя перевести в доступный: конструктор отказывает.
    base = by_name()["plan_get"]
    for over in ({"available": True}, {"status": "available"}):
        with pytest.raises(ValueError):
            TargetTool(**{**{f.name: getattr(base, f.name) for f in fields(TargetTool)}, **over})


def test_targets_module_does_not_reach_backend_storage_or_network():
    """Каталог только описывает: без HTTP, базы, подписи и импорта backend."""
    tree = ast.parse((MCP_ROOT / "src" / "epgu_mcp" / "targets.py").read_text(encoding="utf-8"))
    imported = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            imported.add((node.module or "").split(".")[0])
    assert imported <= {"__future__", "json", "dataclasses", "typing"}, imported


def test_schemas_are_valid_and_inputs_are_strict():
    for t in TARGET_TOOLS:
        Draft202012Validator.check_schema(t.input_schema)
        Draft202012Validator.check_schema(t.output_schema)
        for obj in objects(t.input_schema):
            assert obj.get("additionalProperties") is False, t.name


def test_no_approval_admin_or_credential_arguments():
    for t in TARGET_TOOLS:
        assert not any(part in t.name for part in ("approve", "review", "admin")), t.name
        for name in property_names(t.input_schema):
            low = name.lower()
            assert not any(part in low for part in FORBIDDEN_ARGUMENT_PARTS), (t.name, name)


@pytest.mark.parametrize("extra", ["credential", "cookie", "approve", "authorization", "plan_hash_override"])
def test_schemas_refuse_an_unknown_argument(extra):
    good = {
        "plan_prepare": {"capability_id": "operation.example", "target": "t-1", "payload_b64": "AA==",
                         "idempotency_key": "key-00000001"},
        "plan_get": {"plan_id": PLAN_ID},
        "plan_execute": {"plan_id": PLAN_ID, "plan_hash": HASH},
    }
    for name, args in good.items():
        validator = Draft202012Validator(by_name()[name].input_schema)
        assert validator.is_valid(args), name
        assert not validator.is_valid({**args, extra: "x"}), (name, extra)


def test_input_limits_follow_the_backend():
    prepare = Draft202012Validator(by_name()["plan_prepare"].input_schema)
    base = {"capability_id": "c", "target": "t", "payload_b64": "AA==", "idempotency_key": "key-00000001"}
    assert not prepare.is_valid({**base, "idempotency_key": "short"})
    assert not prepare.is_valid({**base, "attachments": [{"name": "a b", "content_b64": "AA=="}]})
    assert not prepare.is_valid({**base, "attachments": [{"name": f"a{i}", "content_b64": "AA=="} for i in range(6)]})
    assert prepare.is_valid({**base, "attachments": [{"name": "scan-1.pdf", "content_b64": "AA=="}]})
    execute = Draft202012Validator(by_name()["plan_execute"].input_schema)
    assert not execute.is_valid({"plan_id": PLAN_ID})
    assert not execute.is_valid({"plan_id": PLAN_ID, "plan_hash": "A" * 64})
    assert not execute.is_valid({"plan_id": "plan_1", "plan_hash": HASH})


def test_outputs_carry_no_document_bytes_or_admin_fields():
    for t in TARGET_TOOLS:
        names = set(property_names(t.output_schema))
        assert not names & {"payload_b64", "attachment_contents", "content_b64", "approved_by",
                            "client_id", "hash_verified"}, t.name


def test_annotations_describe_the_action_honestly():
    t = by_name()
    # prepare пишет локальный план: не read-only.
    assert (t["plan_prepare"].read_only, t["plan_prepare"].open_world) == (False, False)
    assert t["plan_get"].read_only and not t["plan_get"].destructive and t["plan_get"].idempotent
    ex = t["plan_execute"]
    assert (ex.read_only, ex.destructive, ex.idempotent, ex.open_world) == (False, True, False, True)
    assert "outcome_unknown" in ex.error_codes and "outcome_unknown" not in t["plan_prepare"].error_codes


def test_targets_follow_the_capability_registry_and_stay_off():
    caps = snapshot_items()
    for t in TARGET_TOOLS:
        cap = caps[t.capability_id]
        assert cap["effect"] != "admin", t.name
        assert cap["mcp_profile"] == "none", t.name
        assert tuple(cap["scopes"]) == t.scopes, t.name
    assert {t.capability_id for t in TARGET_TOOLS} == {"operation.prepare", "operation.plan.get",
                                                       "operation.execute"}
    # Одобрение и предпросмотр администратора целей не имеют.
    admin = {c for c, v in caps.items() if v["effect"] == "admin"}
    assert {"operation.review", "operation.approve"} <= admin
    assert not admin & {t.capability_id for t in TARGET_TOOLS}


# ------------------------------------------------------------ реестр и сервер

def plan_spec(name: str, profile: str) -> ToolSpec:
    read_only = profile != "operate"
    return ToolSpec(name=name, description="тест", input_schema=EMPTY_IN, output_schema={"type": "object"},
                    handler=lambda _a: {"ok": True}, profile=profile, read_only=read_only,
                    destructive=False)


@pytest.mark.parametrize("profile", PROFILES)
@pytest.mark.parametrize("name", sorted(NAMES))
def test_registry_refuses_a_reserved_name_in_every_profile(profile, name):
    registry = ToolRegistry(profile)
    for tool_profile in PROFILES[: PROFILES.index(profile) + 1]:
        with pytest.raises(ProfileViolation, match="целевого tool"):
            registry.add_tool(plan_spec(name, tool_profile))
    with pytest.raises(ProfileViolation):
        registry.merge([plan_spec("other_tool", "knowledge"), plan_spec(name, "knowledge")])
    assert registry.names() == []


def test_an_extension_cannot_register_a_target_tool(monkeypatch):
    class EP:
        name = "ops"

        @staticmethod
        def load():
            def register(server, profile):
                server.add_tool(plan_spec("plan_get", "knowledge"))
            return register

    registry = build_registry("knowledge", load_knowledge())
    before = registry.names()
    monkeypatch.setattr(extensions, "_iter_entry_points", lambda: [EP])
    failures = extensions.load_extensions(registry, "knowledge", ["ops"])
    assert len(failures) == 1 and "plan_get" in failures[0][1]
    assert registry.names() == before


@pytest.mark.parametrize("profile", PROFILES)
def test_library_path_exposes_no_target_tool_in_any_profile(profile):
    """build_registry/build_server, а не только отказ CLI для read и operate."""
    registry = build_registry(profile, load_knowledge())
    assert set(registry.names()) == TOOL_NAMES
    assert not set(registry.names()) & NAMES
    server = build_server(registry)

    async def main():
        async with Client(server) as client:
            listed = {t.name for t in (await client.list_tools()).tools}
            assert listed == TOOL_NAMES
            for name in sorted(NAMES):
                with pytest.raises(MCPError) as info:
                    await client.call_tool(name, {"plan_id": PLAN_ID, "plan_hash": HASH})
                assert info.value.code == -32602
            # Справочный tool по-прежнему работает в том же сервере.
            ok = await client.call_tool("capabilities_list", {"mcp_profile": "operate"})
            assert ok.is_error is False and ok.structured_content["items"] == []

    anyio.run(main)
