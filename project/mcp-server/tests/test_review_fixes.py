"""Регрессии по замечаниям приёмки F1-F3 и логированию аргументов."""
from __future__ import annotations

import json
import logging
from typing import Any

import anyio
import pytest
from epgu_knowledge import limits
from jsonschema import Draft202012Validator
from mcp import Client

from conftest import TOOL_NAMES, server_env
from epgu_mcp import extensions
from epgu_mcp.registry import ProfileViolation, ToolRegistry, ToolSpec
from epgu_mcp.server import build_registry, build_server, load_knowledge
from epgu_mcp.tools import build_core_tools

EMPTY_OUT = {"type": "object"}
EMPTY_IN = {"type": "object", "properties": {}, "additionalProperties": False}


def spec(name: str, **kw: Any) -> ToolSpec:
    return ToolSpec(name=name, description="тест", input_schema=EMPTY_IN, output_schema=EMPTY_OUT,
                    handler=lambda _a: {"ok": True}, **kw)


class EP:
    def __init__(self, name: str, fn):
        self.name, self._fn = name, fn

    def load(self):
        return self._fn


@pytest.fixture
def registry() -> ToolRegistry:
    return build_registry("knowledge", load_knowledge())


def run_exts(monkeypatch, registry, *eps, enabled=None):
    monkeypatch.setattr(extensions, "_iter_entry_points", lambda: list(eps))
    names = [e.name for e in eps] if enabled is None else enabled
    return extensions.load_extensions(registry, "knowledge", names)


def snapshot(registry):
    return [(s.name, id(s)) for s in registry.specs()]


# ------------------------------------------------------------------ F1

def test_extension_gets_no_remove_access(monkeypatch, registry):
    before = snapshot(registry)

    def remove_then_crash(server, profile):
        assert not hasattr(server, "remove_tool")
        server.remove_tool("knowledge_overview")  # AttributeError

    failures = run_exts(monkeypatch, registry, EP("rm", remove_then_crash))
    assert [n for n, _ in failures] == ["rm"]
    assert snapshot(registry) == before


def test_remove_replace_crash_keeps_core(monkeypatch, registry):
    before = snapshot(registry)

    def replace(server, profile):
        getattr(server, "remove_tool", lambda _n: None)("knowledge_overview")
        server.add_tool(spec("knowledge_overview"))
        raise RuntimeError("после подмены")

    assert run_exts(monkeypatch, registry, EP("replace", replace))
    assert snapshot(registry) == before


def test_error_after_additions_rolls_back_all(monkeypatch, registry):
    before = snapshot(registry)

    def partial(server, profile):
        server.add_tool(spec("ext_a"))
        server.add_tool(spec("ext_b"))
        raise RuntimeError("сбой")

    assert run_exts(monkeypatch, registry, EP("partial", partial))
    assert snapshot(registry) == before


def test_conflict_with_core_and_other_extension(monkeypatch, registry):
    def first(server, profile):
        server.add_tool(spec("ext_shared"))

    def second(server, profile):
        server.add_tool(spec("ext_own"))
        server.add_tool(spec("ext_shared"))

    def core(server, profile):
        server.add_tool(spec("knowledge_search"))

    failures = run_exts(monkeypatch, registry, EP("first", first), EP("second", second), EP("core", core))
    assert [n for n, _ in failures] == ["second", "core"]
    names = registry.names()
    assert "ext_shared" in names and "ext_own" not in names
    assert registry.get("knowledge_search").description != "тест"


def test_successful_registration(monkeypatch, registry):
    assert run_exts(monkeypatch, registry, EP("ok", lambda s, p: s.add_tool(spec("ext_ok")))) == []
    assert set(registry.names()) == TOOL_NAMES | {"ext_ok"}


def test_extensions_require_explicit_enable(monkeypatch, registry):
    loaded = []

    class Spy(EP):
        def load(self):
            loaded.append(self.name)
            return lambda s, p: s.add_tool(spec(f"ext_{self.name}"))

    failures = run_exts(monkeypatch, registry, Spy("a", None), Spy("b", None), enabled=["b", "missing"])
    assert loaded == ["b"], "не включённые entry points не импортируются"
    assert failures == [("missing", "не найдено")]
    assert "ext_b" in registry.names() and "ext_a" not in registry.names()


def test_merge_is_atomic():
    reg = ToolRegistry("knowledge")
    reg.add_tool(spec("x"))
    with pytest.raises(ProfileViolation):
        reg.merge([spec("y"), spec("z", read_only=False)])
    assert reg.names() == ["x"]


# ------------------------------------------------------------------ F2

def _write(tmp_path, data, name="ds.json"):
    p = tmp_path / name
    p.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    return p


def _package_data():
    from importlib.resources import files
    return json.loads(files("epgu_knowledge").joinpath("data/knowledge.v1.json").read_text(encoding="utf-8"))


def _bad_datasets(tmp_path):
    d1 = _package_data(); d1["sources"][0]["id"] = []
    d2 = _package_data(); d2["routes"].append(dict(d2["routes"][0]))
    d3 = _package_data(); d3["routes"][0]["nodes"][0]["next"].append({"to": "nowhere"})
    d4 = _package_data(); d4["schema_version"] = "2.0"
    return {
        "empty": _write(tmp_path, {}, "empty.json"),
        "malformed": _write(tmp_path, d1, "malformed.json"),
        "duplicate": _write(tmp_path, d2, "dup.json"),
        "dangling": _write(tmp_path, d3, "dangling.json"),
        "version": _write(tmp_path, d4, "version.json"),
    }


@pytest.mark.parametrize("case", ["empty", "malformed", "duplicate", "dangling", "version"])
def test_invalid_dataset_exits_3_before_serving(raw, tmp_path, case):
    path = _bad_datasets(tmp_path)[case]
    s = raw(env=server_env(EPGU_KNOWLEDGE_PATH=str(path), EPGU_MCP_LOG_LEVEL="INFO"))
    code, stdout, stderr = s.finish(timeout=15)
    text = stderr.decode("utf-8")
    assert code == 3, text
    assert stdout == b"", "ни одного байта протокола"
    assert "запуск" not in text, "сервер не должен стартовать"
    assert "Traceback" not in text
    assert str(tmp_path) not in text, "локальный путь не выводится"


# ------------------------------------------------------------------ F3

def _search_schema():
    tool = next(t for t in build_core_tools(load_knowledge()) if t.name == "knowledge_search")
    return tool, Draft202012Validator(tool.input_schema)


def test_search_schema_matches_handler_boundaries():
    tool, v = _search_schema()
    props = tool.input_schema["properties"]
    assert props["query"]["maxLength"] == limits.MAX_QUERY_LEN
    assert props["cursor"]["maxLength"] == limits.MAX_CURSOR_LEN
    assert props["limit"]["maximum"] == limits.MAX_LIMIT
    assert props["domain"]["enum"] == list(limits.DOMAINS)

    ok = {"query": "а" * limits.MAX_QUERY_LEN}
    assert v.is_valid(ok)
    assert "items" in tool.handler(ok)
    too_long = {"query": "а" * (limits.MAX_QUERY_LEN + 1)}
    assert not v.is_valid(too_long)
    assert not v.is_valid({"query": "   "})
    assert not v.is_valid({"query": "api", "cursor": "A" * (limits.MAX_CURSOR_LEN + 1)})
    assert not v.is_valid({"query": "api", "domain": "unknown"})


def test_every_schema_valid_input_is_handler_valid():
    """Для граничных значений схема и handler дают один и тот же вердикт."""
    kb = load_knowledge()
    tools = {t.name: t for t in build_core_tools(kb)}
    cases = [
        ("knowledge_search", {"query": "x" * limits.MAX_QUERY_LEN, "limit": limits.MAX_LIMIT}),
        ("knowledge_search", {"query": "api", "limit": limits.MIN_LIMIT, "domain": limits.DOMAINS[0]}),
        ("knowledge_list_sources", {"officiality": limits.OFFICIALITY[-1]}),
    ]
    for name, args in cases:
        t = tools[name]
        assert Draft202012Validator(t.input_schema).is_valid(args), (name, args)
        t.handler(args)  # не должно поднимать ToolError


def test_query_201_over_mcp_is_schema_error():
    registry = build_registry("knowledge", load_knowledge())
    server = build_server(registry)

    async def main():
        async with Client(server) as client:
            r200 = await client.call_tool("knowledge_search", {"query": "а" * 200})
            assert r200.is_error is False
            r201 = await client.call_tool("knowledge_search", {"query": "а" * 201})
            assert r201.is_error is True
            assert json.loads(r201.content[0].text)["error"]["code"] == "invalid_parameter"

    anyio.run(main)


# ------------------------------------------------------------------ логи

def test_debug_log_has_no_argument_values(caplog):
    server = build_server(build_registry("knowledge", load_knowledge()))
    secret = "токенсекретныйзначение"

    async def main():
        async with Client(server) as client:
            await client.call_tool("knowledge_search", {"query": secret})
            await client.call_tool("knowledge_search", {"query": secret, "extra": secret})

    with caplog.at_level(logging.DEBUG):
        anyio.run(main)
    assert caplog.records
    assert all(secret not in r.getMessage() for r in caplog.records)
