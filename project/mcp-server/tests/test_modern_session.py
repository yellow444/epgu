"""Сессия 2026-07-28 (без initialize): discover, tools/list, tools/call."""
from __future__ import annotations

import json
from typing import Any

import anyio
import pytest
from jsonschema import Draft202012Validator
from mcp.shared.exceptions import MCPError

from conftest import TOOL_NAMES, connect

MODERN = "2026-07-28"


def run(coro_fn):
    anyio.run(coro_fn)


def payload(result) -> Any:
    assert len(result.content) == 1
    return json.loads(result.content[0].text)


def test_discover_and_tools_list():
    async def main():
        async with connect("auto") as client:
            assert client.protocol_version == MODERN
            discover = client.session.discover_result
            assert discover is not None, "ожидался server/discover, а не initialize"
            assert MODERN in discover.supported_versions
            tools = (await client.list_tools()).tools
            assert {t.name for t in tools} == TOOL_NAMES
            assert len(tools) == len(TOOL_NAMES)
            for t in tools:
                a = t.annotations
                assert a is not None
                assert a.read_only_hint is True
                assert a.destructive_hint is False
                assert a.idempotent_hint is True
                assert a.open_world_hint is False
                assert t.input_schema["additionalProperties"] is False
                assert t.output_schema and t.output_schema["type"] == "object"
                assert "не разрешение оператора" in (t.description or "")
                Draft202012Validator.check_schema(t.input_schema)
                Draft202012Validator.check_schema(t.output_schema)

    run(main)


def test_happy_path_every_tool():
    async def main():
        async with connect("auto") as client:
            tools = {t.name: t for t in (await client.list_tools()).tools}

            async def call(name, args=None):
                res = await client.call_tool(name, args or {})
                assert not res.is_error, res.content
                data = res.structured_content
                assert data == payload(res)  # текст и structuredContent совпадают
                Draft202012Validator(tools[name].output_schema).validate(data)
                return data

            meta = await call("knowledge_overview")
            assert meta["counts"]["routes"] >= 1
            routes = (await call("knowledge_list_routes"))["items"]
            assert routes
            rid = routes[0]["id"]
            route = await call("knowledge_get_route", {"route_id": rid})
            assert route["id"] == rid and route["nodes"]
            nid = route["entry_node"]
            node = await call("knowledge_get_node", {"route_id": rid, "node_id": nid})
            assert node["id"] == nid and "incoming" in node and "sources_resolved" in node
            sources = (await call("knowledge_list_sources"))["items"]
            assert sources
            official = (await call("knowledge_list_sources", {"officiality": "official"}))["items"]
            assert official and all(s["officiality"] == "official" for s in official)
            src = await call("knowledge_get_source", {"source_id": sources[0]["id"]})
            assert "used_by" in src
            assert (await call("knowledge_list_notes"))["items"]
            found = await call("knowledge_search", {"query": "заявк", "limit": 5})
            assert "items" in found and "next_cursor" in found
            caps = await call("capabilities_list")
            assert caps["source"] == "snapshot" and caps["items"]
            only = await call("capabilities_list", {"mcp_profile": "knowledge"})
            assert only["items"] and all(c["mcp_profile"] == "knowledge" for c in only["items"])

    run(main)


def test_search_pagination_without_gaps():
    async def main():
        async with connect("auto") as client:
            query = "заявк"
            full = (await client.call_tool("knowledge_search", {"query": query, "limit": 50})).structured_content
            total = [(i["type"], i["route_id"], i["id"]) for i in full["items"]]
            assert len(total) >= 4, "для проверки пагинации нужно хотя бы 4 результата"
            pages, cursor = [], None
            for _ in range(60):
                args: dict[str, Any] = {"query": query, "limit": 3}
                if cursor:
                    args["cursor"] = cursor
                page = (await client.call_tool("knowledge_search", args)).structured_content
                pages += [(i["type"], i["route_id"], i["id"]) for i in page["items"]]
                cursor = page["next_cursor"]
                if not cursor:
                    break
            assert len(pages) == len(set(pages)), "дубли между страницами"
            assert pages == total, "пропуски или другой порядок"

    run(main)


NOT_FOUND_CASES = [
    ("knowledge_get_route", {"route_id": "net-takogo"}),
    ("knowledge_get_node", {"route_id": "net-takogo", "node_id": "start"}),
    ("knowledge_get_node", {"route_id": "transition", "node_id": "net-takogo"}),
    ("knowledge_get_source", {"source_id": "netTakogo"}),
]

INVALID_CASES = [
    ("knowledge_get_route", {}),
    ("knowledge_get_route", {"route_id": 5}),
    ("knowledge_get_route", {"route_id": "transition", "extra": 1}),
    ("knowledge_overview", {"unexpected": True}),
    ("knowledge_search", {"query": ""}),
    ("knowledge_search", {"query": "x", "limit": 0}),
    ("knowledge_search", {"query": "x", "limit": 51}),
    ("knowledge_search", {"query": "x", "cursor": "испорченный"}),
    ("knowledge_list_sources", {"officiality": "no-such-value"}),
    ("capabilities_list", {"effect": "wipe_everything"}),
]


def test_not_found_is_error_result():
    async def main():
        async with connect("auto") as client:
            for name, args in NOT_FOUND_CASES:
                res = await client.call_tool(name, args)
                assert res.is_error is True, (name, args)
                assert payload(res)["error"]["code"] == "not_found", (name, args)

    run(main)


def test_invalid_parameter_is_error_result():
    async def main():
        async with connect("auto") as client:
            for name, args in INVALID_CASES:
                res = await client.call_tool(name, args)
                assert res.is_error is True, (name, args, res)
                assert payload(res)["error"]["code"] == "invalid_parameter", (name, args)

    run(main)


def test_unknown_tool_is_protocol_error():
    async def main():
        async with connect("auto") as client:
            with pytest.raises(MCPError) as info:
                await client.call_tool("operate_everything", {})
            assert info.value.code == -32602

    run(main)
