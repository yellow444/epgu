"""knowledge_search через MCP: source_ids в outputSchema и в настоящем ответе."""
from __future__ import annotations

import anyio
from jsonschema import Draft202012Validator

from conftest import connect
from epgu_mcp.server import load_knowledge
from epgu_mcp.tools import build_core_tools


def _search_tool():
    return next(t for t in build_core_tools(load_knowledge()) if t.name == "knowledge_search")


def test_output_schema_requires_unique_source_ids():
    item = _search_tool().output_schema["properties"]["items"]["items"]
    assert "source_ids" in item["required"]
    assert item["properties"]["source_ids"] == {"type": "array", "items": {"type": "string"},
                                                "uniqueItems": True}
    v = Draft202012Validator(_search_tool().output_schema)
    good = {"type": "note", "id": "n", "title": "t", "source_ids": ["a", "b"]}
    assert v.is_valid({"items": [good], "next_cursor": None})
    assert not v.is_valid({"items": [{k: good[k] for k in ("type", "id", "title")}], "next_cursor": None})
    assert not v.is_valid({"items": [{**good, "source_ids": ["a", "a"]}], "next_cursor": None})
    assert not v.is_valid({"items": [{**good, "source_ids": "a"}], "next_cursor": None})


def test_tool_description_is_unchanged_by_the_field():
    assert "source_ids" not in (_search_tool().description or "")


def test_session_answer_carries_resolvable_source_ids():
    async def main():
        async with connect("auto") as client:
            tools = {t.name: t for t in (await client.list_tools()).tools}
            schema = tools["knowledge_search"].output_schema
            res = await client.call_tool("knowledge_search", {"query": "api", "limit": 50})
            assert not res.is_error
            data = res.structured_content
            Draft202012Validator(schema).validate(data)
            assert data["items"]
            seen = 0
            for item in data["items"]:
                for sid in item["source_ids"]:
                    src = await client.call_tool("knowledge_get_source", {"source_id": sid})
                    assert not src.is_error and src.structured_content["id"] == sid
                    seen += 1
            assert seen, "в выдаче должна быть хотя бы одна ссылка"

    anyio.run(main)
