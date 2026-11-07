"""knowledge_get_manual_path: тот же канон, что HTTP и интерфейс, без входных значений."""
from __future__ import annotations

import json
from pathlib import Path

import anyio
import pytest
from conftest import TOOL_NAMES, connect
from epgu_knowledge import load_manual_path, manual_path_schema
from epgu_mcp.registry import AVAILABLE_PROFILES
from epgu_mcp.server import build_registry, load_knowledge
from epgu_mcp.tools import build_core_tools
from jsonschema import Draft202012Validator

CLIENT_COPY = Path(__file__).resolve().parents[2] / "api-gosuslugi-client/src/components/PublicSetup/manual_path.v1.json"


def _tool():
    return next(t for t in build_core_tools(load_knowledge()) if t.name == "knowledge_get_manual_path")


def test_input_is_empty_and_closed():
    schema = _tool().input_schema
    assert schema["properties"] == {} and schema["additionalProperties"] is False
    assert not schema.get("required")


def test_output_schema_is_the_package_schema():
    assert _tool().output_schema == manual_path_schema()


def test_description_keeps_values_with_the_human():
    text = _tool().description
    assert "не принимает" in text and "не проси" in text
    assert "не проверена" in text


def test_exactly_one_new_tool_and_no_operations():
    assert AVAILABLE_PROFILES == ("knowledge",)
    assert len(TOOL_NAMES) == 11
    names = {t.name for t in build_core_tools(load_knowledge())}
    assert names == TOOL_NAMES
    assert not {n for n in names if n.startswith("plan_")}
    assert "plan_execute" not in build_registry("knowledge", load_knowledge()).names()


def test_session_answer_is_the_canon_and_read_only():
    async def main():
        async with connect("auto") as client:
            tools = {t.name: t for t in (await client.list_tools()).tools}
            tool = tools["knowledge_get_manual_path"]
            assert tool.annotations.read_only_hint is True
            assert tool.annotations.destructive_hint is False
            res = await client.call_tool("knowledge_get_manual_path", {})
            assert not res.is_error
            Draft202012Validator(tool.output_schema).validate(res.structured_content)
            assert res.structured_content == load_manual_path().document()
            assert res.structured_content == json.loads(CLIENT_COPY.read_text(encoding="utf-8"))

    anyio.run(main)


@pytest.mark.parametrize("arguments", [{"organizationOid": "VALUE_MARKER"}, {"contour": "TEST"}])
def test_values_are_refused(arguments):
    async def main():
        async with connect("auto") as client:
            try:
                res = await client.call_tool("knowledge_get_manual_path", arguments)
            except Exception as exc:  # noqa: BLE001  отказ протокола тоже подходит, главное не принять значение
                assert "VALUE_MARKER" not in str(getattr(exc, "data", ""))
                return
            assert res.is_error
            assert not res.structured_content

    anyio.run(main)
