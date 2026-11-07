"""Реальный stdio MCP, без LLM, кабинетов и сети: вычисление из отметок."""
import json

import anyio
import pytest
from conftest import connect
from epgu_knowledge import (
    connection_card_input_schema,
    connection_card_output_schema,
    load_connection_card,
)
from epgu_mcp.server import load_knowledge
from epgu_mcp.tools import build_core_tools

NAME = "knowledge_evaluate_connection_card"
PAYLOAD = {"goal": "obtain_api_key", "facts": {"same_context": "reported_yes", "power_issued": "reported_yes"}}


def test_tool_contract():
    tool = next(t for t in build_core_tools(load_knowledge()) if t.name == NAME)
    assert tool.input_schema == connection_card_input_schema()
    assert tool.output_schema == connection_card_output_schema()
    assert tool.read_only and tool.idempotent and not tool.destructive and not tool.open_world
    assert tool.profile == "knowledge"
    assert "caller_reported" in tool.description
    assert tool.handler(PAYLOAD) == load_connection_card().evaluate(PAYLOAD)


@pytest.mark.parametrize("payload", [
    {"goal": "request_power", "facts": {"same_context": "reported_yes", "system_registered": "reported_yes",
        "cert_bound": "reported_yes", "application_submitted": "reported_no"}},
    {"goal": "check_signature", "facts": {"same_context": "reported_yes", "local_signature_valid": "reported_yes",
        "server_signature_accepted": "reported_no", "cert_bound": "reported_yes",
        "signature_context_checked": "reported_yes", "error_recorded": "reported_yes"}},
    PAYLOAD,
])
def test_stdio_answer_and_annotations(payload):
    async def run():
        async with connect("auto") as client:
            tools = {t.name: t for t in (await client.list_tools()).tools}
            assert tools[NAME].annotations.read_only_hint
            result = await client.call_tool(NAME, payload)
            assert not result.is_error
            assert result.structured_content == load_connection_card().evaluate(payload)
    anyio.run(run)


@pytest.mark.parametrize("payload", [
    {"goal": "request_power", "facts": {"same_context": "SECRET_MARKER"}},
    {"goal": "request_power", "SECRET_MARKER": "SECRET_MARKER"},
    {"goal": "request_power", "facts": {"__proto__": "reported_yes"}},
    {"goal": "constructor"},
])
def test_stdio_invalid_values_not_echoed(payload):
    async def run():
        async with connect("auto") as client:
            result = await client.call_tool(NAME, payload)
            assert result.is_error
            assert "SECRET_MARKER" not in json.dumps(result.model_dump(), ensure_ascii=False)
            assert not result.structured_content
    anyio.run(run)
