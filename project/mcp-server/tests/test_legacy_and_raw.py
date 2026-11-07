"""Legacy-сессия (initialize, 2025-11-25) и сырой JSON-RPC по stdio."""
from __future__ import annotations

import json
from typing import Any

import anyio

from conftest import TOOL_NAMES, connect

LEGACY = "2025-11-25"
MODERN = "2026-07-28"

CLIENT_INFO = {"name": "raw-test", "version": "0"}


def meta(version: str = MODERN) -> dict[str, Any]:
    return {
        "io.modelcontextprotocol/protocolVersion": version,
        "io.modelcontextprotocol/clientInfo": CLIENT_INFO,
        "io.modelcontextprotocol/clientCapabilities": {},
    }


def test_legacy_initialize_via_sdk_client():
    """SDK-клиент в режиме legacy делает initialize и договаривается о 2025-11-25."""

    async def main():
        async with connect("legacy") as client:
            assert client.protocol_version == LEGACY
            assert client.session.discover_result is None
            assert client.session.initialize_result is not None
            tools = (await client.list_tools()).tools
            assert {t.name for t in tools} == TOOL_NAMES
            res = await client.call_tool("knowledge_overview", {})
            assert not res.is_error and res.structured_content["counts"]["routes"] >= 1
            bad = await client.call_tool("knowledge_get_route", {"route_id": "net-takogo"})
            assert bad.is_error is True
            assert json.loads(bad.content[0].text)["error"]["code"] == "not_found"

    anyio.run(main)


def test_raw_legacy_initialize_2025_11_25(raw):
    s = raw()
    s.send({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": LEGACY, "capabilities": {}, "clientInfo": CLIENT_INFO},
    })
    init = s.recv()
    assert init["jsonrpc"] == "2.0" and init["id"] == 1
    assert init["result"]["protocolVersion"] == LEGACY
    assert init["result"]["serverInfo"]["name"] == "epgu-mcp"
    s.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
    s.send({"jsonrpc": "2.0", "id": 2, "method": "tools/list"})
    listed = s.recv()
    assert {t["name"] for t in listed["result"]["tools"]} == TOOL_NAMES
    s.send({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "knowledge_list_notes", "arguments": {}}})
    called = s.recv()
    assert called["result"]["isError"] is False
    assert called["result"]["structuredContent"]["items"]


def test_raw_initialize_with_unknown_version_gets_counter_offer(raw):
    """Неизвестную версию сервер не ломает: отвечает версией, которую поддерживает."""
    s = raw()
    s.send({
        "jsonrpc": "2.0", "id": 1, "method": "initialize",
        "params": {"protocolVersion": "1999-01-01", "capabilities": {}, "clientInfo": CLIENT_INFO},
    })
    reply = s.recv()
    assert reply["jsonrpc"] == "2.0" and reply["id"] == 1
    if "result" in reply:
        assert reply["result"]["protocolVersion"] == LEGACY
    else:  # допустимо и аккуратное -32602/-32022 с перечнем версий
        assert reply["error"]["code"] in (-32602, -32022)


def test_raw_modern_discover_and_calls_with_stdout_hygiene(raw):
    s = raw()
    s.send({"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {"_meta": meta()}})
    disc = s.recv()
    assert MODERN in disc["result"]["supportedVersions"]
    s.send({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {"_meta": meta()}})
    listed = s.recv()
    assert {t["name"] for t in listed["result"]["tools"]} == TOOL_NAMES
    s.send({"jsonrpc": "2.0", "id": 3, "method": "tools/call",
            "params": {"name": "knowledge_get_route", "arguments": {"route_id": "net-takogo"}, "_meta": meta()}})
    err = s.recv()
    assert err["result"]["isError"] is True
    # Мусор и неизвестные методы не должны выводить на stdout ничего, кроме JSON-RPC.
    s.send("это не json")
    s.send({"jsonrpc": "2.0", "id": 4, "method": "no/such/method", "params": {"_meta": meta()}})
    s.send({"jsonrpc": "2.0", "id": 5, "method": "tools/list", "params": {"_meta": meta()}})
    seen: set[Any] = set()
    for _ in range(6):  # ответ на мусор (если есть) + ответы на id 4 и 5
        seen.add(s.recv().get("id"))
        if {4, 5} <= seen:
            break
    assert {4, 5} <= seen
    s.close_stdin()
    code, _stdout, _stderr = s.finish()
    assert code == 0
    lines = [line for line in s.stdout_lines if line.strip()]
    assert len(lines) >= 5, "ожидались ответы на все запросы"
    bodies = []
    for line in lines:
        msg = json.loads(line.decode("utf-8"))  # каждая строка stdout это JSON
        assert msg["jsonrpc"] == "2.0"
        assert "id" in msg or "method" in msg
        bodies.append(msg)
    # Ответ на неизвестный метод это ошибка протокола с id 4.
    unknown = [m for m in bodies if m.get("id") == 4]
    assert unknown and unknown[0]["error"]["code"] == -32601
    assert any(m.get("id") == 5 and "result" in m for m in bodies)
