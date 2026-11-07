"""Общие помощники: запуск сервера подпроцессом по stdio."""
from __future__ import annotations

import json
import os
import queue
import subprocess
import sys
import threading
from contextlib import asynccontextmanager
from pathlib import Path

import pytest
from mcp import Client, StdioServerParameters

TESTS = Path(__file__).resolve().parent
MCP_ROOT = TESTS.parent
SNAPSHOT = MCP_ROOT / "src" / "epgu_mcp" / "capabilities_snapshot.json"
BACKEND_CAPS = MCP_ROOT.parent / "api-gosuslugi-backend" / "capabilities.py"
EXPORT_SCRIPT = MCP_ROOT / "tools" / "export_capabilities.py"

TOOL_NAMES = {
    "knowledge_overview",
    "knowledge_list_routes",
    "knowledge_get_route",
    "knowledge_get_node",
    "knowledge_list_sources",
    "knowledge_get_source",
    "knowledge_list_notes",
    "knowledge_search",
    "knowledge_get_manual_path",
    "knowledge_evaluate_connection_card",
    "capabilities_list",
}


def server_env(**extra: str) -> dict[str, str]:
    env = {"PYTHONUTF8": "1", "EPGU_MCP_LOG_LEVEL": "WARNING"}
    env.update(extra)
    return env


def params(env: dict[str, str] | None = None, args: list[str] | None = None) -> StdioServerParameters:
    return StdioServerParameters(
        command=sys.executable,
        args=["-m", "epgu_mcp", *(args or [])],
        env=server_env() if env is None else env,
    )


@asynccontextmanager
async def connect(mode: str = "auto", env: dict[str, str] | None = None):
    async with Client(params(env), mode=mode, read_timeout_seconds=30) as client:
        yield client


class RawServer:
    """Сервер как сырой процесс: пишем строки в stdin, читаем строки stdout."""

    def __init__(self, env: dict[str, str] | None = None, args: list[str] | None = None) -> None:
        full = {**os.environ, **(server_env() if env is None else env)}
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "epgu_mcp", *(args or [])],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=full,
        )
        self._lines: queue.Queue[bytes | None] = queue.Queue()
        self.stdout_lines: list[bytes] = []
        threading.Thread(target=self._pump, daemon=True).start()

    def _pump(self) -> None:
        assert self.proc.stdout is not None
        for line in self.proc.stdout:
            self._lines.put(line)
        self._lines.put(None)

    def send(self, obj: object) -> None:
        data = obj if isinstance(obj, str) else json.dumps(obj)
        assert self.proc.stdin is not None
        self.proc.stdin.write(data.encode("utf-8") + b"\n")
        self.proc.stdin.flush()

    def recv(self, timeout: float = 20.0) -> dict:
        line = self._lines.get(timeout=timeout)
        assert line is not None, "stdout закрыт"
        self.stdout_lines.append(line)
        return json.loads(line)

    def close_stdin(self) -> None:
        assert self.proc.stdin is not None
        self.proc.stdin.close()

    def finish(self, timeout: float = 20.0) -> tuple[int, bytes, bytes]:
        """Дочитать stdout до конца и дождаться выхода."""
        code = self.proc.wait(timeout=timeout)
        while True:
            line = self._lines.get(timeout=5)
            if line is None:
                break
            self.stdout_lines.append(line)
        assert self.proc.stderr is not None
        return code, b"".join(self.stdout_lines), self.proc.stderr.read()

    def kill(self) -> None:
        if self.proc.poll() is None:
            self.proc.kill()
            self.proc.wait()


@pytest.fixture
def raw():
    servers: list[RawServer] = []

    def make(env: dict[str, str] | None = None, args: list[str] | None = None) -> RawServer:
        s = RawServer(env, args)
        servers.append(s)
        return s

    yield make
    for s in servers:
        s.kill()
