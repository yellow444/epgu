"""Процесс: профили, коды выхода, stdout/stderr, EOF, уровень логов."""
from __future__ import annotations

import pytest

from conftest import server_env
from test_legacy_and_raw import meta


@pytest.mark.parametrize("profile", ["operate", "read"])
def test_unavailable_profile_exits_2(raw, profile):
    s = raw(args=["--profile", profile])
    code, stdout, stderr = s.finish()
    assert code == 2
    assert stdout == b"", "на stdout ничего, кроме протокола"
    text = stderr.decode("utf-8")
    assert profile in text and "недоступен на этапе 1" in text


def test_unknown_profile_exits_2(raw):
    s = raw(args=["--profile", "root"])
    code, stdout, stderr = s.finish()
    assert code == 2 and stdout == b"" and b"root" in stderr


def test_explicit_knowledge_profile_exits_on_eof(raw):
    """Сервер без единого запроса и с закрытым stdin выходит сам, stdout пуст."""
    s = raw(args=["--profile", "knowledge"])
    s.close_stdin()
    code, stdout, _stderr = s.finish(timeout=15)
    assert code == 0 and stdout == b""


def test_exit_promptly_on_eof_after_session(raw):
    s = raw()
    s.send({"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {"_meta": meta()}})
    s.recv()
    s.close_stdin()
    code, _stdout, _stderr = s.finish(timeout=10)
    assert code == 0


def test_bad_dataset_path_exits_3_without_stdout(raw, tmp_path):
    s = raw(env=server_env(EPGU_KNOWLEDGE_PATH=str(tmp_path / "net-takogo.json")))
    code, stdout, stderr = s.finish()
    assert code == 3 and stdout == b""
    assert stderr, "причина должна быть в stderr"


SECRET = "секретнаяфразаповиска"


def _search_and_exit(s):
    s.send({"jsonrpc": "2.0", "id": 1, "method": "server/discover", "params": {"_meta": meta()}})
    s.recv()
    s.send({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
            "params": {"name": "knowledge_search", "arguments": {"query": SECRET}, "_meta": meta()}})
    reply = s.recv()
    assert reply["result"]["isError"] is False
    s.close_stdin()
    return s.finish(timeout=15)


def test_query_is_not_logged_at_info(raw):
    s = raw(env=server_env(EPGU_MCP_LOG_LEVEL="INFO"))
    code, _stdout, stderr = _search_and_exit(s)
    text = stderr.decode("utf-8")
    assert code == 0
    assert "tools/call knowledge_search" in text, "на INFO вызов логируется"
    assert SECRET not in text


def test_query_is_not_logged_even_at_debug(raw):
    """Значения аргументов не попадают в лог ни на каком уровне (в том числе из SDK)."""
    s = raw(env=server_env(EPGU_MCP_LOG_LEVEL="DEBUG"))
    _code, _stdout, stderr = _search_and_exit(s)
    text = stderr.decode("utf-8")
    assert "tools/call knowledge_search" in text
    assert SECRET not in text


def test_logs_go_to_stderr_not_stdout(raw):
    s = raw(env=server_env(EPGU_MCP_LOG_LEVEL="DEBUG"))
    _code, stdout, stderr = _search_and_exit(s)
    assert b"DEBUG" in stderr and b"DEBUG" not in stdout
    assert b"INFO" not in stdout
