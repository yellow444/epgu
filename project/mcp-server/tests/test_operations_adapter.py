"""HTTP-адаптер операций на фейковом backend (httpx.MockTransport).

Сквозной цикл на настоящем backend и mock executor лежит в
api-gosuslugi-backend/test_mcp_operations_adapter.py. Здесь граница адаптера:
конфигурация и файл ключа, путь установки, проекция ответа, неизвестный исход
и отсутствие повторов. Ключ синтетический, сети нет.
"""
from __future__ import annotations

import base64
import json
import logging
import os
import subprocess
import sys
import textwrap
import traceback
from dataclasses import fields
from pathlib import Path
from typing import Any

import anyio
import httpx
import pytest
from mcp import Client
from mcp.shared.exceptions import MCPError

from conftest import TOOL_NAMES
from epgu_mcp import extensions, operations
from epgu_mcp.operations import (
    OperationsAdapter,
    OperationsConfig,
    OperationsConfigError,
    ResultProjection,
    build_operate_registry,
    operation_specs,
    read_credential,
)
from epgu_mcp.registry import PROFILES, ProfileViolation, ToolRegistry, ToolSpec
from epgu_mcp import server as server_module
from epgu_mcp.server import build_registry, build_server, load_knowledge
from epgu_mcp.targets import RESERVED_NAMES, TARGET_TOOLS

CRED = "itk_synthetic_" + "S" * 40
CANARY = "CANARY-SECRET-1d9e"
CAP = "test.mock.send"
PLAN_ID = "plan_" + "1" * 32
HASH = "b" * 64
BASE = "https://backend.test"
PROJECTION = {CAP: ResultProjection({"sent": bool, "number": str})}
PREPARE_ARGS = {"capability_id": CAP, "target": "target-1", "payload_b64": base64.b64encode(b"doc").decode(),
                "attachments": [{"name": "scan-1.bin", "content_b64": base64.b64encode(b"\x00\xff").decode()}],
                "idempotency_key": "mcp-adapter-0001"}


def plan_body(**over: Any) -> dict[str, Any]:
    body = {
        "plan_id": PLAN_ID, "plan_hash": HASH, "status": "planned", "expires_at": "2026-11-03T12:00:00+00:00",
        "preview": {
            "capability_id": CAP, "target": "target-1", "payload_sha256": "c" * 64, "payload_size": 3,
            "attachments": [{"name": "scan-1.bin", "sha256": "d" * 64, "size": 2}],
            "context": {"contour": "TEST", "organization_ref": "org-1", "is_ref": None,
                        "certificate_thumbprint": "AB" * 20, "generation": 1, "binding_epoch": 1},
            "external_calls": [{"name": "reserve_number", "side_effects": ["reserves_number"]},
                               {"name": "send", "side_effects": ["external_write"]}],
            "target_policy": {"capability_id": CAP, "effect": "write_external", "implemented": True,
                              "machine": "target", "mcp_profile": "none", "scopes": ["external:execute"],
                              "gates": [], "side_effects": ["external_write", "reserves_number"]},
        },
        "result": None, "error_code": None, "steps": [],
    }
    body.update(over)
    return body


def problem(status: int, code: str, **extra: Any) -> httpx.Response:
    return httpx.Response(status, headers={"content-type": "application/problem+json"},
                          json={"type": "about:blank", "title": code, "status": status, "code": code,
                                "detail": "отказ " + code, **extra})


class Backend:
    """Фейковый backend: записывает запросы и отвечает заданной функцией."""

    def __init__(self, respond: Any) -> None:
        self.respond = respond
        self.requests: list[httpx.Request] = []

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        return self.respond(request)


@pytest.fixture
def cred_file(tmp_path: Path) -> Path:
    path = tmp_path / "credential"
    path.write_text(CRED + "\n", encoding="ascii")
    if os.name == "posix":
        path.chmod(0o600)
    return path


def make(cred_file: Path, respond: Any, **over: Any) -> tuple[Any, Backend]:
    backend = Backend(respond)
    config = OperationsConfig(base_url=BASE, credential_file=cred_file, transport=httpx.MockTransport(backend),
                              projections=over.pop("projections", PROJECTION), **over)
    server = build_server(build_operate_registry(load_knowledge(), OperationsAdapter(config)))
    return server, backend


def call(server: Any, name: str, args: dict[str, Any]) -> Any:
    async def main() -> Any:
        async with Client(server) as client:
            return await client.call_tool(name, args)

    return anyio.run(main)


def error_of(result: Any) -> dict[str, Any]:
    assert result.is_error is True
    return json.loads(result.content[0].text)["error"]


def text_of(result: Any) -> str:
    return "".join(getattr(c, "text", "") for c in result.content) + json.dumps(result.structured_content or {})


# ------------------------------------------------------------ установка

def test_executable_specs_follow_the_catalog_exactly(tmp_path):
    adapter = OperationsAdapter(OperationsConfig(base_url=BASE, credential_file=tmp_path / "absent"))
    specs = {s.name: s for s in operation_specs(adapter)}
    assert set(specs) == RESERVED_NAMES
    for t in TARGET_TOOLS:
        s = specs[t.name]
        assert (s.title, s.description, s.input_schema, s.output_schema, s.profile) == (
            t.title, t.description, t.input_schema, t.output_schema, t.profile)
        assert (s.read_only, s.destructive, s.idempotent, s.open_world) == (
            t.read_only, t.destructive, t.idempotent, t.open_world)
        assert s.blocking is True and s.input_schema is not t.input_schema


def _objects(schema: Any) -> list[dict[str, Any]]:
    found: list[dict[str, Any]] = []
    if isinstance(schema, dict):
        if schema.get("type") == "object" and "properties" in schema:
            found.append(schema)
        for value in schema.values():
            found.extend(_objects(value))
    elif isinstance(schema, list):
        for value in schema:
            found.extend(_objects(value))
    return found


def test_catalog_outputs_are_strict_and_declare_configuration_errors():
    for t in TARGET_TOOLS:
        for obj in _objects(t.output_schema):
            assert obj.get("additionalProperties") is False, (t.name, sorted(obj["properties"]))
        assert "configuration_error" in t.error_codes and "withheld" in t.output_schema["required"]
    assert "result" not in {t.name: t for t in TARGET_TOOLS}["plan_execute"].output_schema["properties"]


def test_operations_install_only_into_an_explicit_operate_registry(cred_file):
    adapter = OperationsAdapter(OperationsConfig(base_url=BASE, credential_file=cred_file))
    for profile in ("knowledge", "read"):
        registry = build_registry(profile, load_knowledge())
        with pytest.raises(ProfileViolation, match="только в профиль operate"):
            registry.install_operations(adapter)
        assert set(registry.names()) == TOOL_NAMES
    registry = build_registry("operate", load_knowledge())
    with pytest.raises(TypeError):
        registry.install_operations(object())
    registry.install_operations(adapter)
    assert set(registry.names()) == TOOL_NAMES | RESERVED_NAMES
    # Повторная установка отклоняется целиком: реестр не меняется.
    with pytest.raises(ProfileViolation):
        registry.install_operations(adapter)
    assert len(registry.names()) == len(TOOL_NAMES) + 3


@pytest.mark.parametrize("profile", PROFILES)
def test_the_standard_server_still_exposes_no_operation(profile):
    registry = build_registry(profile, load_knowledge())
    assert set(registry.names()) == TOOL_NAMES


def handshake(server: Any, mode: str | None = None) -> tuple[str | None, str | None, list[str]]:
    async def main() -> Any:
        async with (Client(server, mode=mode) if mode else Client(server)) as client:
            info = client.server_info
            names = [t.name for t in (await client.list_tools()).tools]
            return client.instructions, info.title if info is not None else None, names

    return anyio.run(main)


@pytest.mark.parametrize("mode", [None, "legacy"])
@pytest.mark.parametrize("profile", PROFILES)
def test_a_server_without_operations_keeps_the_knowledge_metadata(profile, mode):
    instructions, title, names = handshake(build_server(build_registry(profile, load_knowledge())), mode)
    assert instructions == server_module.INSTRUCTIONS and "ничего не отправляет" in instructions
    assert set(names) == TOOL_NAMES
    if mode == "legacy":
        assert title == server_module.TITLE == "EPGU: справочные знания"


@pytest.mark.parametrize("mode", [None, "legacy"])
def test_a_server_with_operations_says_what_it_does(cred_file, mode):
    server, backend = make(cred_file, lambda r: httpx.Response(500))
    instructions, title, names = handshake(server, mode)
    assert RESERVED_NAMES <= set(names) and backend.requests == []
    assert instructions == server_module.OPERATIONS_INSTRUCTIONS
    for phrase in ("по HTTP", "plan_execute исполняет", "одобрить нельзя", "outcome_unknown",
                   "повторять запрос нельзя", "plan_get может быть не", "не подключённый коннектор"):
        assert phrase in instructions, phrase
    for promise in ("ничего не отправляет", "справочная информация, а не"):
        assert promise not in instructions
    if mode == "legacy":
        assert title == server_module.OPERATIONS_TITLE and "операции" in title


def test_operations_installed_after_build_are_not_served_under_knowledge_metadata(cred_file):
    registry = build_registry("operate", load_knowledge())
    server = build_server(registry)
    registry.install_operations(OperationsAdapter(OperationsConfig(base_url=BASE, credential_file=cred_file)))

    async def main() -> None:
        async with Client(server) as client:
            with pytest.raises(MCPError, match="набор операций изменился"):
                await client.list_tools()
            with pytest.raises(MCPError, match="набор операций изменился"):
                await client.call_tool("plan_get", {"plan_id": PLAN_ID})

    anyio.run(main)


def test_copied_catalog_specs_are_refused_by_add_tool_merge_and_extensions(cred_file, monkeypatch):
    """Копия схем, имени, профиля и аннотаций каталога не обходит резерв имён."""
    adapter = OperationsAdapter(OperationsConfig(base_url=BASE, credential_file=cred_file))
    copies = [ToolSpec(**{f.name: getattr(s, f.name) for f in fields(ToolSpec)}) for s in operation_specs(adapter)]
    registry = ToolRegistry("operate")
    for spec in copies:
        with pytest.raises(ProfileViolation, match="целевого tool"):
            registry.add_tool(spec)
    with pytest.raises(ProfileViolation):
        registry.merge(copies)
    assert registry.names() == []

    class EP:
        name = "ops"

        @staticmethod
        def load():
            def register(server, profile):
                # Даже установка в промежуточный реестр расширения не проходит merge.
                server._staged.install_operations(adapter)
            return register

    main = build_registry("operate", load_knowledge())
    monkeypatch.setattr(extensions, "_iter_entry_points", lambda: [EP])
    failures = extensions.load_extensions(main, "operate", ["ops"])
    assert len(failures) == 1 and "целевого tool" in failures[0][1]
    assert set(main.names()) == TOOL_NAMES


def test_import_build_list_and_extensions_open_no_credential_or_network(cred_file, tmp_path):
    """Файл ключа и сеть трогает только вызов tool."""
    script = textwrap.dedent("""
        import sys
        target = sys.argv[1]
        events = []
        def hook(event, args):
            if event == "open" and args and str(args[0]).endswith("credential"):
                events.append("open")
            # Цикл событий на Windows сам соединяет пару сокетов на 127.0.0.1;
            # обращение к backend.test началось бы с getaddrinfo.
            if event == "socket.getaddrinfo":
                events.append(event)
            if event == "socket.connect" and not str(args[1]).startswith("('127.0.0.1'"):
                events.append(event)
        sys.addaudithook(hook)
        import anyio
        from mcp import Client
        from epgu_mcp import extensions, operations
        from epgu_mcp.server import build_server, load_knowledge
        config = operations.OperationsConfig.from_env({
            "EPGU_MCP_BACKEND_URL": "https://backend.test", "EPGU_MCP_CREDENTIAL_FILE": target})
        adapter = operations.OperationsAdapter(config)
        registry = operations.build_operate_registry(load_knowledge(), adapter)
        extensions.load_extensions(registry, "operate", [])
        server = build_server(registry)
        async def main():
            async with Client(server) as client:
                return [t.name for t in (await client.list_tools()).tools]
        names = anyio.run(main)
        assert "plan_execute" in names, names
        repr(config), repr(adapter)
        print("EVENTS", events)
    """)
    run = subprocess.run([sys.executable, "-c", script, str(cred_file)], capture_output=True, text=True,
                         encoding="utf-8", env={**os.environ, "PYTHONUTF8": "1"}, timeout=120)
    assert run.returncode == 0, run.stderr[-2000:]
    assert "EVENTS []" in run.stdout, run.stdout


# ------------------------------------------------------------ конфигурация и ключ

def test_config_takes_a_path_not_the_secret(cred_file):
    config = OperationsConfig.from_env({"EPGU_MCP_BACKEND_URL": BASE, "EPGU_MCP_CREDENTIAL_FILE": str(cred_file),
                                        "EPGU_MCP_BACKEND_TIMEOUT": "5"})
    assert config.credential_file == cred_file and config.timeout == 5.0 and not config.allow_loopback_http
    assert CRED not in repr(config) and CRED not in repr(OperationsAdapter(config))
    assert read_credential(cred_file) == CRED
    for env in ({}, {"EPGU_MCP_BACKEND_URL": BASE}, {"EPGU_MCP_BACKEND_URL": BASE, "EPGU_MCP_CREDENTIAL_FILE": "rel"},
                {"EPGU_MCP_BACKEND_URL": BASE, "EPGU_MCP_CREDENTIAL_FILE": str(cred_file),
                 "EPGU_MCP_BACKEND_TIMEOUT": "x"}):
        with pytest.raises(OperationsConfigError):
            OperationsConfig.from_env(env)


@pytest.mark.parametrize("content", [b"short", "ключ-кириллицей-длиннее-шестнадцати".encode(),
                                     CANARY.encode() + b" with space", b"\xff" * 20, b"x" * 9000])
def test_bad_credential_file_is_refused_without_its_content(tmp_path, content):
    path = tmp_path / "credential"
    path.write_bytes(content)
    with pytest.raises(OperationsConfigError) as info:
        read_credential(path)
    shown = "".join(traceback.format_exception(info.value))
    assert CANARY not in shown and "short" not in shown and "xxxx" not in shown


def test_credential_file_must_exist_and_stay_outside_git(tmp_path):
    with pytest.raises(OperationsConfigError, match="не прочитан"):
        read_credential(tmp_path / "missing")
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    inside = repo / "conf" / "credential"
    inside.parent.mkdir()
    inside.write_text(CRED, encoding="ascii")
    with pytest.raises(OperationsConfigError, match="Git"):
        read_credential(inside)
    with pytest.raises(OperationsConfigError, match="не обычный файл"):
        read_credential(repo / "conf")


@pytest.mark.skipif(os.name != "posix", reason="права файла POSIX")
def test_credential_file_open_to_others_is_refused(cred_file):
    cred_file.chmod(0o644)
    with pytest.raises(OperationsConfigError, match="0600"):
        read_credential(cred_file)


def test_missing_credential_is_a_configuration_error_without_a_request(tmp_path):
    server, backend = make(tmp_path / "absent", lambda r: httpx.Response(500))
    err = error_of(call(server, "plan_get", {"plan_id": PLAN_ID}))
    assert err["code"] == "configuration_error" and backend.requests == []


BAD_URLS = [
    f"https://{CANARY}@backend.invalid/api",
    f"https://user:{CANARY}@backend.invalid/api",
    f"https://backend.invalid/api?credential={CANARY}",
    f"https://backend.invalid/api#{CANARY}",
    f"https://{CANARY}@backend.invalid/api?credential={CANARY}",
    f"https://backend.invalid:{CANARY}/api",
    f"ftp://backend.invalid/{CANARY}",
    f"https:///{CANARY}",
    f"//backend.invalid/{CANARY}",
    f"https://[{CANARY}/api",
    f"http://backend.invalid/{CANARY}",
    f"http://127.0.0.1/{CANARY}",
]


@pytest.fixture
def no_read_no_client(monkeypatch):
    """Отказ в адресе должен случиться до чтения ключа и до клиента 4a."""
    def forbidden(*a: Any, **k: Any) -> Any:
        raise AssertionError("ключ или клиент тронуты до отказа в адресе")

    monkeypatch.setattr(operations, "read_credential", forbidden)
    monkeypatch.setattr(operations, "IntegrationClient", forbidden)


def _no_canary(exc: BaseException) -> None:
    text = "".join(traceback.format_exception(exc))
    assert CANARY not in text and exc.__suppress_context__ is True, text


@pytest.mark.parametrize("url", BAD_URLS)
def test_unsafe_base_url_is_refused_at_construction_without_echo(tmp_path, url, no_read_no_client):
    # loopback http разрешён явно: отказ даёт не он, а компоненты адреса.
    allow = not url.startswith("http://127.0.0.1")
    with pytest.raises(OperationsConfigError) as info:
        OperationsConfig(base_url=url, credential_file=tmp_path / "absent", allow_loopback_http=allow)
    _no_canary(info.value)
    env = {"EPGU_MCP_BACKEND_URL": url, "EPGU_MCP_CREDENTIAL_FILE": str(tmp_path / "absent"),
           "EPGU_MCP_ALLOW_LOOPBACK_HTTP": "1" if allow else ""}
    with pytest.raises(OperationsConfigError) as info:
        OperationsConfig.from_env(env)
    _no_canary(info.value)


@pytest.mark.parametrize("url,allow,origin", [
    (f"https://backend.test/api/{CANARY}", False, "https://backend.test"),
    ("https://Backend.Test:8443/api/", False, "https://backend.test:8443"),
    (f"http://127.0.0.1:8000/{CANARY}", True, "http://127.0.0.1:8000"),
    ("http://[::1]:8000", True, "http://[::1]:8000"),
    ("http://localhost", True, "http://localhost"),
])
def test_allowed_base_url_shows_only_its_origin(tmp_path, url, allow, origin, no_read_no_client):
    config = OperationsConfig(base_url=url, credential_file=tmp_path / "absent", allow_loopback_http=allow)
    adapter = OperationsAdapter(config)
    assert config.origin == origin and origin in repr(config) and origin in repr(adapter)
    assert CANARY not in repr(config) + repr(adapter) + str(config) + str(adapter)
    assert "/api" not in repr(config) + repr(adapter)


def test_loopback_http_needs_the_explicit_switch(tmp_path):
    with pytest.raises(OperationsConfigError, match="только явно"):
        OperationsConfig(base_url="http://127.0.0.1:8000", credential_file=tmp_path / "absent")
    with pytest.raises(OperationsConfigError, match="только явно"):
        OperationsConfig(base_url="http://127.0.0.1:8000", credential_file=tmp_path / "absent",
                         allow_loopback_http="1")


# ------------------------------------------------------------ аргументы

@pytest.mark.parametrize("tool,args", [
    ("plan_execute", {"plan_id": PLAN_ID, "plan_hash": HASH, "credential": CRED}),
    ("plan_execute", {"plan_id": PLAN_ID, "plan_hash": HASH, "approve": True}),
    ("plan_get", {"plan_id": PLAN_ID, "base_url": "https://evil.test"}),
    ("plan_get", {"plan_id": "plan_1"}),
    ("plan_prepare", {**PREPARE_ARGS, "payload_b64": "не base64"}),
    ("plan_prepare", {**PREPARE_ARGS, "payload_b64": "AAA"}),
    ("plan_prepare", {**PREPARE_ARGS, "attachments": [{"name": "a", "content_b64": "%%%%"}]}),
])
def test_bad_or_extra_arguments_make_no_request(cred_file, tool, args):
    server, backend = make(cred_file, lambda r: httpx.Response(500))
    err = error_of(call(server, tool, args))
    assert err["code"] == "invalid_parameter" and backend.requests == []


# ------------------------------------------------------------ проекция

def leaky_plan(**over: Any) -> dict[str, Any]:
    """План с полями администратора, байтами документа и canary в результате и ссылке."""
    return plan_body(
        status="succeeded",
        result={"sent": True, "number": "N-1", "token": CANARY, "nested": {"x": CANARY}, "count": "1"},
        steps=[{"name": "reserve_number", "state": "completed", "reference": CANARY,
                "started_at": "t1", "finished_at": "t2", "raw": CANARY}],
        payload_b64=base64.b64encode(CANARY.encode()).decode(), approved_by="acc_" + "1" * 32,
        client_id="cli_x", hash_verified=True,
        attachment_contents=[{"name": "scan-1.bin", "content_b64": base64.b64encode(CANARY.encode()).decode()}],
        **over,
    )


def test_projection_passes_only_described_fields(cred_file):
    server, _ = make(cred_file, lambda r: httpx.Response(200, json=leaky_plan()))
    result = call(server, "plan_get", {"plan_id": PLAN_ID})
    assert result.is_error is False
    data = result.structured_content
    assert data["result"] == {"sent": True, "number": "N-1"}
    assert data["withheld"] == ["result", "step_references"]
    assert data["steps"] == [{"name": "reserve_number", "state": "completed", "reference": None,
                              "started_at": "t1", "finished_at": "t2"}]
    dump = text_of(result)
    assert CANARY not in dump and base64.b64encode(CANARY.encode()).decode() not in dump
    for key in ("payload_b64", "approved_by", "client_id", "hash_verified", "attachment_contents", "content_b64"):
        assert key not in dump, key


def test_without_a_projection_the_result_and_references_are_withheld(cred_file):
    body = plan_body(status="succeeded", result={"sent": True, "number": "N-1"},
                     steps=[{"name": "send", "state": "completed", "reference": "msg-1",
                             "started_at": "t1", "finished_at": "t2"}])
    server, _ = make(cred_file, lambda r: httpx.Response(200, json=body), projections={})
    data = call(server, "plan_get", {"plan_id": PLAN_ID}).structured_content
    assert data["result"] is None and data["withheld"] == ["result", "step_references"]
    assert data["steps"][0]["reference"] is None


def test_references_pass_only_when_described_for_the_capability(cred_file):
    body = plan_body(status="succeeded", result={"number": "N-1"},
                     steps=[{"name": "send", "state": "completed", "reference": "msg-1",
                             "started_at": "t1", "finished_at": "t2"}])
    server, _ = make(cred_file, lambda r: httpx.Response(200, json=body),
                     projections={CAP: ResultProjection({"number": str}, step_references=True)})
    data = call(server, "plan_get", {"plan_id": PLAN_ID}).structured_content
    assert data["steps"][0]["reference"] == "msg-1" and data["withheld"] == []


@pytest.mark.parametrize("over", [
    {"status": "done"},
    {"preview": {"capability_id": CAP}},
    {"steps": [{"name": "other_call", "state": "completed", "reference": None, "started_at": "t"}]},
    {"result": {"completed_calls": ["not_declared"]}, "status": "failed"},
    {"plan_id": "plan_" + "2" * 32},
    {"result": [1, 2]},
    # Клиент 4a такие поля не проверяет, их ловит выходная схема проекции.
    {"plan_hash": "not-a-hash"},
    {"steps": [{"name": "send", "state": "exploded", "reference": None, "started_at": "t"}]},
])
def test_incomplete_or_unexpected_plan_is_not_a_success(cred_file, over):
    server, _ = make(cred_file, lambda r: httpx.Response(200, json=plan_body(**over)))
    result = call(server, "plan_get", {"plan_id": PLAN_ID})
    if over.get("result", {}) == {"completed_calls": ["not_declared"]}:
        # Журнал с неописанным вызовом скрывается, а не выдаётся.
        assert result.structured_content["result"] is None and "result" in result.structured_content["withheld"]
    else:
        assert error_of(result)["code"] == "unexpected_response"


def test_execute_success_hides_the_result_and_points_to_plan_get(cred_file):
    server, backend = make(cred_file, lambda r: httpx.Response(
        200, json={"plan_id": PLAN_ID, "status": "succeeded", "result": {"token": CANARY}}))
    result = call(server, "plan_execute", {"plan_id": PLAN_ID, "plan_hash": HASH})
    assert result.structured_content == {"plan_id": PLAN_ID, "status": "succeeded", "withheld": ["result"]}
    assert CANARY not in text_of(result) and len(backend.requests) == 1


def test_a_credential_echoed_by_the_backend_never_reaches_the_output(cred_file):
    body = plan_body(preview={**plan_body()["preview"], "target": "x" + CRED})
    server, _ = make(cred_file, lambda r: httpx.Response(200, json=body))
    result = call(server, "plan_get", {"plan_id": PLAN_ID})
    assert error_of(result)["code"] == "unexpected_response" and CRED not in text_of(result)


# ------------------------------------------------------------ отказы и неизвестный исход

@pytest.mark.parametrize("status,code", [(401, "unauthenticated"), (403, "forbidden"), (409, "plan_state"),
                                         (410, "plan_expired"), (503, "executor_unavailable")])
def test_refusals_keep_the_backend_code_and_are_sent_once(cred_file, status, code):
    server, backend = make(cred_file, lambda r: problem(status, code, detail="ключ " + CRED))
    result = call(server, "plan_execute", {"plan_id": PLAN_ID, "plan_hash": HASH})
    err = error_of(result)
    assert err["code"] == code and len(backend.requests) == 1
    assert CRED not in text_of(result)


def test_an_undeclared_backend_code_is_not_passed_through(cred_file):
    server, _ = make(cred_file, lambda r: problem(409, "brand_new_code"))
    assert error_of(call(server, "plan_get", {"plan_id": PLAN_ID}))["code"] == "unexpected_response"


def test_unknown_after_a_partial_effect_keeps_the_journal(cred_file):
    outcome = {"plan_id": PLAN_ID, "completed_calls": ["reserve_number"], "uncertain_calls": ["send"]}
    server, backend = make(cred_file, lambda r: problem(502, "outcome_unknown", outcome=outcome))
    err = error_of(call(server, "plan_execute", {"plan_id": PLAN_ID, "plan_hash": HASH}))
    assert err["code"] == "outcome_unknown" and err["plan_id"] == PLAN_ID and err["http_status"] == 502
    assert (err["completed_calls"], err["uncertain_calls"]) == (["reserve_number"], ["send"])
    # Ни повтора, ни скрытого plan_get.
    assert [(r.method, r.url.path) for r in backend.requests] == [
        ("POST", "/v1/operations/plans/%s/execute" % PLAN_ID)]


@pytest.mark.parametrize("exc", [httpx.ReadError("reset"), httpx.ReadTimeout("slow"), httpx.RemoteProtocolError("x")])
def test_transport_failure_of_execute_is_unknown_with_null_calls(cred_file, exc):
    def boom(request: httpx.Request) -> httpx.Response:
        raise exc

    server, backend = make(cred_file, boom)
    err = error_of(call(server, "plan_execute", {"plan_id": PLAN_ID, "plan_hash": HASH}))
    # Код клиента transport_error, но тип исключения OutcomeUnknown: исход неизвестен.
    assert err["code"] == "outcome_unknown" and err["reason"] == "transport_error"
    assert err["completed_calls"] is None and err["uncertain_calls"] is None and err["http_status"] is None
    assert len(backend.requests) == 1


@pytest.mark.parametrize("response", [
    httpx.Response(500, text="oops"),
    httpx.Response(200, json={"plan_id": PLAN_ID, "status": "planned"}),
    httpx.Response(302, headers={"location": "https://evil.test"}),
    problem(502, "outcome_unknown"),
])
def test_unexpected_execute_answers_are_unknown_not_success(cred_file, response):
    server, backend = make(cred_file, lambda r: response)
    err = error_of(call(server, "plan_execute", {"plan_id": PLAN_ID, "plan_hash": HASH}))
    assert err["code"] == "outcome_unknown" and err["completed_calls"] is None
    assert len(backend.requests) == 1


def test_transport_failure_of_prepare_is_a_transport_error(cred_file):
    def boom(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("down")

    server, backend = make(cred_file, boom)
    err = error_of(call(server, "plan_prepare", PREPARE_ARGS))
    assert err["code"] == "transport_error" and err["may_have_reached_server"] is False
    assert len(backend.requests) == 1


def test_prepare_sends_the_decoded_bytes_with_the_key_in_the_header_only(cred_file):
    server, backend = make(cred_file, lambda r: httpx.Response(201, json=plan_body()))
    result = call(server, "plan_prepare", PREPARE_ARGS)
    assert result.structured_content["created"] is True
    (request,) = backend.requests
    assert request.headers["authorization"] == "Bearer " + CRED and "cookie" not in request.headers
    assert CRED not in str(request.url) and CRED not in request.content.decode()
    body = json.loads(request.content)
    assert body["payload_b64"] == PREPARE_ARGS["payload_b64"] and body["attachments"] == PREPARE_ARGS["attachments"]


def test_logs_carry_no_key_payload_or_canary(cred_file, caplog):
    caplog.set_level(logging.DEBUG)
    server, _ = make(cred_file, lambda r: httpx.Response(200, json=leaky_plan()))
    call(server, "plan_prepare", PREPARE_ARGS)
    call(server, "plan_get", {"plan_id": PLAN_ID})
    server2, _ = make(cred_file, lambda r: problem(502, "outcome_unknown", detail=CRED))
    call(server2, "plan_execute", {"plan_id": PLAN_ID, "plan_hash": HASH})
    logged = "\n".join(r.getMessage() for r in caplog.records)
    assert "tools/call plan_execute: outcome_unknown" in logged
    for secret in (CRED, CANARY, PREPARE_ARGS["payload_b64"]):
        assert secret not in logged


def test_the_client_is_closed_after_every_call(cred_file, monkeypatch):
    closed = []
    real = operations.IntegrationClient.close
    monkeypatch.setattr(operations.IntegrationClient, "close", lambda self: (closed.append(1), real(self)))
    server, _ = make(cred_file, lambda r: problem(409, "plan_state"))
    call(server, "plan_execute", {"plan_id": PLAN_ID, "plan_hash": HASH})
    server, _ = make(cred_file, lambda r: httpx.Response(200, json=plan_body()))
    call(server, "plan_get", {"plan_id": PLAN_ID})
    assert closed == [1, 1]


def test_unknown_tool_names_stay_a_protocol_error(cred_file):
    server, _ = make(cred_file, lambda r: httpx.Response(500))

    async def main() -> None:
        async with Client(server) as client:
            for name in ("plan_approve", "plan_review"):
                with pytest.raises(MCPError) as info:
                    await client.call_tool(name, {"plan_id": PLAN_ID})
                assert info.value.code == -32602

    anyio.run(main)
