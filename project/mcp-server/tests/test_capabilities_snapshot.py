"""Снимок реестра возможностей сверяется с backend capabilities.py."""
from __future__ import annotations

import importlib.util
import json

import pytest

from conftest import BACKEND_CAPS, EXPORT_SCRIPT, SNAPSHOT


def _exporter():
    spec = importlib.util.spec_from_file_location("_export_capabilities", EXPORT_SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _committed() -> dict:
    return json.loads(SNAPSHOT.read_text(encoding="utf-8"))


@pytest.mark.skipif(
    not BACKEND_CAPS.is_file(),
    reason=f"нет {BACKEND_CAPS}: реестр backend отсутствует, сверка снимка невозможна",
)
def test_snapshot_matches_backend_registry():
    exporter = _exporter()
    fresh = exporter.build_snapshot(BACKEND_CAPS)
    assert fresh == _committed(), (
        "снимок устарел: запустите python mcp-server/tools/export_capabilities.py"
    )
    # Побайтовая сверка с тем, что записал бы генератор.
    assert exporter.render(fresh) == SNAPSHOT.read_text(encoding="utf-8")


def test_snapshot_invariants():
    snap = _committed()
    items = snap["items"]
    ids = [c["id"] for c in items]
    assert len(ids) == len(set(ids)) and ids
    for c in items:
        if c["effect"] in ("write_external", "admin"):
            assert c["mcp_profile"] not in ("knowledge", "read"), c["id"]
        if c["mcp_profile"] == "knowledge":
            assert c["effect"] == "knowledge", c["id"]
    assert any(c["id"] == "knowledge.search" for c in items)


def test_admin_capabilities_never_become_mcp_tools():
    from epgu_mcp.registry import PROFILES
    from epgu_mcp.server import build_registry, load_knowledge

    items = _committed()["items"]
    admin = {c["id"] for c in items if c["effect"] == "admin"}
    assert {"integration.create", "integration.list", "integration.revoke"} <= admin
    for c in items:
        if c["effect"] == "admin":
            assert c["mcp_profile"] == "none", c["id"]
    kb = load_knowledge()
    # Во всех профилях, включая ещё не открытые read и operate.
    for profile in PROFILES:
        registry = build_registry(profile, kb)
        for spec in registry.specs():
            assert "admin" not in spec.name and "integration" not in spec.name, (profile, spec.name)
            assert spec.read_only and not spec.destructive, (profile, spec.name)
