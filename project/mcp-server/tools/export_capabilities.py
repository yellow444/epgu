"""Генератор снимка реестра возможностей для MCP.

Загружает ``api-gosuslugi-backend/capabilities.py`` по пути файла (без
импорта приложения FastAPI) и пишет ``src/epgu_mcp/capabilities_snapshot.json``.

    python tools/export_capabilities.py            # записать снимок
    python tools/export_capabilities.py --check    # только сверить (код 1 при расхождении)
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
MCP_ROOT = HERE.parent
DEFAULT_BACKEND = MCP_ROOT.parent / "api-gosuslugi-backend" / "capabilities.py"
DEFAULT_SNAPSHOT = MCP_ROOT / "src" / "epgu_mcp" / "capabilities_snapshot.json"
SCHEMA_VERSION = "1.0"


def load_registry_module(path: Path):
    """Импортировать capabilities.py по пути, не затрагивая sys.path."""
    spec = importlib.util.spec_from_file_location("_epgu_capabilities_export", path)
    if spec is None or spec.loader is None:
        raise ImportError(f"не удалось загрузить {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # нужно для dataclass
    try:
        spec.loader.exec_module(module)
    finally:
        sys.modules.pop(spec.name, None)
    return module


def build_snapshot(path: Path = DEFAULT_BACKEND) -> dict:
    module = load_registry_module(path)
    return {
        "schema_version": SCHEMA_VERSION,
        "generated_from": "api-gosuslugi-backend/capabilities.py",
        "items": [cap.to_dict() for cap in module.items()],
    }


def render(snapshot: dict) -> str:
    return json.dumps(snapshot, ensure_ascii=False, indent=2) + "\n"


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("--backend", type=Path, default=DEFAULT_BACKEND)
    p.add_argument("--out", type=Path, default=DEFAULT_SNAPSHOT)
    p.add_argument("--check", action="store_true", help="не писать, только сверить")
    args = p.parse_args(argv)
    if not args.backend.is_file():
        print(f"нет файла реестра: {args.backend}", file=sys.stderr)
        return 2
    text = render(build_snapshot(args.backend))
    if args.check:
        current = args.out.read_text(encoding="utf-8") if args.out.is_file() else ""
        if current != text:
            print("снимок расходится с реестром; запустите без --check", file=sys.stderr)
            return 1
        return 0
    args.out.write_text(text, encoding="utf-8", newline="\n")
    print(f"записан {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
