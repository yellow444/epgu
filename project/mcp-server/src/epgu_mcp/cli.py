"""Точка входа: ``python -m epgu_mcp --profile knowledge`` (транспорт stdio).

stdout занят протоколом. Всё остальное (логи, сообщения об ошибках) идёт в
stderr. Коды выхода: 0 штатно, 2 неверные или недоступные аргументы,
3 набор знаний не загружен или не прошёл проверку (сервер не запускается).
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
from collections.abc import Sequence

import anyio

from . import __version__
from .extensions import load_extensions
from .registry import AVAILABLE_PROFILES, PROFILES

LOG_LEVEL_ENV = "EPGU_MCP_LOG_LEVEL"
EXTENSIONS_ENV = "EPGU_MCP_EXTENSIONS"
EXIT_USAGE = 2
EXIT_DATA = 3

log = logging.getLogger("epgu_mcp")


def _eprint(message: str) -> None:
    print(f"epgu-mcp: {message}", file=sys.stderr, flush=True)


def configure_logging() -> None:
    """Логи только в stderr; уровень из EPGU_MCP_LOG_LEVEL (по умолчанию INFO)."""
    raw = os.environ.get(LOG_LEVEL_ENV, "INFO").strip().upper() or "INFO"
    level = logging.getLevelName(raw)
    bad = not isinstance(level, int)
    if bad:
        level = logging.INFO
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    root = logging.getLogger()
    root.handlers[:] = [handler]
    root.setLevel(level)
    if bad:
        log.warning("неизвестный уровень %s=%r, использован INFO", LOG_LEVEL_ENV, raw)


def _parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="python -m epgu_mcp",
        description="MCP-сервер EPGU (stdio). Этап 1: только профиль knowledge.",
    )
    p.add_argument("--profile", default="knowledge", help="профиль: knowledge (по умолчанию)")
    p.add_argument(
        "--extension", action="append", default=[], metavar="NAME",
        help=f"включить расширение по имени entry point (можно повторять; также {EXTENSIONS_ENV} "
             "через запятую). По умолчанию расширения не загружаются",
    )
    p.add_argument("--no-extensions", action="store_true",
                   help=f"не загружать расширения, даже если они перечислены в {EXTENSIONS_ENV}")
    p.add_argument("--version", action="version", version=f"epgu-mcp {__version__}")
    return p


def _enabled_extensions(cli: list[str]) -> list[str]:
    env = [n.strip() for n in os.environ.get(EXTENSIONS_ENV, "").split(",") if n.strip()]
    return list(dict.fromkeys([*cli, *env]))


def main(argv: Sequence[str] | None = None) -> int:
    for stream in (sys.stderr, sys.stdout):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[union-attr]
        except (AttributeError, ValueError):
            pass
    try:
        args = _parser().parse_args(argv)
    except SystemExit as exc:  # argparse сам пишет в stderr
        return int(exc.code) if isinstance(exc.code, int) else EXIT_USAGE

    if args.profile not in PROFILES:
        _eprint(f"неизвестный профиль {args.profile!r}; допустимые значения: {', '.join(PROFILES)}")
        return EXIT_USAGE
    if args.profile not in AVAILABLE_PROFILES:
        _eprint(
            f"профиль {args.profile} недоступен на этапе 1; доступен только "
            f"{', '.join(AVAILABLE_PROFILES)}"
        )
        return EXIT_USAGE

    configure_logging()

    from epgu_knowledge import InvalidDataset, KnowledgeError

    from .server import KNOWLEDGE_PATH_ENV, build_registry, build_server, load_knowledge

    # Загрузка проверяет схему и ссылки; при ошибке tools не регистрируются.
    try:
        kb = load_knowledge()
    except KnowledgeError as exc:
        _eprint(f"набор знаний не загружен: {exc}")
        if isinstance(exc, InvalidDataset):
            for problem in exc.errors[:5]:
                _eprint(f"  {problem[:300]}")
        return EXIT_DATA
    if os.environ.get(KNOWLEDGE_PATH_ENV):
        log.info("набор знаний взят из %s", KNOWLEDGE_PATH_ENV)

    registry = build_registry(args.profile, kb)
    enabled = [] if args.no_extensions else _enabled_extensions(args.extension)
    if enabled:
        load_extensions(registry, args.profile, enabled)
    server = build_server(registry)
    log.info("запуск: профиль %s, tools: %s", args.profile, ", ".join(registry.names()))

    from mcp.server.stdio import stdio_server

    async def run() -> None:
        async with stdio_server() as (read_stream, write_stream):
            await server.run(read_stream, write_stream, server.create_initialization_options())

    try:
        anyio.run(run)
    except KeyboardInterrupt:
        pass
    log.info("остановка")
    return 0
