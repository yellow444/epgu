"""Механизм расширений: entry point group ``epgu_mcp.extensions``.

Расширение это функция ``register(server, profile)``. Первый аргумент это
промежуточный набор ``ExtensionRegistrar`` с методом ``add_tool(ToolSpec)``,
второй имя профиля. Расширение не получает основной реестр: удалить или
заменить уже принятые tools оно не может. Набор проверяется правилами профиля
и сливается в реестр одним шагом только после успешного возврата ``register``.
Расширение, которое упало или нарушило правила, пропускается целиком.

Расширения загружаются только по явному списку (``--extension`` или
EPGU_MCP_EXTENSIONS); остальные найденные entry points не импортируются.
Расширение это доверенный код: ``entry_point.load()`` исполняет его с правами
процесса, а аннотации ToolSpec не доказывают отсутствие обращений наружу.
"""
from __future__ import annotations

import logging
from collections.abc import Collection, Iterable
from importlib import metadata
from typing import Any

from .registry import ProfileViolation, ToolRegistry, ToolSpec

GROUP = "epgu_mcp.extensions"
log = logging.getLogger("epgu_mcp.extensions")


def _iter_entry_points() -> Iterable[Any]:
    """Точка подмены в тестах."""
    return metadata.entry_points(group=GROUP)


class ExtensionRegistrar:
    """Промежуточный набор tools одного расширения."""

    def __init__(self, registry: ToolRegistry) -> None:
        self.profile = registry.profile
        # Отдельный реестр того же профиля проверяет правила профиля и дубли.
        self._staged = ToolRegistry(registry.profile)
        self._taken = frozenset(registry.names())

    def add_tool(self, spec: ToolSpec) -> None:
        if isinstance(spec, ToolSpec) and spec.name in self._taken:
            raise ProfileViolation(f"{spec.name}: tool с таким именем уже есть")
        self._staged.add_tool(spec)

    def specs(self) -> list[ToolSpec]:
        return self._staged.specs()


def load_extensions(
    registry: ToolRegistry, profile: str, enabled: Collection[str] = ()
) -> list[tuple[str, str]]:
    """Загрузить разрешённые расширения. Возвращает список (имя, причина отказа)."""
    failures: list[tuple[str, str]] = []
    wanted = set(enabled)
    seen: set[str] = set()
    for ep in _iter_entry_points():
        name = getattr(ep, "name", repr(ep))
        if name not in wanted:
            log.debug("расширение %s не включено, пропущено", name)
            continue
        if name in seen:
            failures.append((name, "повторное имя расширения"))
            log.error("расширение %s отклонено: повторное имя", name)
            continue
        seen.add(name)
        try:
            register = ep.load()
            staging = ExtensionRegistrar(registry)
            register(staging, profile)
            registry.merge(staging.specs())
        except Exception as exc:  # расширение не должно ронять сервер
            reason = f"{type(exc).__name__}: {exc}"
            failures.append((name, reason))
            log.error("расширение %s отклонено: %s", name, reason)
        else:
            log.info("расширение %s загружено", name)
    for name in sorted(wanted - seen):
        failures.append((name, "не найдено"))
        log.error("расширение %s не найдено", name)
    return failures
