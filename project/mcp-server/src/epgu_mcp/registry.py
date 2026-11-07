"""Реестр tools и правила профилей.

Профили упорядочены по силе: knowledge < read < operate. Tool может быть
добавлен только в реестр с профилем не ниже собственного. В профилях
knowledge и read допускаются только tools с readOnlyHint=true. Имена целевых
tools операций из ``targets.py`` зарезервированы: ``add_tool`` и ``merge`` не
принимают tool с таким именем ни в одном профиле, даже с копией схем и
аннотаций каталога. Единственный путь к ним ``install_operations``: реестр сам
строит спецификации из каталога и переданного ``OperationsAdapter`` и только в
профиле operate. Расширения этот путь не получают: их набор сливается через
``merge``. Это защита от ошибочной регистрации, а не sandbox от доверенного
кода процесса.
"""
from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from .targets import RESERVED_NAMES

PROFILES = ("knowledge", "read", "operate")
# На этапе 1 запускается только knowledge.
AVAILABLE_PROFILES = ("knowledge",)
_RANK = {name: i for i, name in enumerate(PROFILES)}
_READ_ONLY_PROFILES = ("knowledge", "read")

# Подпись действия: handler получает проверенные аргументы, возвращает dict.
Handler = Callable[[dict[str, Any]], dict[str, Any]]


class ToolError(Exception):
    """Ошибка бизнес-уровня: уходит клиенту как результат с isError=true."""

    def __init__(self, code: str, message: str, data: dict[str, Any] | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        # Подробности, которые уходят клиенту рядом с code и message.
        self.data = dict(data or {})


class ProfileViolation(Exception):
    """Попытка добавить tool, который не разрешён в текущем профиле."""


@dataclass(frozen=True)
class ToolSpec:
    name: str
    description: str
    input_schema: dict[str, Any]
    output_schema: dict[str, Any]
    handler: Handler = field(repr=False, compare=False)
    title: str | None = None
    # Минимальный профиль, в котором tool разрешён.
    profile: str = "knowledge"
    read_only: bool = True
    destructive: bool = False
    idempotent: bool = True
    open_world: bool = False
    # handler ждёт сеть: сервер вызывает его в рабочем потоке, а не в цикле событий.
    blocking: bool = False


class ToolRegistry:
    """Набор tools сервера для одного профиля."""

    def __init__(self, profile: str) -> None:
        if profile not in _RANK:
            raise ValueError(f"неизвестный профиль: {profile!r}")
        self.profile = profile
        self._tools: dict[str, ToolSpec] = {}

    def add_tool(self, spec: ToolSpec) -> None:
        if not isinstance(spec, ToolSpec):
            raise TypeError("ожидается ToolSpec")
        if spec.name in RESERVED_NAMES:
            # Целевые tools операций описаны в targets.py и ещё не включены.
            raise ProfileViolation(f"{spec.name}: имя целевого tool, он не включён ни в одном профиле")
        self._check(spec)
        self._tools[spec.name] = spec

    def install_operations(self, adapter: Any) -> None:
        """Tools операций из каталога и HTTP-адаптера, только в явно собранном реестре operate.

        Готовые ToolSpec сюда не передаются: спецификации строит ``operations.py``
        из ``targets.py``. Установка целиком или ничего.
        """
        from .operations import OperationsAdapter, operation_specs

        if self.profile != "operate":
            raise ProfileViolation(f"операции ставятся только в профиль operate, не {self.profile}")
        if type(adapter) is not OperationsAdapter:
            raise TypeError("ожидается OperationsAdapter")
        specs = operation_specs(adapter)
        if {s.name for s in specs} != RESERVED_NAMES:
            raise ProfileViolation("набор операций не совпадает с каталогом")
        trial = dict(self._tools)
        for spec in specs:
            self._check(spec, trial)
            trial[spec.name] = spec
        self._tools = trial

    def _check(self, spec: ToolSpec, tools: dict[str, ToolSpec] | None = None) -> None:
        if spec.profile not in _RANK:
            raise ProfileViolation(f"{spec.name}: неизвестный профиль tool {spec.profile!r}")
        if _RANK[spec.profile] > _RANK[self.profile]:
            raise ProfileViolation(
                f"{spec.name}: tool профиля {spec.profile} нельзя добавить в профиль {self.profile}"
            )
        if self.profile in _READ_ONLY_PROFILES and (
            not spec.read_only or spec.destructive or spec.open_world
        ):
            raise ProfileViolation(
                f"{spec.name}: в профиле {self.profile} допустимы только read-only tools "
                "без побочных эффектов и обращений наружу"
            )
        if spec.name in (self._tools if tools is None else tools):
            raise ProfileViolation(f"{spec.name}: tool с таким именем уже есть")

    def merge(self, specs: list[ToolSpec]) -> None:
        """Добавить набор tools целиком или не добавить ничего."""
        trial = ToolRegistry(self.profile)
        trial._tools = dict(self._tools)
        for spec in specs:
            trial.add_tool(spec)
        self._tools = trial._tools

    def get(self, name: str) -> ToolSpec | None:
        return self._tools.get(name)

    def names(self) -> list[str]:
        return list(self._tools)

    def specs(self) -> list[ToolSpec]:
        return list(self._tools.values())
