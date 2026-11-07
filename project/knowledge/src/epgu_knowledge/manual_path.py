"""Ручной маршрут подключения: один источник текстов для HTTP, MCP и интерфейса.

Набор статический и только читается. Значения организации в нём нет и сюда они
не передаются: человек заполняет их у себя. Происхождение из исходника интерфейса
не является проверкой доступности внешних кабинетов.
"""
from __future__ import annotations

import copy
import json
import re
from functools import lru_cache
from typing import Any
from urllib.parse import urlparse

from .base import _canonical_hash, _read_resource
from .errors import InvalidDataset, KnowledgeError

MANUAL_SCHEMA_VERSION = "manual-path.v1"
_DATA_RESOURCE = ("data", "manual_path.v1.json")
_SCHEMA_RESOURCE = ("schema", "manual_path.v1.schema.json")
_MAX_REPORTED = 20

# Настоящие значения и секреты в публичных данных, а не слова «ИНН» или «OID».
_FORBIDDEN_VALUES = (
    ("почтовый адрес", re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+")),
    ("длинное число", re.compile(r"\d{5,}")),
    ("OID", re.compile(r"\d+(?:\.\d+){3,}")),
    ("шестнадцатеричное значение", re.compile(r"\b[0-9a-fA-F]{32,}\b")),
    ("токен", re.compile(r"\beyJ[\w-]{8,}|\bBearer\s+\S")),
    ("ключевой материал", re.compile(r"-----BEGIN ")),
)


def manual_path_schema() -> dict:
    """Схема набора (копия): выходная схема MCP берётся отсюда, а не описывается заново."""
    return json.loads(_read_resource(_SCHEMA_RESOURCE).decode("utf-8"))


def _strings(value: Any, path: str):
    if isinstance(value, str):
        yield path, value
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _strings(item, f"{path}/{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            yield from _strings(item, f"{path}/{index}")


def _repeated(items: list, where: str) -> list:
    seen: set = set()
    errors = []
    for item in items:
        if item["id"] in seen:
            errors.append(f"integrity: {where}: повторный id {item['id']!r}")
        seen.add(item["id"])
    return errors


def _check_integrity(data: dict) -> list:
    errors = []
    for where in ("link_kinds", "links", "steps", "fields"):
        errors += _repeated(data[where], f"/{where}")
    kinds = {kind["id"] for kind in data["link_kinds"]}
    pairs = set()
    for link in data["links"]:
        where = f"/links/{link['id']}"
        pairs.add((link["kind"], link["contour"]))
        if link["kind"] not in kinds:
            errors.append(f"integrity: {where}: неизвестный вид {link['kind']!r}")
        if not link["label"].startswith(f"{link['contour']}:"):
            errors.append(f"integrity: {where}: подпись не называет контур {link['contour']}")
        host = urlparse(link["url"]).hostname or ""
        if (".test." in host) != (link["contour"] == "TEST"):
            errors.append(f"integrity: {where}: адрес не соответствует контуру {link['contour']}")
    for kind in kinds:
        for contour in data["contours"]:
            if (kind, contour) not in pairs:
                errors.append(f"integrity: /link_kinds: для {kind!r} нет ссылки контура {contour}")
    for step in data["steps"]:
        for kind in step["link_kinds"]:
            if kind not in kinds:
                errors.append(f"integrity: /steps/{step['id']}: неизвестный вид ссылки {kind!r}")
    for path, text in _strings(data, ""):
        if path.endswith("/url") or path == "/provenance/links_verified_at":
            continue
        for name, pattern in _FORBIDDEN_VALUES:
            if pattern.search(text):
                errors.append(f"values: {path}: похоже на {name}")
    return errors


def check_manual_path(data: Any) -> list:
    """Замечания к набору: схема, связность и запрет настоящих значений."""
    from jsonschema import Draft202012Validator

    validator = Draft202012Validator(
        manual_path_schema(), format_checker=Draft202012Validator.FORMAT_CHECKER
    )
    errors = [
        "schema: /" + "/".join(str(p) for p in err.path) + f": {err.message}"
        for err in sorted(validator.iter_errors(data), key=lambda e: list(map(str, e.path)))
    ]
    return errors or _check_integrity(data)


class ManualPath:
    """Проверенный набор. Все ответы это копии."""

    def __init__(self, data: Any) -> None:
        errors = check_manual_path(data)
        if errors:
            raise InvalidDataset("invalid_dataset", errors[:_MAX_REPORTED], total=len(errors))
        self._data = copy.deepcopy(data)
        self._hash = _canonical_hash(self._data)

    @property
    def content_sha256(self) -> str:
        return self._hash

    def document(self) -> dict:
        return copy.deepcopy(self._data)


@lru_cache(maxsize=1)
def load_manual_path() -> ManualPath:
    """Набор из данных пакета. Повреждённый набор не отдаётся."""
    try:
        data = json.loads(_read_resource(_DATA_RESOURCE).decode("utf-8"))
    except OSError as exc:
        raise KnowledgeError("unreadable_dataset", "ручной маршрут недоступен") from exc
    except (UnicodeDecodeError, ValueError) as exc:
        raise KnowledgeError("invalid_dataset", "ручной маршрут не является JSON") from exc
    return ManualPath(data)
