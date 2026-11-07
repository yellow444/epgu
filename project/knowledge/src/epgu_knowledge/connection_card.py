"""Детерминированный разбор отметок человека, без проверки внешних систем.

Таблица содержит только равенства и списки допустимых значений. Это справочный
калькулятор одного TEST-маршрута, не разрешение выполнить действие.
"""
from __future__ import annotations

import copy
import json
from functools import lru_cache
from typing import Any

from jsonschema import Draft202012Validator

from .base import _canonical_hash, _read_resource, load
from .errors import InvalidDataset, KnowledgeError

STATES = ("unknown", "reported_yes", "reported_no")
FACTS = (
    "same_context", "system_registered", "cert_bound", "application_submitted",
    "application_received", "power_visible", "power_issued", "key_configured",
    "local_signature_valid", "server_signature_accepted", "signature_context_checked",
    "error_recorded",
)
GOALS = ("request_power", "check_signature", "obtain_api_key")


def _object(properties: dict, required: list) -> dict:
    return {"type": "object", "properties": properties, "required": required,
            "additionalProperties": False}


def connection_card_input_schema() -> dict:
    return _object({"goal": {"enum": list(GOALS)}, "facts": _object(
        {key: {"enum": list(STATES)} for key in FACTS}, [])}, ["goal"])


def connection_card_schema() -> dict:
    return json.loads(_read_resource(("schema", "connection_card.v1.schema.json")))


def connection_card_output_schema() -> dict:
    return _object({
        "schema_version": {"const": "connection-card-assessment.v1"},
        "definition_version": {"type": "string"}, "contour": {"const": "TEST"},
        "basis": {"const": "caller_reported"}, "notice": {"type": "string"},
        "goal": {"enum": list(GOALS)},
        "reported_facts": _object({key: {"enum": list(STATES)} for key in FACTS}, []),
        "unknown_facts": {"type": "array", "items": {"enum": list(FACTS)}, "uniqueItems": True},
        "rule": connection_card_schema()["$defs"]["rule"],
    }, ["schema_version", "definition_version", "contour", "basis", "notice", "goal",
        "reported_facts", "unknown_facts", "rule"])


class ConnectionCard:
    """Проверенный набор правил. Входы и ответы не сохраняются."""

    def __init__(self, data: Any) -> None:
        validator = Draft202012Validator(connection_card_schema())
        if not validator.is_valid(data):
            raise InvalidDataset("invalid_dataset", ["нарушена схема карточки"], total=1)
        errors = []
        if [s["id"] for s in data["states"]] != list(STATES):
            errors.append("неверный набор состояний")
        if {f["id"] for f in data["facts"]} != set(FACTS) or len(data["facts"]) != len(FACTS):
            errors.append("неверный набор фактов")
        if {g["id"] for g in data["goals"]} != set(GOALS) or len(data["goals"]) != len(GOALS):
            errors.append("неверный набор целей")
        kb = load()
        for goal in data["goals"]:
            if len(set(goal["facts"])) != len(goal["facts"]) or not set(goal["facts"]) <= set(FACTS):
                errors.append("неверные факты цели")
            if not goal["rules"] or goal["rules"][-1]["when"] != {}:
                errors.append("отсутствует завершающее правило")
            ids = [r["id"] for r in goal["rules"]]
            if len(set(ids)) != len(ids):
                errors.append("повторное правило")
            for index, rule in enumerate(goal["rules"]):
                if not set(rule["when"]) <= set(goal["facts"]):
                    errors.append("правило использует посторонний факт")
                if not rule["when"] and index != len(goal["rules"]) - 1:
                    errors.append("преждевременное завершающее правило")
                kb.get_node(rule["reference"]["route"], rule["reference"]["node"])
                for source in rule["source_ids"]:
                    kb.get_source(source)
        if errors:
            raise InvalidDataset("invalid_dataset", errors[:20], total=len(errors))
        self._data = copy.deepcopy(data)
        self._hash = _canonical_hash(self._data)

    @property
    def content_sha256(self) -> str:
        return self._hash

    def document(self) -> dict:
        return copy.deepcopy(self._data)

    def evaluate(self, payload: Any) -> dict:
        if not Draft202012Validator(connection_card_input_schema()).is_valid(payload):
            # Не отражаем в ошибке неизвестные поля, произвольные значения и секреты.
            raise KnowledgeError("invalid_parameter", "нужны цель и только допустимые отметки карточки")
        goal = next(g for g in self._data["goals"] if g["id"] == payload["goal"])
        supplied = payload.get("facts", {})
        facts = {key: supplied.get(key, "unknown") for key in goal["facts"]}
        rule = next(rule for rule in goal["rules"] if all(
            facts[key] in expected if isinstance(expected, list) else facts[key] == expected
            for key, expected in rule["when"].items()
        ))
        return {
            "schema_version": "connection-card-assessment.v1",
            "definition_version": self._data["version"], "contour": "TEST",
            "basis": "caller_reported", "notice": self._data["notice"], "goal": goal["id"],
            "reported_facts": facts, "unknown_facts": [key for key, value in facts.items() if value == "unknown"],
            "rule": copy.deepcopy(rule),
        }


@lru_cache(maxsize=1)
def load_connection_card() -> ConnectionCard:
    try:
        data = json.loads(_read_resource(("data", "connection_card.v1.json")))
    except (OSError, UnicodeDecodeError, ValueError) as exc:
        raise KnowledgeError("invalid_dataset", "карточка недоступна") from exc
    return ConnectionCard(data)
