"""Границы справочной диагностики: неизвестное и сведения человека не доказательства."""
import copy
import itertools
import json

import pytest
from epgu_knowledge import (
    ConnectionCard,
    KnowledgeError,
    connection_card_input_schema,
    connection_card_output_schema,
    connection_card_schema,
    load_connection_card,
)
from epgu_knowledge.connection_card import STATES
from jsonschema import Draft202012Validator


def evaluate(goal="request_power", **facts):
    return load_connection_card().evaluate({"goal": goal, "facts": facts})


@pytest.mark.parametrize("goal", ["request_power", "check_signature", "obtain_api_key"])
def test_unknown_is_insufficient_not_failure(goal):
    result = evaluate(goal)
    assert result["rule"]["id"] == "context_unknown"
    assert result["basis"] == "caller_reported"
    assert result["unknown_facts"] == list(result["reported_facts"])
    assert not {"ready", "authorized", "connected", "granted"} & result.keys()


@pytest.mark.parametrize("goal,facts,rule", [
    ("request_power", {"system_registered": "reported_yes", "cert_bound": "reported_yes",
                       "power_visible": "reported_no"}, "application_history_unknown"),
    ("request_power", {"application_submitted": "reported_yes", "power_visible": "reported_no"}, "application_pending"),
    ("request_power", {"application_received": "reported_yes"}, "receipt_pending"),
    ("request_power", {"application_received": "reported_yes", "application_submitted": "reported_no"}, "receipt_vs_submission"),
    ("request_power", {"power_issued": "reported_yes", "power_visible": "reported_no"}, "issued_not_visible"),
    ("request_power", {"system_registered": "reported_yes", "cert_bound": "reported_yes",
                       "application_submitted": "reported_no"}, "request_power"),
    ("check_signature", {"local_signature_valid": "reported_yes", "server_signature_accepted": "reported_no",
                         "error_recorded": "reported_yes", "cert_bound": "reported_yes",
                         "signature_context_checked": "reported_yes"}, "signature_rejected_unexplained"),
    ("check_signature", {"local_signature_valid": "reported_yes", "server_signature_accepted": "reported_no"}, "error_not_recorded"),
    ("check_signature", {"local_signature_valid": "reported_yes"}, "server_result_unknown"),
    ("check_signature", {"local_signature_valid": "reported_no", "server_signature_accepted": "reported_yes"}, "signature_reports_differ"),
    ("obtain_api_key", {"power_issued": "reported_yes"}, "formation_route"),
    ("obtain_api_key", {"key_configured": "reported_yes"}, "key_configured_reported"),
    ("obtain_api_key", {"key_configured": "reported_yes", "power_issued": "reported_no"}, "key_rights_differ"),
])
def test_counterexamples(goal, facts, rule):
    result = evaluate(goal, same_context="reported_yes", **facts)
    assert result["rule"]["id"] == rule
    assert result["basis"] == "caller_reported"


@pytest.mark.parametrize("payload", [None, [], {}, {"goal": "PROD"}, {"goal": "constructor"},
    {"goal": "request_power", "facts": None}, {"goal": "request_power", "facts": []},
    {"goal": "request_power", "facts": {"__proto__": "reported_yes"}},
    {"goal": "request_power", "facts": {"constructor": "reported_yes"}},
    {"goal": "request_power", "facts": {"same_context": True}},
    {"goal": "request_power", "facts": {"same_context": "SECRET_MARKER"}},
    {"goal": "request_power", "SECRET_MARKER": "SECRET_MARKER"}])
def test_closed_input_without_value_echo(payload):
    with pytest.raises(KnowledgeError) as exc:
        load_connection_card().evaluate(payload)
    assert exc.value.code == "invalid_parameter"
    assert "SECRET_MARKER" not in str(exc.value)


def test_dataset_and_schemas_are_valid():
    for schema in (connection_card_schema(), connection_card_input_schema(), connection_card_output_schema()):
        Draft202012Validator.check_schema(schema)
    card = load_connection_card()
    Draft202012Validator(connection_card_schema()).validate(card.document())
    Draft202012Validator(connection_card_output_schema()).validate(evaluate())


def test_every_rule_reachable_and_no_cross_goal_dependency():
    card = load_connection_card()
    for goal in card.document()["goals"]:
        reached = set()
        for values in itertools.product(STATES, repeat=len(goal["facts"])):
            facts = dict(zip(goal["facts"], values))
            result = card.evaluate({"goal": goal["id"], "facts": facts})
            reached.add(result["rule"]["id"])
            assert set(result["reported_facts"]) == set(goal["facts"])
        assert reached == {rule["id"] for rule in goal["rules"]}
    base = evaluate(system_registered="reported_yes", cert_bound="reported_yes",
                    application_submitted="reported_no", same_context="reported_yes")
    extra = evaluate(system_registered="reported_yes", cert_bound="reported_yes",
                     application_submitted="reported_no", same_context="reported_yes",
                     key_configured="reported_no", local_signature_valid="reported_no")
    assert extra == base


def test_returned_objects_cannot_mutate_the_rules():
    card = load_connection_card()
    result = evaluate()
    result["rule"]["summary"] = "changed"
    document = card.document()
    document["goals"].clear()
    assert evaluate()["rule"]["summary"] != "changed"
    assert card.document()["goals"]


@pytest.mark.parametrize("change", ["source", "node", "fact", "duplicate", "fallback"])
def test_broken_definitions_fail_closed(change):
    data = copy.deepcopy(load_connection_card().document())
    goal = data["goals"][0]
    rule = goal["rules"][0]
    if change == "source":
        rule["source_ids"] = ["missing"]
    elif change == "node":
        rule["reference"]["node"] = "missing"
    elif change == "fact":
        rule["when"] = {"local_signature_valid": "reported_yes"}
    elif change == "duplicate":
        goal["rules"][1]["id"] = rule["id"]
    else:
        goal["rules"][-1]["when"] = {"same_context": "reported_yes"}
    with pytest.raises(KnowledgeError):
        ConnectionCard(data)


def test_no_values_or_secret_material_in_dataset():
    text = json.dumps(load_connection_card().document(), ensure_ascii=False)
    for forbidden in ("LBR261030", "7704706116", "5087746493654", "@mirasnowfox", "BEGIN PRIVATE", "Bearer "):
        assert forbidden not in text
