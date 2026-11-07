"""Ручной маршрут: схема, связность и запрет настоящих значений в публичных данных."""
import copy
import hashlib
import json
from pathlib import Path

import pytest
from epgu_knowledge import (
    InvalidDataset,
    ManualPath,
    load,
    load_manual_path,
    manual_path_schema,
)
from epgu_knowledge.manual_path import check_manual_path

PROJECT = Path(__file__).resolve().parents[2]


@pytest.fixture()
def data():
    return load_manual_path().document()


def test_bundle_has_links_steps_fields_and_template(data):
    assert data["schema_version"] == "manual-path.v1"
    assert [link["id"] for link in data["links"]] == [
        "test-systems", "test-powers", "prod-systems", "prod-powers", "test-tech", "prod-tech"]
    assert [step["id"] for step in data["steps"]] == [
        "organization", "information_system", "powers", "access_check", "request_and_next"]
    ids = {field["id"] for field in data["fields"]}
    assert {"organizationOid", "systemOid", "systemCardId", "organizationName"} <= ids
    assert "Контур: <TEST или PROD, заполните вручную>" in data["letter_template"]["body"]
    assert "Идентификатор карточки ИС: <заполните вручную>" in data["letter_template"]["body"]


def test_every_link_is_https_and_in_its_contour(data):
    for link in data["links"]:
        assert link["url"].startswith("https://")
        assert link["label"].startswith(link["contour"] + ":")
        assert (".test." in link["url"]) == (link["contour"] == "TEST")


def test_external_cabinets_are_not_claimed_as_checked(data):
    assert data["provenance"]["links_availability"] == "not_verified"
    assert data["provenance"]["links_verified_at"] is None
    assert "не проверка" in data["provenance"]["note"]


@pytest.mark.parametrize("status,date", [
    ("verified", None),
    ("not_verified", "2026-11-06"),
    ("verified", "2026-02-31"),
    ("verified", "2026-11-99"),
    ("verified", "yesterday"),
])
def test_inconsistent_or_invalid_verification_dates_are_rejected(data, status, date):
    data["provenance"].update(links_availability=status, links_verified_at=date)
    with pytest.raises(InvalidDataset):
        ManualPath(data)


def test_verified_metadata_can_carry_a_real_calendar_date(data):
    # This checks metadata shape, not the availability of any external site.
    data["provenance"].update(links_availability="verified", links_verified_at="2026-11-06")
    assert check_manual_path(data) == []


def test_template_has_no_recipient_and_stays_unfilled(data):
    assert set(data["letter_template"]) == {"body"}
    body = data["letter_template"]["body"]
    assert "<заполните вручную>" in body
    assert "@" not in body


def test_field_names_may_mention_oid_and_inn_as_words(data):
    data["fields"][0]["label"] = "ИНН и OID организации"
    assert check_manual_path(data) == []


@pytest.mark.parametrize("value", [
    "пишите на support@example.com",
    "OID 1000312345",
    "OID 1.2.643.100.1",
    "ИНН 7707083893",
    "токен eyJhbGciOiJIUzI1NiJ9",
    "Authorization: Bearer abc",
    "a" * 32 + " ключ",
    "-----BEGIN " + "PRIVATE KEY-----",
])
@pytest.mark.parametrize("place", ["template", "hint", "step", "warning"])
def test_real_values_are_refused_anywhere(data, value, place):
    if place == "template":
        data["letter_template"]["body"] += value
    elif place == "hint":
        data["fields"][0]["hint"] = value
    elif place == "step":
        data["steps"][0]["collect"] = value
    else:
        data["warnings"][0] = value
    assert any(item.startswith("values:") for item in check_manual_path(data))


@pytest.mark.parametrize("change,fragment", [
    (lambda d: d["links"][0].update(url="http://svcdev-partners.test.gosuslugi.ru/systems"), "schema:"),
    (lambda d: d["links"][0].update(url="https://user@svcdev-partners.test.gosuslugi.ru/"), "schema:"),
    (lambda d: d["links"][0].update(contour="STAGE"), "schema:"),
    (lambda d: d["links"][0].update(contour="PROD"), "контур"),
    (lambda d: d["links"][2].update(url="https://svcdev-partners.test.gosuslugi.ru/systems"), "контуру"),
    (lambda d: d["links"].pop(0), "нет ссылки контура"),
    (lambda d: d["links"][1].update(id="test-systems"), "повторный id"),
    (lambda d: d["links"][0].update(kind="other"), "неизвестный вид"),
    (lambda d: d["steps"][0].update(link_kinds=["other"]), "неизвестный вид ссылки"),
    (lambda d: d["steps"][1].update(id="organization"), "повторный id"),
    (lambda d: d["fields"][1].update(id=d["fields"][0]["id"]), "повторный id"),
    (lambda d: d["letter_template"].update(to="x"), "schema:"),
    (lambda d: d.update(extra=1), "schema:"),
    (lambda d: d.update(schema_version="manual-path.v2"), "schema:"),
    (lambda d: d["provenance"].update(origin="live_check"), "schema:"),
])
def test_broken_bundle_is_refused(data, change, fragment):
    change(data)
    errors = check_manual_path(data)
    assert any(fragment in item for item in errors), errors
    with pytest.raises(InvalidDataset):
        ManualPath(data)


def test_answers_are_copies_and_the_hash_follows_the_content(data):
    manual = load_manual_path()
    manual.document()["links"].clear()
    assert manual.document()["links"]
    other = copy.deepcopy(data)
    other["notice"] += " Новая редакция."
    assert ManualPath(other).content_sha256 != manual.content_sha256


def test_schema_is_closed_and_read_from_the_package():
    schema = manual_path_schema()
    assert schema["additionalProperties"] is False
    assert schema["properties"]["letter_template"]["additionalProperties"] is False


def test_knowledge_v1_is_independent_of_the_bundle():
    assert "manual" not in json.dumps(sorted(load().dataset()))
    raw = (PROJECT / "knowledge/src/epgu_knowledge/data/knowledge.v1.json").read_bytes()
    assert hashlib.sha256(raw).hexdigest().startswith("62d0774fe8e7")


def test_interface_copy_is_byte_identical_to_the_bundle():
    canon = (PROJECT / "knowledge/src/epgu_knowledge/data/manual_path.v1.json").read_bytes()
    copy_ = (PROJECT / "api-gosuslugi-client/src/components/PublicSetup/manual_path.v1.json").read_bytes()
    assert copy_ == canon
