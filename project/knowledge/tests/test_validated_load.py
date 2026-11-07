"""Загрузка с проверкой: повреждённые наборы не индексируются, проверка не падает."""
import json

import pytest

from epgu_knowledge import InvalidDataset, KnowledgeBase, KnowledgeError, limits, load


def _raises_invalid(path, code="invalid_dataset"):
    with pytest.raises(InvalidDataset) as exc:
        load(path)
    assert exc.value.code == code
    assert exc.value.total >= 1 and exc.value.errors
    assert str(path.parent) not in exc.value.message
    return exc.value


def test_package_dataset_loads_validated():
    assert load().meta()["schema_version"] == limits.SCHEMA_VERSION


def test_empty_object_rejected(tmp_path):
    p = tmp_path / "empty.json"
    p.write_text("{}", encoding="utf-8")
    err = _raises_invalid(p, code="unsupported_version")
    assert err.total == len(load(p, validate=False).validate())


def test_unsupported_version(write_dataset):
    _raises_invalid(write_dataset(lambda d: d.update(schema_version="2.0")), "unsupported_version")


@pytest.mark.parametrize("mutate", [
    lambda d: d["sources"][0].update(id=[]),
    lambda d: d["sources"][0].update(id={"x": 1}),
    lambda d: d["routes"][0].update(id=[1]),
    lambda d: d["routes"][0].update(entry_node=["a"]),
    lambda d: d["routes"][0]["nodes"][0].update(id={}),
    lambda d: d["routes"][0]["nodes"][0]["next"].append({"to": ["x"]}),
    lambda d: d["routes"][0]["nodes"][0]["sources"].append([]),
    lambda d: d["notes"][0].update(id=[], sources=[{"a": 1}]),
], ids=["source-id-list", "source-id-dict", "route-id", "entry-node", "node-id",
        "edge-to", "node-source-ref", "note-id-and-ref"])
def test_malformed_types_reported_not_raised(write_dataset, mutate):
    path = write_dataset(mutate)
    errs = load(path, validate=False).validate()
    assert errs and all(isinstance(e, str) for e in errs)
    assert any(e.startswith("schema:") for e in errs)
    _raises_invalid(path)


def test_unhashable_source_id_direct():
    errs = KnowledgeBase({"sources": [{"id": []}]}).validate()
    assert errs and not any(e.startswith("validator:") for e in errs)


def test_duplicate_ids_rejected(write_dataset):
    def mutate(d):
        d["routes"].append(dict(d["routes"][0]))
        d["notes"].append(dict(d["notes"][0]))

    err = _raises_invalid(write_dataset(mutate))
    assert any("повторный id маршрута" in e for e in err.errors)
    assert any("повторный id заметки" in e for e in err.errors)


def test_dangling_refs_rejected(write_dataset):
    def mutate(d):
        d["routes"][0]["nodes"][0]["next"].append({"to": "nowhere", "label": "x"})

    _raises_invalid(write_dataset(mutate))


def test_invalid_not_cached_as_valid(write_dataset):
    path = write_dataset(lambda d: d.update(schema_version="9"))
    for _ in range(2):
        with pytest.raises(InvalidDataset):
            load(path)


def test_reported_errors_are_capped(tmp_path, raw_data):
    data = json.loads(json.dumps(raw_data))
    for src in data["sources"]:
        src["url"] = "http://insecure.example/"
    p = tmp_path / "many.json"
    p.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    err = _raises_invalid(p)
    assert err.total == len(data["sources"]) > len(err.errors) == 20


def test_unreadable_message_has_no_path(tmp_path):
    with pytest.raises(KnowledgeError) as exc:
        load(tmp_path / "missing.json")
    assert exc.value.code == "unreadable_dataset"
    assert str(tmp_path) not in str(exc.value)


def test_limits_match_search(kb):
    kb.search("а" * limits.MAX_QUERY_LEN)
    with pytest.raises(ValueError):
        kb.search("а" * (limits.MAX_QUERY_LEN + 1))
    with pytest.raises(ValueError):
        kb.search("api", cursor="A" * (limits.MAX_CURSOR_LEN + 1))
    kb.search("api", limit=limits.MAX_LIMIT)
    with pytest.raises(ValueError):
        kb.search("api", limit=limits.MAX_LIMIT + 1)


def test_ids_fit_limit(raw_data):
    ids = [s["id"] for s in raw_data["sources"]] + [n["id"] for n in raw_data["notes"]]
    for r in raw_data["routes"]:
        ids.append(r["id"])
        ids.extend(n["id"] for n in r["nodes"])
    assert max(map(len, ids)) <= limits.MAX_ID_LEN
