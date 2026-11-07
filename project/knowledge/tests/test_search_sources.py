"""Ссылки на источники в выдаче поиска: договор поля source_ids.

Ожидание строится по самому набору (JSON), а не по коду поиска: для узла и
заметки это их поле sources, для источника его id, для маршрута пустой
список. Порядок как в наборе, без повторов, только известные источники.
"""
import copy

import pytest

from epgu_knowledge import KnowledgeBase, load

QUERIES = ["api", "подпись", "сертификат", "регламент", "заявк", "есиа", "смэв", "источник"]


def expected_refs(data, item):
    known = {s["id"] for s in data["sources"]}
    if item["type"] == "source":
        return [item["id"]]
    if item["type"] == "route":
        return []
    if item["type"] == "note":
        refs = next(n for n in data["notes"] if n["id"] == item["id"])["sources"]
    else:
        route = next(r for r in data["routes"] if r["id"] == item["route_id"])
        refs = next(n for n in route["nodes"] if n["id"] == item["node_id"])["sources"]
    out = []
    for s in refs:
        if s in known and s not in out:
            out.append(s)
    return out


def all_hits(kb, **kw):
    seen = {}
    for q in QUERIES:
        for item in kb.search(q, limit=50, **kw)["items"]:
            seen[(item["type"], item["route_id"], item["id"])] = item
    return list(seen.values())


def test_package_dataset_refs_match_the_data(kb, raw_data):
    hits = all_hits(kb)
    kinds = {h["type"] for h in hits}
    assert kinds == {"route", "node", "note", "source"}, "запросы должны задеть все типы"
    for item in hits:
        assert item["source_ids"] == expected_refs(raw_data, item), item["id"]


def test_every_listed_source_opens(kb):
    for item in all_hits(kb):
        for sid in item["source_ids"]:
            assert kb.get_source(sid)["id"] == sid


def test_id_and_type_are_kept(kb, raw_data):
    note_ids = {n["id"] for n in raw_data["notes"]}
    source_ids = {s["id"] for s in raw_data["sources"]}
    for item in all_hits(kb):
        if item["type"] == "note":
            assert item["id"] in note_ids and item["id"] not in source_ids
        if item["type"] == "source":
            assert item["source_ids"] == [item["id"]]


def test_route_hits_get_no_aggregated_sources(kb, raw_data):
    routes = [h for h in all_hits(kb) if h["type"] == "route"]
    assert routes
    with_node_refs = 0
    for item in routes:
        route = next(r for r in raw_data["routes"] if r["id"] == item["id"])
        with_node_refs += any(n["sources"] for n in route["nodes"])
        assert item["source_ids"] == []
    assert with_node_refs, "нужен маршрут, у узлов которого есть источники"


def test_domain_filter_keeps_node_refs(kb, raw_data):
    hits = kb.search("подпись", limit=50, domain="esia")["items"]
    assert hits
    for item in hits:
        assert item["source_ids"] == expected_refs(raw_data, item)


def test_pages_carry_the_same_refs(kb):
    full = kb.search("api", limit=50)["items"]
    assert len(full) >= 4
    collected, cursor = [], None
    while True:
        page = kb.search("api", limit=3, cursor=cursor)
        collected.extend(page["items"])
        cursor = page["next_cursor"]
        if cursor is None:
            break
    assert collected == full


def _tiny(node_sources, note_sources):
    return {
        "schema_version": "knowledge.v1",
        "dataset": {"id": "t", "reviewed_at": "2026-11-04"},
        "sources": [
            {"id": "srcA", "title": "Источник А", "url": "https://example.invalid/a",
             "section": "раздел", "kind_label": "x", "officiality": "official"},
            {"id": "srcB", "title": "Источник Б", "url": "https://example.invalid/b",
             "section": "раздел", "kind_label": "x", "officiality": "official"},
        ],
        "routes": [{
            "id": "r1", "title": "Маршрут зебра", "summary": "зебра", "domain": "epgu",
            "coverage": {"status": "informational", "capabilities": [], "note": ""},
            "entry_node": "n1",
            "nodes": [{"id": "n1", "title": "Узел зебра", "body": "зебра", "checks": [],
                       "sources": node_sources, "next": [], "warning": None, "layout": {}}],
        }],
        "notes": [{"id": "note1", "title": "Заметка зебра", "status": "x", "text": "зебра",
                   "sources": note_sources}],
    }


def by_type(kb, query="зебра"):
    return {i["type"]: i for i in kb.search(query, limit=50)["items"]}


def test_duplicates_are_dropped_in_dataset_order():
    kb = KnowledgeBase(_tiny(["srcB", "srcA", "srcB"], ["srcA", "srcA"]))
    hits = by_type(kb)
    assert hits["node"]["source_ids"] == ["srcB", "srcA"]
    assert hits["note"]["source_ids"] == ["srcA"]
    assert hits["route"]["source_ids"] == []


def test_empty_refs_stay_empty():
    hits = by_type(KnowledgeBase(_tiny([], [])))
    assert hits["node"]["source_ids"] == [] and hits["note"]["source_ids"] == []


def test_unknown_ref_is_not_invented_or_passed_through():
    data = _tiny(["srcA", "srcGhost"], ["srcGhost"])
    kb = KnowledgeBase(data)
    hits = by_type(kb)
    assert hits["node"]["source_ids"] == ["srcA"]
    assert hits["note"]["source_ids"] == []
    errors = KnowledgeBase(copy.deepcopy(data)).validate()
    assert any("srcGhost" in e for e in errors), "такой набор load() не пропустит"


def test_validated_load_accepts_duplicate_refs(write_dataset):
    def mutate(d):
        node = d["routes"][0]["nodes"][0]
        if node["sources"]:
            node["sources"] = node["sources"] + node["sources"][:1]

    kb = load(write_dataset(mutate))
    node = kb.dataset()["routes"][0]["nodes"][0]
    for item in kb.search(node["title"], limit=50)["items"]:
        if item["type"] == "node" and item["id"] == node["id"]:
            assert len(item["source_ids"]) == len(set(item["source_ids"]))
            break
    else:
        pytest.fail("узел не найден по своему заголовку")


def test_item_keys_are_exact(kb):
    for item in all_hits(kb):
        assert set(item) == {"type", "route_id", "node_id", "id", "title", "snippet", "score",
                             "source_ids"}
