import base64

import pytest

from epgu_knowledge import KnowledgeError, NotFound


def test_not_found_is_knowledge_error():
    assert issubclass(NotFound, KnowledgeError)
    err = NotFound("x")
    assert err.code == "not_found" and err.message == "x"


def test_meta(kb):
    meta = kb.meta()
    assert meta["schema_version"] == "1.0"
    assert meta["dataset"]["id"] == "epgu-integration-guide"
    assert set(meta["counts"]) == {"routes", "nodes", "sources", "notes"}


def test_list_routes_shape_and_order(kb, raw_data):
    routes = kb.list_routes()
    assert [r["id"] for r in routes] == [r["id"] for r in raw_data["routes"]]
    assert set(routes[0]) == {"id", "title", "summary", "domain", "coverage",
                              "entry_node", "node_count"}
    assert sum(r["node_count"] for r in routes) == 51


def test_get_route_and_node(kb):
    route = kb.get_route("epgu-vendor")
    assert route["entry_node"] == "start"
    assert [n["id"] for n in route["nodes"]][0] == "start"
    node = kb.get_node("epgu-vendor", "cabinet")
    assert {"incoming", "sources_resolved"} <= set(node)
    assert {i["from"] for i in node["incoming"]} == {"start"}
    assert [s["id"] for s in node["sources_resolved"]] == node["sources"]
    assert kb.get_node("epgu-vendor", "start")["incoming"] == []


def test_not_found(kb):
    with pytest.raises(NotFound):
        kb.get_route("nope")
    with pytest.raises(NotFound):
        kb.get_node("nope", "start")
    with pytest.raises(NotFound):
        kb.get_node("epgu-vendor", "nope")
    with pytest.raises(NotFound):
        kb.get_source("nope")
    with pytest.raises(NotFound):
        kb.get_route(None)  # type: ignore[arg-type]


def test_sources(kb):
    allsrc = kb.list_sources()
    assert len(allsrc) == 28
    official = kb.list_sources("official")
    assert official and all(s["officiality"] == "official" for s in official)
    with pytest.raises(ValueError):
        kb.list_sources("bogus")
    src = kb.get_source("apiCabinet")
    assert src["used_by"]
    assert all({"route", "node"} == set(u) for u in src["used_by"])
    node = kb.get_node(src["used_by"][0]["route"], src["used_by"][0]["node"])
    assert "apiCabinet" in node["sources"]


def test_notes(kb):
    notes = kb.list_notes()
    assert [n["id"] for n in notes] == [f"note-{i:02d}" for i in range(1, 10)]


# --- поиск -------------------------------------------------------------------

def test_search_case_insensitive(kb):
    a = kb.search("регламент", limit=50)
    b = kb.search("РЕГЛАМЕНТ", limit=50)
    assert a == b and a["items"]


def test_search_yo_equals_ye(kb):
    # в данных встречается «приём» и «прием» в разных написаниях; проверяем симметрию
    a = kb.search("приём", limit=50)
    b = kb.search("прием", limit=50)
    assert a == b
    a2 = kb.search("ПРИЁМ", limit=50)
    assert a2 == a


def test_search_yo_in_fixture(write_dataset):
    from epgu_knowledge import load

    def mutate(d):
        d["notes"][0]["text"] = "Ёлка и всё остальное"

    kb = load(write_dataset(mutate))
    ids = {i["id"] for i in kb.search("елка все")["items"]}
    assert "note-01" in ids
    ids = {i["id"] for i in kb.search("ЁЛКА всё")["items"]}
    assert "note-01" in ids


def test_search_domain_filter(kb):
    all_hits = kb.search("подпись", limit=50)["items"]
    esia = kb.search("подпись", limit=50, domain="esia")["items"]
    assert esia and len(esia) < len(all_hits)
    assert all(i["type"] in ("route", "node") for i in esia)
    domains = {r["id"]: r["domain"] for r in kb.list_routes()}
    assert all(domains[i["route_id"]] == "esia" for i in esia)
    with pytest.raises(ValueError):
        kb.search("подпись", domain="bogus")


@pytest.mark.parametrize("limit", [0, -1, 51, 1000, True, "5", 2.5, None])
def test_search_limit_bounds(kb, limit):
    with pytest.raises(ValueError):
        kb.search("регламент", limit=limit)


@pytest.mark.parametrize("limit", [1, 50])
def test_search_limit_edges_ok(kb, limit):
    assert len(kb.search("регламент", limit=limit)["items"]) <= limit


@pytest.mark.parametrize("query", ["", "   ", None, "x" * 201])
def test_search_bad_query(kb, query):
    with pytest.raises(ValueError):
        kb.search(query)  # type: ignore[arg-type]


def test_search_item_shape_and_order(kb):
    items = kb.search("сертификат", limit=50)["items"]
    assert items
    assert set(items[0]) == {"type", "route_id", "node_id", "id", "title", "snippet", "score",
                             "source_ids"}
    keys = [(-i["score"], i["type"], i["route_id"] or "", i["id"]) for i in items]
    assert keys == sorted(keys)


def test_search_no_results(kb):
    assert kb.search("zzzzqqqq-нет-такого") == {"items": [], "next_cursor": None}


def test_search_deterministic(kb):
    assert kb.search("API", limit=50) == kb.search("API", limit=50)


def test_pagination_no_dup_no_gap(kb):
    full = kb.search("api", limit=50)
    assert full["next_cursor"] is None
    total = len(full["items"])
    assert total > 6
    page1 = kb.search("api", limit=4)
    assert page1["next_cursor"]
    page2 = kb.search("api", limit=total - 4, cursor=page1["next_cursor"])
    assert page2["next_cursor"] is None
    merged = page1["items"] + page2["items"]
    assert merged == full["items"]
    keys = [(i["type"], i["route_id"], i["id"]) for i in merged]
    assert len(keys) == len(set(keys))


def test_pagination_walks_all_pages(kb):
    full = kb.search("api", limit=50)["items"]
    seen, cursor = [], None
    for _ in range(100):
        page = kb.search("api", limit=3, cursor=cursor)
        seen += page["items"]
        cursor = page["next_cursor"]
        if cursor is None:
            break
    assert seen == full


def _tamper(cursor):
    raw = base64.urlsafe_b64decode(cursor + "=" * (-len(cursor) % 4)).decode()
    parts = raw.split(":")
    return parts


def _enc(parts):
    return base64.urlsafe_b64encode(":".join(parts).encode()).rstrip(b"=").decode()


def test_tampered_cursor(kb):
    cursor = kb.search("api", limit=2)["next_cursor"]
    for bad in ["", "!!!", "abc", "Zm9v", cursor[:-2], cursor + "A", "A" * 500]:
        with pytest.raises(ValueError):
            kb.search("api", limit=2, cursor=bad)
    parts = _tamper(cursor)
    # изменён офсет без пересчёта контрольной суммы
    forged = _enc(["0"] + parts[1:])
    with pytest.raises(ValueError):
        kb.search("api", limit=2, cursor=forged)
    # изменён хеш набора
    forged = _enc([parts[0], "0" * 16] + parts[2:])
    with pytest.raises(ValueError):
        kb.search("api", limit=2, cursor=forged)


def test_cursor_for_other_query_or_domain(kb):
    cursor = kb.search("api", limit=2)["next_cursor"]
    with pytest.raises(ValueError):
        kb.search("сертификат", limit=2, cursor=cursor)
    with pytest.raises(ValueError):
        kb.search("api", limit=2, cursor=cursor, domain="epgu")


def test_cursor_from_different_dataset(kb, write_dataset):
    from epgu_knowledge import load

    other = load(write_dataset(lambda d: d["notes"][0].update(title="Иной заголовок")))
    cursor = kb.search("api", limit=2)["next_cursor"]
    with pytest.raises(ValueError):
        other.search("api", limit=2, cursor=cursor)


# --- копии -------------------------------------------------------------------

def test_results_are_copies(kb):
    r = kb.get_route("epgu-vendor")
    r["title"] = "BROKEN"
    r["nodes"][0]["checks"].append("x")
    r["nodes"].clear()
    again = kb.get_route("epgu-vendor")
    assert again["title"] != "BROKEN" and again["nodes"]
    assert "x" not in again["nodes"][0]["checks"]

    n = kb.get_node("epgu-vendor", "cabinet")
    n["sources_resolved"][0]["title"] = "BROKEN"
    n["incoming"].clear()
    n2 = kb.get_node("epgu-vendor", "cabinet")
    assert n2["sources_resolved"][0]["title"] != "BROKEN" and n2["incoming"]

    kb.list_routes()[0]["coverage"]["capabilities"].append("x")
    assert "x" not in kb.list_routes()[0]["coverage"]["capabilities"]

    kb.list_sources().clear()
    assert len(kb.list_sources()) == 28
    kb.get_source("apiSpec")["used_by"].clear()
    assert kb.get_source("apiSpec")["used_by"]
    kb.list_notes()[0]["sources"].append("x")
    assert "x" not in kb.list_notes()[0]["sources"]

    meta = kb.meta()
    meta["dataset"]["id"] = "BROKEN"
    meta["counts"]["routes"] = 0
    assert kb.meta()["dataset"]["id"] == "epgu-integration-guide"
    assert kb.meta()["counts"]["routes"] == 10

    page = kb.search("api", limit=2)
    page["items"].clear()
    assert kb.search("api", limit=2)["items"]
