import re

import pytest
from jsonschema import Draft202012Validator

import epgu_knowledge
from epgu_knowledge import KnowledgeError, load

OFFICIALITY_MAP = {
    "Официальный документ": "official",
    "Официальный документ для старой версии": "official",
    "Официальная историческая публикация": "official_historical",
    "Официальный каталог": "official_catalog",
    "Официальный FAQ": "official_catalog",
    "Документация оператора": "operator_docs",
    "Неофициальная реализация": "unofficial_implementation",
    "Документация неофициальной реализации": "unofficial_implementation",
    "Опыт разработчика, не контракт оператора": "developer_experience",
    "Историческая статья разработчика": "developer_experience",
}


def test_schema_is_valid_2020_12(schema):
    Draft202012Validator.check_schema(schema)
    assert schema["$schema"] == "https://json-schema.org/draft/2020-12/schema"


def test_dataset_matches_schema(raw_data, schema):
    errors = list(Draft202012Validator(schema).iter_errors(raw_data))
    assert errors == []


def test_validate_is_empty(kb):
    assert kb.validate() == []


def test_counts(kb):
    counts = kb.meta()["counts"]
    assert counts == {"routes": 10, "nodes": 51, "sources": 28, "notes": 9}


def test_officiality_mapping_is_exact(raw_data):
    for src in raw_data["sources"]:
        assert OFFICIALITY_MAP[src["kind_label"]] == src["officiality"]
        assert src["url"].startswith("https://")
        assert src["version"] is None and src["sha256"] is None


def test_coverage_table(raw_data):
    epgu = ["services.list", "order.reserve", "order.push",
            "order.details", "order.cancel", "order.download_file"]
    for route in raw_data["routes"]:
        cov = route["coverage"]
        if route["id"] in ("epgu-vendor", "epgu-consumer"):
            assert cov["status"] == "official_api_partial"
            assert cov["capabilities"] == epgu
        elif route["id"] == "signing":
            assert cov["status"] == "official_api_partial"
            assert cov["capabilities"] == ["goskey.preview", "goskey.submit"]
        else:
            assert cov["status"] == "informational"
            assert cov["capabilities"] == []


def test_empty_warning_is_null(raw_data):
    for route in raw_data["routes"]:
        for node in route["nodes"]:
            assert node["warning"] is None or node["warning"].strip()


def test_provenance(kb):
    ds = kb.meta()["dataset"]
    assert re.fullmatch(r"[0-9a-f]{64}", ds["generated_from"]["sha256"])
    assert ds["reviewed_at"] == "2026-10-23"


# --- ссылочная целостность на повреждённых наборах ---------------------------

def _errors(path):
    return load(path, validate=False).validate()


def test_dangling_next(write_dataset):
    def mutate(d):
        d["routes"][0]["nodes"][0]["next"].append({"to": "no-such-node", "label": "x"})

    errs = _errors(write_dataset(mutate))
    assert any("несуществующему узлу 'no-such-node'" in e for e in errs)


def test_unknown_source_in_node(write_dataset):
    def mutate(d):
        d["routes"][0]["nodes"][0]["sources"].append("ghostSource")

    errs = _errors(write_dataset(mutate))
    assert any("неизвестный источник 'ghostSource'" in e for e in errs)


def test_unknown_source_in_note(write_dataset):
    def mutate(d):
        d["notes"][0]["sources"].append("ghostSource")

    errs = _errors(write_dataset(mutate))
    assert any("/notes/0" in e and "ghostSource" in e for e in errs)


def test_bad_entry_node(write_dataset):
    def mutate(d):
        d["routes"][1]["entry_node"] = "nowhere"

    errs = _errors(write_dataset(mutate))
    assert any("entry_node 'nowhere'" in e for e in errs)


def test_duplicate_ids(write_dataset):
    def mutate(d):
        d["routes"][0]["nodes"].append(dict(d["routes"][0]["nodes"][0]))
        d["sources"].append(dict(d["sources"][0]))

    errs = _errors(write_dataset(mutate))
    assert any("повторный id узла" in e for e in errs)
    assert any("повторный id источника" in e for e in errs)


def test_schema_violations_reported(write_dataset):
    def mutate(d):
        d["sources"][0]["url"] = "http://insecure.example/x"
        d["routes"][0]["extra"] = 1

    errs = _errors(write_dataset(mutate))
    assert any(e.startswith("schema:") and "/sources/0/url" in e for e in errs)
    assert any(e.startswith("schema:") and "extra" in e for e in errs)


def test_broken_structure_does_not_crash(write_dataset):
    def mutate(d):
        d["routes"] = [{"id": "r", "nodes": "oops"}, 5]
        d["notes"] = "x"

    kb = load(write_dataset(mutate), validate=False)
    assert kb.validate()
    assert kb.list_routes()[0]["node_count"] == 0


def test_load_errors(tmp_path):
    with pytest.raises(KnowledgeError) as e1:
        load(tmp_path / "missing.json")
    assert e1.value.code == "unreadable_dataset"
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(KnowledgeError) as e2:
        load(bad)
    assert e2.value.code == "invalid_dataset"
    arr = tmp_path / "arr.json"
    arr.write_text("[]", encoding="utf-8")
    with pytest.raises(KnowledgeError):
        load(arr)


def test_load_is_cached(write_dataset):
    p = write_dataset()
    assert load(p) is load(p)
    assert epgu_knowledge.load() is epgu_knowledge.load()


# --- отсутствие секретов и персональных данных --------------------------------

SECRET_PATTERNS = {
    "PIN со значением": re.compile(r"\bPIN\b\s*(?:[:=]\s*\S|\d{4})"),
    "password=": re.compile(r"password\s*=", re.I),
    "Bearer ": re.compile(r"Bearer\s+\S", re.I),
    "ИНН/12 цифр подряд": re.compile(r"(?<!\d)\d{12}(?!\d)"),
    "СНИЛС 123-456-789 01": re.compile(r"(?<!\d)\d{3}-\d{3}-\d{3}[ -]\d{2}(?!\d)"),
    "11 цифр подряд": re.compile(r"(?<!\d)\d{11}(?!\d)"),
    "закрытый ключ PEM": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "email": re.compile(r"[\w.+-]+@[\w-]+\.[\w.-]+"),
    "длинный токен (40+ знаков base64/hex без пробелов)": re.compile(r"[A-Za-z0-9+/_-]{40,}"),
    "api_key=/secret=/token=": re.compile(r"(api[_-]?key|secret|token)\s*[=:]\s*\S{8,}", re.I),
}


def _walk(value, path=""):
    if isinstance(value, dict):
        for k, v in value.items():
            yield from _walk(v, f"{path}/{k}")
    elif isinstance(value, list):
        for i, v in enumerate(value):
            yield from _walk(v, f"{path}/{i}")
    elif isinstance(value, str):
        yield path, value


def test_no_secrets_or_pii(raw_data):
    hits = []
    for path, text in _walk(raw_data):
        # хеш происхождения и URL внешних документов проверяются отдельно
        if path.endswith("/sha256") or path.endswith("/url"):
            continue
        for name, pattern in SECRET_PATTERNS.items():
            if pattern.search(text):
                hits.append((name, path))
    assert hits == []


def test_pin_only_in_prohibitions(raw_data):
    """Слово PIN допустимо лишь как запрет («Не прикладывать PIN ...»), без значений."""
    for path, text in _walk(raw_data):
        if re.search(r"(?<![A-Za-z])PIN(?![A-Za-z])", text):
            assert re.search(r"(^|[.;:] )Не ", text) or "нельзя" in text.lower(), (path, text)


def test_urls_have_no_credentials_or_query_secrets(raw_data):
    for src in raw_data["sources"]:
        assert "@" not in src["url"].split("/")[2]
        assert not re.search(r"(token|key|secret|password)=", src["url"], re.I)
