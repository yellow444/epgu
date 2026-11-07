import copy
import json
from importlib import resources

import pytest

import epgu_knowledge


def _package_json(*parts):
    res = resources.files("epgu_knowledge")
    for p in parts:
        res = res.joinpath(p)
    return json.loads(res.read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def raw_data():
    return _package_json("data", "knowledge.v1.json")


@pytest.fixture(scope="session")
def schema():
    return _package_json("schema", "knowledge.v1.schema.json")


@pytest.fixture()
def kb():
    return epgu_knowledge.load()


@pytest.fixture()
def write_dataset(tmp_path, raw_data):
    """Записать изменённую копию набора и вернуть путь."""

    def _write(mutate=None, name="ds.json"):
        data = copy.deepcopy(raw_data)
        if mutate is not None:
            mutate(data)
        path = tmp_path / name
        path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
        return path

    return _write
