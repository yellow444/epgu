"""Ротация журнала входящих запросов.

Проверено на стенде: 70 запросов по мегабайту за пять секунд вытесняли журнал
целиком, вместе с настоящими сообщениями. Здесь проверяем, что запасных файлов
теперь несколько и старое переживает одну ротацию.
"""

import importlib
import json

import pytest


@pytest.fixture()
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("INBOUND_JOURNAL", str(tmp_path / "messages.jsonl"))
    monkeypatch.setenv("INBOUND_JOURNAL_KEEP", "3")

    import inbound_store

    importlib.reload(inbound_store)
    # Лимит считаем от настоящего размера записи: если в запись добавят поле,
    # тест не должен молча превратиться в проверку чего-то другого. Берём
    # самую длинную метку и добавляем запас, чтобы в файл влезало ровно три.
    one = len(json.dumps(record(inbound_store, "настоящее сообщение"), ensure_ascii=False)) + 1
    monkeypatch.setenv("INBOUND_JOURNAL_MAX_BYTES", str(one * 3 + 100))
    return inbound_store


def record(store, marker, size=200):
    return store.build_record(
        method="POST",
        path="/push",
        query="",
        client="127.0.0.1",
        headers={"content-type": "application/json"},
        # ensure_ascii=False обязателен: иначе метка уедет в журнал в виде
        # \uXXXX, и искать её в тексте будет бесполезно.
        body=json.dumps(
            {"marker": marker, "fill": "x" * size}, ensure_ascii=False
        ).encode("utf-8"),
        truncated=False,
        mnemonic="TESTIS01",
    )


def everything(store):
    """Всё, что ещё можно прочитать: текущий журнал и запасные файлы."""
    path = store.journal_path()
    text = ""
    for candidate in [path] + [
        path.with_name(path.name + "." + str(number)) for number in range(1, 5)
    ]:
        if candidate.exists():
            text += candidate.read_text(encoding="utf-8")
    return text


def test_old_records_survive_several_rotations(store):
    """Раньше запасной файл был один, и двух ротаций хватало, чтобы стереть всё."""
    store.append(record(store, "настоящее сообщение"))
    # Четыре файла по три записи: девятая запись ещё не вытесняет первую.
    for number in range(8):
        store.append(record(store, "мусор-%d" % number))

    files = sorted(p.name for p in store.journal_path().parent.iterdir())
    assert files[0] == "messages.jsonl"
    assert len(files) > 1, "ротация не сработала, проверять нечего"
    assert len(files) <= 4, "запасных файлов больше, чем разрешено"
    assert "настоящее сообщение" in everything(store)


def test_journal_is_a_window_not_an_archive(store):
    """Глубина конечная: журнал не хранилище, сообщения надо забирать вовремя."""
    store.append(record(store, "настоящее сообщение"))
    for number in range(40):
        store.append(record(store, "мусор-%d" % number))

    assert "настоящее сообщение" not in everything(store)


def test_journal_does_not_grow_without_limit(store):
    for number in range(200):
        store.append(record(store, "мусор-%d" % number))

    total = sum(
        path.stat().st_size for path in store.journal_path().parent.iterdir()
    )
    # Четыре файла по лимиту плюс запись, которая лимит переехала.
    assert total < 4 * store.max_journal_bytes() + 2000


def test_clear_removes_every_rotation(store):
    for number in range(12):
        store.append(record(store, "мусор-%d" % number))
    store.clear()

    assert list(store.journal_path().parent.iterdir()) == []
    assert store.count() == 0
