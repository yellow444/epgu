"""Свой учёт прочитанного по запросам поддержки."""

import importlib

import pytest


@pytest.fixture()
def state(tmp_path, monkeypatch):
    monkeypatch.setenv("MAIL_STATE_FILE", str(tmp_path / "mail-state.json"))
    import mail_state

    importlib.reload(mail_state)
    return mail_state


def threads():
    return [
        {
            "ticket": "6451421",
            "last_at": "2026-08-15T10:10:00",
            "status_kind": "progress",
        },
        {
            "ticket": "4950973",
            "last_at": "2026-08-03T10:00:00",
            "status_kind": "done",
        },
    ]


def test_everything_is_unread_until_marked(state):
    annotated = state.annotate(threads())
    assert [item["unread"] for item in annotated] == [True, True]
    # Активным считается то, что ещё в работе.
    assert [item["active"] for item in annotated] == [True, False]


def test_marking_hides_the_request_until_new_mail(state):
    items = threads()
    state.mark_many(items)
    annotated = state.annotate(threads())
    assert [item["unread"] for item in annotated] == [False, False]

    # Пришло письмо свежее отметки: запрос снова непрочитанный.
    newer = threads()
    newer[0]["last_at"] = "2026-08-16T09:00:00"
    assert state.annotate(newer)[0]["unread"] is True


def test_single_request_can_be_marked(state):
    state.mark_read("6451421", "2026-08-15T10:10:00")
    annotated = state.annotate(threads())
    assert annotated[0]["unread"] is False
    assert annotated[1]["unread"] is True


def test_marking_can_be_taken_back(state):
    state.mark_many(threads())
    state.forget("6451421")
    annotated = state.annotate(threads())
    assert annotated[0]["unread"] is True


def test_older_mark_does_not_overwrite_newer(state):
    state.mark_read("6451421", "2026-08-15T10:10:00")
    state.mark_read("6451421", "2026-08-01T10:00:00")
    assert state.load()["6451421"] == "2026-08-15T10:10:00"


def test_state_survives_reload_and_broken_file(state, tmp_path):
    state.mark_many(threads())
    importlib.reload(state)
    assert state.load()["6451421"] == "2026-08-15T10:10:00"

    state.state_path().write_text("не json", encoding="utf-8")
    # Битый файл не должен ронять список запросов.
    assert state.load() == {}
    assert state.annotate(threads())[0]["unread"] is True


def test_clear_forgets_everything(state):
    state.mark_many(threads())
    state.clear()
    assert state.load() == {}
