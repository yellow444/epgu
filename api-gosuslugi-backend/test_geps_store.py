"""Хранение Госпочты: заявки, уведомления и вложения на томе."""

from __future__ import annotations

import importlib
import json

import pytest


@pytest.fixture()
def store(tmp_path, monkeypatch):
    monkeypatch.setenv("GEPS_STORE_DIR", str(tmp_path / "geps"))

    import geps_store

    importlib.reload(geps_store)
    return geps_store


def window():
    return {
        "startDateTime": "2026-08-15T00:00:00.000+03:00",
        "endDateTime": "2026-08-16T00:00:00.000+03:00",
        "statusFilter": "ANY",
    }


def brief(message_uuid="91160bbb-f997-11ef-8080-808080808080", **changes):
    item = {
        "threadUuid": "6c7a5efd-2a8c-11f0-8080-808080808080",
        "messageUuid": message_uuid,
        "sender": "ФССП",
        "subject": "Извещение",
        "isRead": False,
        "createDate": "2026-08-15T10:20:00+03:00",
    }
    item.update(changes)
    return item


def detail(message_uuid="91160bbb-f997-11ef-8080-808080808080", **changes):
    card = {
        "threadUuid": "6c7a5efd-2a8c-11f0-8080-808080808080",
        "messageUuid": message_uuid,
        "sender": "ФССП",
        "subject": "Извещение",
        "isRead": True,
        "createDate": "2026-08-15T10:20:00+03:00",
        "html": "<div>Извещение</div>",
        "params": {"uin": "42"},
        "attachments": [
            {
                "attachmentUuid": "61d94a0a-66ce-11ef-8080-808080808080",
                "fileName": "postanovlenie.pdf",
                "fileSize": 100,
                "mimeType": "application/pdf",
                "signed": True,
                "status": "READY",
                "statusDescription": "Доступен",
                "downloadable": True,
            }
        ],
        "statuses": [{"mnemonic": "READ", "description": "Прочитано"}],
    }
    card.update(changes)
    return card


# --- заявки ------------------------------------------------------------


def test_job_lives_through_its_states(store):
    job = store.create_job(window(), "11971e70-a8ec-11f0-84e4-c322de0b8c44")

    assert job["state"] == store.STATE_ORDERED
    assert store.pending_jobs()[0]["id"] == job["id"]

    store.update_job(job["id"], state=store.STATE_READY, message_count=3)
    assert store.get_job(job["id"])["state"] == store.STATE_READY
    assert store.pending_jobs() == []
    assert store.list_jobs(state=store.STATE_READY)[0]["message_count"] == 3


def test_same_period_is_not_ordered_twice(store):
    """Заказов пять в сутки, повторять один и тот же период незачем."""
    store.create_job(window(), "task-1")
    assert store.has_job_for_range(window()) is True

    other = window()
    other["startDateTime"] = "2026-08-10T00:00:00.000+03:00"
    assert store.has_job_for_range(other) is False


def test_failed_job_does_not_block_a_new_order(store):
    job = store.create_job(window(), "task-1")
    store.update_job(job["id"], state=store.STATE_FAILED)

    assert store.has_job_for_range(window()) is False


def test_update_of_unknown_job_returns_nothing(store):
    assert store.update_job("нет такого", state=store.STATE_READY) is None


# --- уведомления --------------------------------------------------------


def test_messages_are_stored_once_and_counted(store):
    added = store.save_messages("job-1", [brief(), brief("dcb4a0aa-0000-11f0-8080-808080808080")])
    assert added == 2

    # Повторный список того же периода не должен плодить дубли.
    added_again = store.save_messages("job-2", [brief()])
    assert added_again == 0
    assert store.counts()["messages"] == 2


def test_message_page_is_sorted_and_filtered(store):
    store.save_messages(
        "job-1",
        [
            brief("aaaaaaaa-0000-11f0-8080-808080808080", createDate="2026-08-10T10:00:00+03:00"),
            brief("bbbbbbbb-0000-11f0-8080-808080808080", createDate="2026-08-16T10:00:00+03:00", isRead=True),
        ],
    )

    page = store.list_messages(limit=1)
    assert page["total"] == 2
    assert page["messages"][0]["message_uuid"].startswith("bbbb")

    unread = store.list_messages(only_unread=True)
    assert unread["total"] == 1
    assert unread["messages"][0]["message_uuid"].startswith("aaaa")


def test_detail_is_attached_to_the_stored_message(store):
    store.save_messages("job-1", [brief()])
    record = store.save_detail(brief()["messageUuid"], detail())

    assert record["detail"]["html"] == "<div>Извещение</div>"
    assert record["attachments"][0]["file_name"] == "postanovlenie.pdf"
    assert record["attachments"][0]["downloadable"] is True
    assert store.counts()["without_detail"] == 0


def test_detail_for_unknown_message_creates_the_record(store):
    """Карточку могли открыть руками, до того как список разложили."""
    record = store.save_detail(brief()["messageUuid"], detail())
    assert record["message_uuid"] == brief()["messageUuid"]
    assert store.counts()["messages"] == 1


# --- вложения -----------------------------------------------------------


def test_attachment_is_written_and_remembered(store):
    store.save_messages("job-1", [brief()])
    store.save_detail(brief()["messageUuid"], detail())

    saved = store.save_attachment(
        brief()["messageUuid"],
        "61d94a0a-66ce-11ef-8080-808080808080",
        b"%PDF-1.4",
        "postanovlenie.pdf",
    )

    assert saved["size"] == 8
    record = store.get_message(brief()["messageUuid"])
    assert record["attachments"][0]["saved_path"] == saved["path"]
    assert store.counts()["attachments_saved"] == 1

    signature = store.save_attachment(
        brief()["messageUuid"],
        "61d94a0a-66ce-11ef-8080-808080808080",
        b"SIG",
        "postanovlenie.pdf",
        signature=True,
    )
    assert signature["file_name"].endswith(".sig")
    record = store.get_message(brief()["messageUuid"])
    assert record["attachments"][0]["signature_path"] == signature["path"]


def test_saved_paths_survive_a_second_reading_of_the_card(store):
    store.save_messages("job-1", [brief()])
    store.save_detail(brief()["messageUuid"], detail())
    saved = store.save_attachment(
        brief()["messageUuid"], "61d94a0a-66ce-11ef-8080-808080808080", b"x", "a.pdf"
    )

    store.save_detail(brief()["messageUuid"], detail())

    record = store.get_message(brief()["messageUuid"])
    assert record["attachments"][0]["saved_path"] == saved["path"]


@pytest.mark.parametrize(
    "name, expected",
    [
        ("../../etc/passwd", "passwd"),
        ("C:\\windows\\evil.dll", "evil.dll"),
        ("..", "attachment"),
        ("", "attachment"),
        ("обычное имя.pdf", "обычное имя.pdf"),
    ],
)
def test_file_name_never_leaves_its_folder(store, name, expected):
    """Имя приходит от отправителя, а попадает в путь на диске."""
    assert store.safe_name(name) == expected


def test_attachment_of_unknown_message_still_lands_on_disk(store):
    saved = store.save_attachment("нет-такого", "att", b"x", "file.pdf")
    assert saved["path"].endswith("file.pdf")


# --- устойчивость и очистка ---------------------------------------------


def test_broken_file_does_not_break_the_listing(store):
    store.save_messages("job-1", [brief()])
    store.messages_path().write_text("не json", encoding="utf-8")

    assert store.list_messages()["total"] == 0
    assert store.counts()["messages"] == 0


def test_stored_data_survives_reload(store):
    store.save_messages("job-1", [brief()])
    importlib.reload(store)

    assert store.list_messages()["total"] == 1
    assert json.loads(store.messages_path().read_text(encoding="utf-8"))


def test_clear_removes_everything_including_files(store):
    store.save_messages("job-1", [brief()])
    store.save_detail(brief()["messageUuid"], detail())
    store.save_attachment(
        brief()["messageUuid"], "61d94a0a-66ce-11ef-8080-808080808080", b"x", "a.pdf"
    )
    store.create_job(window(), "task-1")

    store.clear()

    assert store.counts() == {
        "messages": 0,
        "unread": 0,
        "without_detail": 0,
        "attachments_saved": 0,
        "jobs": 0,
        "jobs_pending": 0,
    }
    assert not store.files_root().exists()
