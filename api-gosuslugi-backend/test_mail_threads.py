"""Разбор писем поддержки: номер запроса, статус, группировка."""

import importlib

import pytest


@pytest.fixture()
def mailbox(monkeypatch, tmp_path):
    monkeypatch.setenv("SETTINGS_FILE", str(tmp_path / "settings.env"))
    import settings_store
    import mailbox as module

    importlib.reload(settings_store)
    importlib.reload(module)
    return module


# Реальные темы из ящика поддержки: по ним и восстанавливается состояние.
SUBJECTS = [
    ("39", "Зарегистрирован запрос SCR#6451421. Тема запроса: Запрос тестового сертификата для ИС TESTEP", "2026-08-15T10:00:00"),
    ("40", "Статус работ по запросу SCR#6451421: «Исполнение». Тема запроса: Запрос тестового сертификата для ИС TESTEP", "2026-08-15T10:05:00"),
    ("41", "Для запроса SCR#6451421 в системе Ростелекома присвоен номер. Тема запроса: Запрос тестового сертификата для ИС TESTEP", "2026-08-15T10:10:00"),
]


def headers(items):
    return [
        {
            "uid": uid,
            "from": "Федеральный ситуационный центр <noreply@sc.digital.gov.ru>",
            "subject": subject,
            "received_at": received,
            "watched": True,
        }
        for uid, subject, received in items
    ]


def test_ticket_number_is_extracted(mailbox):
    assert mailbox.parse_ticket(SUBJECTS[0][1]) == "6451421"
    assert mailbox.parse_ticket("письмо без номера") == ""


def test_status_is_read_from_the_subject(mailbox):
    assert mailbox.parse_status(SUBJECTS[0][1]) == ("Зарегистрирован", "new")
    # Статус в кавычках берётся как есть: формулировки поддержки меняются.
    assert mailbox.parse_status(SUBJECTS[1][1]) == ("Исполнение", "progress")
    assert mailbox.parse_status(SUBJECTS[2][1]) == ("Принят в работу", "progress")
    assert mailbox.parse_status("Запрос SCR#1 выполнен. Тема: тест") == ("Выполнен", "done")
    assert mailbox.parse_status("Запрос SCR#1 закрыт. Тема : тест") == ("Закрыт", "done")
    assert mailbox.parse_status("По запросу SCR#1 требуется дополнительная информация") == (
        "Нужен ответ от нас",
        "action",
    )


def test_topic_is_cleaned_from_service_words(mailbox):
    assert mailbox.parse_topic(SUBJECTS[0][1]) == "Запрос тестового сертификата для ИС TESTEP"
    assert mailbox.parse_topic("Запрос SCR#1 выполнен. Тема: Настройки TESTEP") == "Настройки TESTEP"


def test_messages_group_into_one_request(mailbox):
    threads = mailbox.build_threads(headers(SUBJECTS))
    assert len(threads) == 1
    thread = threads[0]
    assert thread["ticket"] == "6451421"
    assert thread["messages"] == 3
    assert thread["topic"] == "Запрос тестового сертификата для ИС TESTEP"
    # Последним пришло "присвоен номер", оно и определяет статус.
    assert thread["status"] == "Принят в работу"
    assert thread["needs_action"] is False
    assert thread["has_files"] is False


def test_comment_and_file_do_not_overwrite_the_status(mailbox):
    items = SUBJECTS + [
        ("42", "К запросу SCR#6451421 добавлен файл. Тема запроса: Запрос тестового сертификата", "2026-08-15T11:00:00"),
        ("43", "К запросу SCR#6451421 добавлен комментарий. Тема запроса: Запрос тестового сертификата", "2026-08-15T11:05:00"),
    ]
    thread = mailbox.build_threads(headers(items))[0]
    assert thread["status"] == "Принят в работу"
    assert thread["has_files"] is True
    assert thread["last_event"] == "Добавлен комментарий"


def test_request_needing_an_answer_is_flagged(mailbox):
    items = [
        ("27", "Зарегистрирован запрос SCR#4950973. Тема запроса: Вопрос по регламенту", "2026-08-01T10:00:00"),
        ("28", "По запросу SCR#4950973 требуется дополнительная информация. Тема : Вопрос по регламенту", "2026-08-02T10:00:00"),
    ]
    thread = mailbox.build_threads(headers(items))[0]
    assert thread["needs_action"] is True
    assert thread["status"] == "Нужен ответ от нас"


def test_closed_request_is_not_flagged_as_waiting_for_us(mailbox):
    # Запрос просил уточнение, но потом был закрыт: подсвечивать его нельзя.
    items = [
        ("27", "Зарегистрирован запрос SCR#4950973. Тема запроса: Вопрос по регламенту", "2026-08-01T10:00:00"),
        ("28", "По запросу SCR#4950973 требуется дополнительная информация. Тема : Вопрос", "2026-08-02T10:00:00"),
        ("32", "Запрос SCR#4950973 закрыт. Тема : Вопрос по регламенту", "2026-08-03T10:00:00"),
    ]
    thread = mailbox.build_threads(headers(items))[0]
    assert thread["status"] == "Закрыт"
    assert thread["needs_action"] is False


def test_threads_are_sorted_by_last_activity(mailbox):
    items = [
        ("10", "Зарегистрирован запрос SCR#111. Тема запроса: Старый", "2026-07-01T10:00:00"),
        ("11", "Зарегистрирован запрос SCR#222. Тема запроса: Свежий", "2026-08-15T10:00:00"),
    ]
    threads = mailbox.build_threads(headers(items))
    assert [item["ticket"] for item in threads] == ["222", "111"]


def test_letters_without_ticket_are_skipped(mailbox):
    items = [("38", "Код подтверждения адреса электронной почты организации", "2026-08-15T09:00:00")]
    assert mailbox.build_threads(headers(items)) == []
