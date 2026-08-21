"""Автоматическая обработка почты: что такт делает и чего не делает никогда."""

from __future__ import annotations

import importlib
from datetime import datetime, timedelta, timezone

import pytest

NOW = datetime(2026, 8, 21, 12, 0, tzinfo=timezone.utc)


class FakeMailbox:
    """Ящик без сети: помнит вызовы и отдаёт заранее заданные ответы."""

    def __init__(self, module, *, threads=None, attachments=None):
        self.module = module
        self.threads = threads or []
        self.attachments = attachments or []
        self.saved = []
        self.sent = []

    def install(self, monkeypatch, mail_worker):
        module = self.module
        monkeypatch.setattr(module, "fetch_headers", lambda config, scan=200: [])
        monkeypatch.setattr(module, "build_threads", lambda headers: self.threads)
        monkeypatch.setattr(
            module, "list_attachments", lambda config, letters=20: self.attachments
        )

        def save(config, *, uid, index, target_dir=None):
            name = next(
                item["name"] for item in self.attachments
                if item["uid"] == uid and item["index"] == index
            )
            self.saved.append({"name": name, "target": str(target_dir) if target_dir else ""})
            return {"saved": True, "name": name, "path": "/tmp/" + name, "size": 10}

        monkeypatch.setattr(module, "save_attachment", save)

        def send(config, **kwargs):
            self.sent.append(kwargs)
            return {"sent": True, "recipients": [kwargs["to"]], "subject": kwargs["subject"]}

        monkeypatch.setattr(module, "send_letter", send)
        monkeypatch.setattr(
            module,
            "fetch_message",
            lambda config, *, uid: {
                "uid": uid,
                "from": "noreply@sc.digital.gov.ru",
                "reply_to": "sd@sc.digital.gov.ru",
                "subject": "Запрос SCR#6451421 выполнен",
                "body": "Просим подтвердить решение",
                "message_id": "<1@sc>",
                "references": "",
                "ticket": "6451421",
                "received_at": "2026-08-18T12:00:00+00:00",
            },
        )


DONE_THREAD = {
    "ticket": "6451421",
    "topic": "Запрос тестового сертификата",
    "status": "Выполнен",
    "status_kind": "done",
    "status_at": "2026-08-19T12:00:00+00:00",
    "last_at": "2026-08-19T12:00:00+00:00",
    "uids": ["40", "44"],
    "needs_action": False,
}


@pytest.fixture()
def worker(tmp_path, monkeypatch):
    monkeypatch.setenv("CERT_INBOX_DIR", str(tmp_path / "mail"))
    monkeypatch.setenv("KEYS_DIR", str(tmp_path / "keys"))
    monkeypatch.setenv("SETTINGS_FILE", str(tmp_path / "settings.env"))
    monkeypatch.setenv("MAIL_IMAP_HOST", "imap.example.org")
    monkeypatch.setenv("MAIL_USER", "smev@example.org")
    monkeypatch.setenv("MAIL_PASSWORD", "secret")
    monkeypatch.setenv("SECRET_PROVIDER", "env")
    monkeypatch.delenv("MAIL_AUTO_ENABLED", raising=False)
    monkeypatch.delenv("MAIL_AUTO_CONFIRM", raising=False)

    import certsources
    import mailbox
    import secret_store
    import settings_store
    import mail_worker

    for module in (settings_store, secret_store, certsources, mailbox, mail_worker):
        importlib.reload(module)
    (tmp_path / "mail").mkdir()
    return mail_worker, mailbox


def test_disabled_by_default(worker):
    mail_worker, _ = worker

    assert mail_worker.enabled() is False
    # Забор вложений безопасен и потому включён, отправка писем - нет.
    assert mail_worker.collect_enabled() is True
    assert mail_worker.confirm_enabled() is False


def test_tick_without_mailbox_is_skipped(worker, monkeypatch):
    mail_worker, mailbox = worker
    monkeypatch.delenv("MAIL_IMAP_HOST", raising=False)
    importlib.reload(mailbox)

    report = mail_worker.tick(NOW)

    assert report["skipped"] == ["почта не настроена"]
    assert report["threads"] == 0


def test_files_land_in_their_folders(worker, monkeypatch):
    mail_worker, mailbox = worker
    fake = FakeMailbox(
        mailbox,
        threads=[DONE_THREAD],
        attachments=[
            {"uid": "44", "index": 0, "name": "org.cer", "ticket": "6451421", "too_large": False},
            {"uid": "44", "index": 1, "name": "primary.key", "ticket": "6451421", "too_large": False},
            {"uid": "44", "index": 2, "name": "photo.png", "ticket": "6451421", "too_large": False},
        ],
    )
    fake.install(monkeypatch, mail_worker)

    report = mail_worker.tick(NOW)

    saved = {item["name"]: item["target"] for item in fake.saved}
    assert saved["org.cer"] == ""
    assert saved["primary.key"].endswith("keys")
    # Картинка из подписи письма не нужна никому.
    assert "photo.png" not in saved
    assert len(report["collected"]) == 2


def test_the_same_file_is_not_taken_twice(worker, monkeypatch):
    mail_worker, mailbox = worker
    fake = FakeMailbox(
        mailbox,
        threads=[DONE_THREAD],
        attachments=[
            {"uid": "44", "index": 0, "name": "org.cer", "ticket": "6451421", "too_large": False}
        ],
    )
    fake.install(monkeypatch, mail_worker)
    # Первый такт сохранил файл, значит на диске он уже есть.
    (mail_worker.certsources.cert_dir() / "org.cer").write_bytes(b"cert")

    report = mail_worker.tick(NOW)

    assert fake.saved == []
    assert report["collected"] == []


def test_deadline_is_three_days_from_the_solution(worker, monkeypatch):
    mail_worker, mailbox = worker
    fake = FakeMailbox(mailbox, threads=[DONE_THREAD])
    fake.install(monkeypatch, mail_worker)

    waiting = mail_worker.deadlines([DONE_THREAD], NOW)

    assert len(waiting) == 1
    assert waiting[0]["ticket"] == "6451421"
    assert waiting[0]["overdue"] is False
    # Решение пришло 19-го, срок истекает 22-го, сейчас 21-е.
    assert round(waiting[0]["hours_left"]) == 24


def test_long_overdue_requests_are_forgotten(worker):
    mail_worker, _ = worker
    old = dict(DONE_THREAD, status_at="2026-06-01T12:00:00+00:00")

    assert mail_worker.deadlines([old], NOW) == []


def test_nothing_is_sent_while_confirmation_is_off(worker, monkeypatch):
    mail_worker, mailbox = worker
    fake = FakeMailbox(mailbox, threads=[DONE_THREAD])
    fake.install(monkeypatch, mail_worker)

    report = mail_worker.tick(NOW)

    assert fake.sent == []
    assert "автоматический ответ выключен" in report["skipped"]


def test_confirmation_waits_for_the_delay(worker, monkeypatch):
    mail_worker, mailbox = worker
    fake = FakeMailbox(mailbox, threads=[DONE_THREAD])
    fake.install(monkeypatch, mail_worker)
    monkeypatch.setattr(mail_worker, "confirm_enabled", lambda: True)
    monkeypatch.setattr(mail_worker, "confirm_after_hours", lambda: 48)

    # Прошло 24 часа из 48: рано.
    early = mail_worker.tick(NOW - timedelta(hours=24))
    assert fake.sent == []
    assert early["confirmed"] == []

    # Прошло 48 часов: пора.
    report = mail_worker.tick(NOW)
    assert len(fake.sent) == 1
    assert report["confirmed"][0]["ticket"] == "6451421"


def test_confirmation_goes_into_the_same_thread(worker, monkeypatch):
    mail_worker, mailbox = worker
    fake = FakeMailbox(mailbox, threads=[DONE_THREAD])
    fake.install(monkeypatch, mail_worker)
    monkeypatch.setattr(mail_worker, "confirm_enabled", lambda: True)

    mail_worker.tick(NOW)

    letter = fake.sent[0]
    assert letter["to"] == "sd@sc.digital.gov.ru"
    assert letter["subject"] == "Запрос SCR#6451421 выполнен"
    assert letter["in_reply_to"] == "<1@sc>"
    assert "Подтверждаем решение запроса SCR#6451421" in letter["body"]
    assert "> Просим подтвердить решение" in letter["body"]


def test_confirmation_is_sent_only_once(worker, monkeypatch):
    mail_worker, mailbox = worker
    fake = FakeMailbox(mailbox, threads=[DONE_THREAD])
    fake.install(monkeypatch, mail_worker)
    monkeypatch.setattr(mail_worker, "confirm_enabled", lambda: True)

    mail_worker.tick(NOW)
    mail_worker.tick(NOW)

    assert len(fake.sent) == 1


def test_overdue_request_is_not_answered(worker, monkeypatch):
    mail_worker, mailbox = worker
    late = dict(DONE_THREAD, status_at="2026-08-15T12:00:00+00:00")
    fake = FakeMailbox(mailbox, threads=[late])
    fake.install(monkeypatch, mail_worker)
    monkeypatch.setattr(mail_worker, "confirm_enabled", lambda: True)

    mail_worker.tick(NOW)

    # Срок прошёл: письмо уже ничего не изменит, а тикет закрыт.
    assert fake.sent == []


def test_journal_keeps_names_but_not_letters(worker, monkeypatch):
    mail_worker, mailbox = worker
    fake = FakeMailbox(
        mailbox,
        threads=[DONE_THREAD],
        attachments=[
            {"uid": "44", "index": 0, "name": "org.cer", "ticket": "6451421", "too_large": False}
        ],
    )
    fake.install(monkeypatch, mail_worker)

    mail_worker.tick(NOW)
    written = mail_worker.state_path().read_text(encoding="utf-8")

    assert "org.cer" in written
    # Ни текста письма, ни ПИНа в журнале быть не должно.
    assert "Просим подтвердить решение" not in written


def test_a_broken_journal_does_not_stop_the_tick(worker, monkeypatch):
    mail_worker, mailbox = worker
    mail_worker.state_path().write_text("это не json", encoding="utf-8")
    fake = FakeMailbox(mailbox, threads=[DONE_THREAD])
    fake.install(monkeypatch, mail_worker)

    report = mail_worker.tick(NOW)

    assert report["threads"] == 1


# ---------- Границы автоответа ----------


ACTION_THREAD = {
    "ticket": "7000001",
    "topic": "Настройки ИС",
    "status": "Нужен ответ от нас",
    "status_kind": "action",
    "status_at": "2026-08-20T12:00:00+00:00",
    "last_at": "2026-08-20T12:00:00+00:00",
    "status_uid": "50",
    "uids": ["50"],
    "needs_action": True,
}


def test_deadline_covers_requests_waiting_for_our_answer(worker):
    mail_worker, _ = worker

    waiting = mail_worker.deadlines([ACTION_THREAD], NOW)

    assert len(waiting) == 1
    assert waiting[0]["kind"] == "action"


def test_closed_request_has_no_deadline(worker):
    mail_worker, _ = worker
    closed = dict(DONE_THREAD, status="Закрыт")

    assert mail_worker.deadlines([closed], NOW) == []


def test_question_is_never_answered_automatically(worker, monkeypatch):
    mail_worker, mailbox = worker
    fake = FakeMailbox(mailbox, threads=[ACTION_THREAD])
    fake.install(monkeypatch, mail_worker)
    monkeypatch.setattr(mail_worker, "confirm_enabled", lambda: True)

    mail_worker.tick(NOW)

    # Уточняющий вопрос требует человека, машинного ответа тут быть не может.
    assert fake.sent == []


def test_letter_from_a_stranger_gets_no_answer(worker, monkeypatch):
    mail_worker, mailbox = worker
    fake = FakeMailbox(mailbox, threads=[DONE_THREAD])
    fake.install(monkeypatch, mail_worker)
    monkeypatch.setattr(mail_worker, "confirm_enabled", lambda: True)
    monkeypatch.setattr(
        mailbox,
        "fetch_message",
        lambda config, *, uid: {
            "uid": uid,
            "from": "Поддержка <support@example.org>",
            "reply_to": "support@example.org",
            "subject": "Запрос SCR#6451421 выполнен",
            "body": "Подтвердите решение",
            "message_id": "<9@x>",
            "references": "",
            "ticket": "6451421",
            "received_at": "2026-08-19T12:00:00+00:00",
        },
    )

    mail_worker.tick(NOW)

    # Тему письма подделать несложно, поэтому адрес отправителя проверяется.
    assert fake.sent == []


def test_answer_goes_only_to_known_support_addresses(worker, monkeypatch):
    mail_worker, mailbox = worker
    fake = FakeMailbox(mailbox, threads=[DONE_THREAD])
    fake.install(monkeypatch, mail_worker)
    monkeypatch.setattr(mail_worker, "confirm_enabled", lambda: True)
    monkeypatch.setattr(
        mailbox,
        "fetch_message",
        lambda config, *, uid: {
            "uid": uid,
            "from": "Робот <noreply@sc.digital.gov.ru>",
            # Ведомственный отправитель, но обратный адрес подставлен чужой.
            "reply_to": "attacker@example.org",
            "subject": "Запрос SCR#6451421 выполнен",
            "body": "Подтвердите решение",
            "message_id": "<9@x>",
            "references": "",
            "ticket": "6451421",
            "received_at": "2026-08-19T12:00:00+00:00",
        },
    )

    mail_worker.tick(NOW)

    assert fake.sent == []


def test_answer_targets_the_letter_that_announced_the_decision(worker, monkeypatch):
    mail_worker, mailbox = worker
    # После решения пришёл комментарий: статус он не меняет, отвечать надо не на него.
    thread = dict(DONE_THREAD, status_uid="44", uids=["40", "44", "48"])
    fake = FakeMailbox(mailbox, threads=[thread])
    fake.install(monkeypatch, mail_worker)

    waiting = mail_worker.deadlines([thread], NOW)

    assert waiting[0]["uid"] == "44"
