"""Планировщик Госпочты: распорядок, лимиты и отказ работать молча."""

from __future__ import annotations

import importlib
from datetime import datetime, timedelta, timezone

import pytest

MSK = timezone(timedelta(hours=3))
NOW = datetime(2026, 8, 16, 12, 0, tzinfo=MSK)
THREAD = "6c7a5efd-2a8c-11f0-8080-808080808080"
MESSAGE = "91160bbb-f997-11ef-8080-808080808080"
TASK = "11971e70-a8ec-11f0-84e4-c322de0b8c44"


class FakeGateway:
    """ГЭПС без сети: помнит вызовы и отдаёт заранее заданные ответы."""

    def __init__(self, *, result=None, message=None, search_fails=False):
        self.calls = []
        self._result = result or {"status": "PROCESSING", "ready": False, "messages": []}
        self._message = message
        self._search_fails = search_fails

    async def search(self, payload):
        self.calls.append(("search", payload))
        if self._search_fails:
            raise RuntimeError("ГЭПС недоступен")
        return TASK

    async def result(self, task_uuid, offset, limit):
        self.calls.append(("result", task_uuid))
        return self._result

    async def message(self, thread_uuid, message_uuid):
        self.calls.append(("message", message_uuid))
        return self._message or {
            "threadUuid": thread_uuid,
            "messageUuid": message_uuid,
            "sender": "ФССП",
            "subject": "Извещение",
            "isRead": True,
            "createDate": "2026-08-15T10:20:00+03:00",
            "html": "<div>текст</div>",
            "params": {},
            "attachments": [],
            "statuses": [],
        }

    def count(self, kind):
        return sum(1 for call in self.calls if call[0] == kind)


@pytest.fixture()
def scheduler(tmp_path, monkeypatch):
    monkeypatch.setenv("GEPS_STORE_DIR", str(tmp_path / "geps"))
    monkeypatch.setenv("GEPS_QUOTA_FILE", str(tmp_path / "quota.json"))
    monkeypatch.setenv("EPGU_SETTINGS_FILE", str(tmp_path / "settings.env"))
    monkeypatch.delenv("GEPS_SCHEDULE_ENABLED", raising=False)

    import geps_quota
    import geps_store
    import settings_store
    import geps_scheduler

    for module in (geps_quota, geps_store, settings_store, geps_scheduler):
        importlib.reload(module)
    geps_scheduler.store = geps_store
    return geps_scheduler


def ready_page(count=1):
    return {
        "status": "COMPLETED",
        "ready": True,
        "total": count,
        "messages": [
            {
                "threadUuid": THREAD,
                "messageUuid": "%08d-f997-11ef-8080-808080808080" % index,
                "sender": "ФССП",
                "subject": "Извещение",
                "isRead": False,
                "createDate": "2026-08-15T10:20:00+03:00",
            }
            for index in range(count)
        ],
    }


# --- распорядок ---------------------------------------------------------


@pytest.mark.asyncio
async def test_first_tick_orders_the_previous_day(scheduler):
    gateway = FakeGateway()

    report = await scheduler.tick(gateway, NOW)

    assert report["ordered"] == 1
    assert gateway.count("search") == 1
    _, payload = gateway.calls[0]
    # Забираем предыдущие сутки по московскому времени.
    assert payload["startDateTime"].startswith("2026-08-15T00:00:00")
    assert payload["endDateTime"].startswith("2026-08-16T00:00:00")


@pytest.mark.asyncio
async def test_second_tick_does_not_order_the_same_day_again(scheduler):
    gateway = FakeGateway()
    await scheduler.tick(gateway, NOW)
    await scheduler.tick(gateway, NOW + timedelta(minutes=15))

    assert gateway.count("search") == 1


@pytest.mark.asyncio
async def test_result_is_not_requested_before_the_recommended_hour(scheduler):
    gateway = FakeGateway()
    await scheduler.tick(gateway, NOW)
    await scheduler.tick(gateway, NOW + timedelta(minutes=20))

    assert gateway.count("result") == 0


@pytest.mark.asyncio
async def test_ready_list_is_stored_and_details_are_collected(scheduler):
    import geps_store

    gateway = FakeGateway(result=ready_page(2))
    await scheduler.tick(gateway, NOW)
    report = await scheduler.tick(gateway, NOW + timedelta(hours=2))

    assert report["ready"] == 1
    assert report["new_messages"] == 2
    assert report["details"] == 2
    assert geps_store.counts()["messages"] == 2
    assert geps_store.counts()["without_detail"] == 0

    # Третий такт не должен перечитывать то же самое.
    again = await scheduler.tick(gateway, NOW + timedelta(hours=3))
    assert again["details"] == 0


@pytest.mark.asyncio
async def test_unfinished_list_is_retried_later(scheduler):
    import geps_store

    gateway = FakeGateway()
    await scheduler.tick(gateway, NOW)
    report = await scheduler.tick(gateway, NOW + timedelta(hours=2))

    assert report["waiting"] == 1
    job = geps_store.pending_jobs()[0]
    assert job["checks"] == 1
    # Следующая проверка отложена, а не назначена на сейчас.
    assert datetime.fromisoformat(job["next_check_at"]) > NOW + timedelta(hours=2)


@pytest.mark.asyncio
async def test_failed_task_is_closed_and_not_polled_forever(scheduler):
    import geps_store

    gateway = FakeGateway(result={"status": "ERROR", "ready": False, "messages": []})
    await scheduler.tick(gateway, NOW)
    report = await scheduler.tick(gateway, NOW + timedelta(hours=2))

    assert report["errors"] == 1
    failed = [job for job in geps_store.list_jobs() if job["state"] == geps_store.STATE_FAILED]
    assert len(failed) == 1
    # ГЭПС на такую задачу просит новый заказ, и он делается сразу же.
    assert report["ordered"] == 1


@pytest.mark.asyncio
async def test_old_job_is_marked_expired_without_asking(scheduler):
    """Результат живёт семь дней, дальше спрашивать нечего."""
    import geps_store

    gateway = FakeGateway()
    await scheduler.tick(gateway, NOW)
    # Возраст заявки считается от её собственной отметки времени, а не от
    # часов машины, поэтому проставляем её явно.
    old_job = geps_store.pending_jobs()[0]
    geps_store.update_job(old_job["id"], created_at=NOW.isoformat(timespec="seconds"))

    report = await scheduler.tick(gateway, NOW + timedelta(days=8))

    assert report["expired"] == 1
    # За протухшим результатом не ходим совсем.
    assert gateway.count("result") == 0
    assert geps_store.get_job(old_job["id"])["state"] == geps_store.STATE_EXPIRED


# --- лимиты -------------------------------------------------------------


@pytest.mark.asyncio
async def test_search_quota_stops_new_orders(scheduler):
    import geps_quota

    for _ in range(5):
        geps_quota.take("search")

    gateway = FakeGateway()
    report = await scheduler.tick(gateway, NOW)

    assert report["ordered"] == 0
    assert gateway.count("search") == 0
    assert any("заказ списка" in reason for reason in report["skipped"])


@pytest.mark.asyncio
async def test_result_quota_stops_polling(scheduler):
    import geps_quota

    gateway = FakeGateway()
    await scheduler.tick(gateway, NOW)
    for _ in range(15):
        geps_quota.take("result")

    report = await scheduler.tick(gateway, NOW + timedelta(hours=2))

    assert gateway.count("result") == 0
    assert any("получение списка" in reason for reason in report["skipped"])


@pytest.mark.asyncio
async def test_attempt_is_spent_even_if_the_call_fails(scheduler):
    import geps_quota

    gateway = FakeGateway(search_fails=True)
    report = await scheduler.tick(gateway, NOW)

    assert report["errors"] == 1
    assert geps_quota.used("search") == 1


# --- выключатель --------------------------------------------------------


def test_automatic_mode_is_off_until_switched_on(scheduler):
    import settings_store

    assert scheduler.enabled() is False

    settings_store.save({"GEPS_SCHEDULE_ENABLED": "1"})
    assert scheduler.enabled() is True

    settings_store.save({"GEPS_SCHEDULE_ENABLED": "0"})
    assert scheduler.enabled() is False


@pytest.mark.asyncio
async def test_run_once_says_plainly_that_there_is_no_token(scheduler):
    async def no_gateway():
        return None

    worker = scheduler.Scheduler(no_gateway)
    report = await worker.run_once()

    assert "маркер" in report["skipped"]
    assert worker.describe()["last_skip"]


@pytest.mark.asyncio
async def test_run_once_works_even_when_automatic_mode_is_off(scheduler):
    """Ручной прогон - осознанное действие оператора, выключатель ему не помеха."""
    gateway = FakeGateway()

    async def factory():
        return gateway

    worker = scheduler.Scheduler(factory)
    report = await worker.run_once()

    assert report["ordered"] == 1
    assert worker.describe()["enabled"] is False


@pytest.mark.asyncio
async def test_gateway_is_closed_after_the_tick(scheduler):
    closed = []

    class ClosingGateway(FakeGateway):
        async def aclose(self):
            closed.append(True)

    async def factory():
        return ClosingGateway()

    await scheduler.Scheduler(factory).run_once()
    assert closed == [True]
