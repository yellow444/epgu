"""Планировщик Госпочты: один заказ в сутки и аккуратный дозор за результатом.

Лимиты ГЭПС не оставляют выбора в режиме работы: пять заказов списка в сутки,
пятнадцать получений результата, список готовится около часа и живёт неделю.
Отсюда весь распорядок: раз в сутки заказать вчерашний день, потом изредка
заходить за результатом, а карточки и вложения добирать уже без ограничений.

Важное про то, почему по умолчанию выключено. Обращение к ГЭПС равнозначно
входу на портал: по постановлениям Правительства № 606 и № 947 уведомление
считается вручённым с этого момента, и с него же идут процессуальные сроки.
Фоновая задача, которая молча забирает почту, начинает эти сроки без ведома
человека. Поэтому автоматический режим включается явно и об этом пишется в лог.

Что делает один такт (:func:`tick`):

1. Забирает результат по заявкам, которым подошло время проверки.
2. Если за нужный день заявки ещё нет, заказывает её.
3. Добирает карточки уведомлений, у которых их нет.

Такт ничего не знает про сеть: все обращения идут через переданный ``gateway``,
поэтому его можно проверить целиком, без ЕПГУ.
"""

from __future__ import annotations

import asyncio
import logging
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Awaitable, Callable, Dict, List, Optional, Protocol

from epgu import geps

import geps_quota
import geps_store

logger = logging.getLogger("geps.scheduler")

MOSCOW = timezone(timedelta(hours=3))

# Сколько ждать до первой проверки результата и между следующими.
FIRST_CHECK_AFTER = timedelta(hours=1)
RETRY_CHECK_AFTER = timedelta(hours=1)
# Сколько карточек добираем за один такт: их лимит не ограничивает, но и
# выгребать сотни за раз незачем.
DETAILS_PER_TICK = 20
# Сколько живёт результат по спецификации.
RESULT_LIFETIME = geps.RESULT_LIFETIME


class Gateway(Protocol):
    """Обращения к ГЭПС. Реализация живёт в приложении, здесь только контракт."""

    async def search(self, payload: Dict[str, str]) -> str: ...

    async def result(self, task_uuid: str, offset: int, limit: int) -> Dict[str, Any]: ...

    async def message(self, thread_uuid: str, message_uuid: str) -> Dict[str, Any]: ...


def enabled() -> bool:
    """Включён ли автоматический режим.

    Значение читается из настроек, сохранённых оператором, а не только из
    окружения: включать почту через пересборку контейнера неудобно.
    """
    import settings_store

    saved = settings_store.load().get("GEPS_SCHEDULE_ENABLED")
    raw = saved if saved is not None else os.getenv("GEPS_SCHEDULE_ENABLED", "0")
    return str(raw).strip().lower() in {"1", "true", "да", "on"}


def interval_seconds() -> int:
    """Как часто просыпаться. Не то же самое, что частота обращений к ЕПГУ."""
    try:
        value = int(os.getenv("GEPS_SCHEDULE_INTERVAL", "900"))
    except ValueError:
        value = 900
    return max(60, value)


def target_range(now: Optional[datetime] = None) -> geps.SearchRange:
    """Период, который забираем: предыдущие сутки по московскому времени."""
    moment = (now or datetime.now(MOSCOW)).astimezone(MOSCOW)
    end = moment.replace(hour=0, minute=0, second=0, microsecond=0)
    return geps.SearchRange(start=end - geps.MAX_RANGE, end=end)


def _parse(value: Any) -> Optional[datetime]:
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value))
    except ValueError:
        return None


async def _collect_results(
    gateway: Gateway,
    now: datetime,
    report: Dict[str, Any],
) -> None:
    """Сходить за результатом по заявкам, которым подошло время."""
    for job in geps_store.pending_jobs():
        ordered_at = _parse(job.get("created_at"))
        if ordered_at and now - ordered_at > RESULT_LIFETIME:
            geps_store.update_job(
                job["id"],
                state=geps_store.STATE_EXPIRED,
                error="Результат живёт семь дней и уже недоступен",
            )
            report["expired"] += 1
            continue

        due = _parse(job.get("next_check_at")) or (
            (ordered_at + FIRST_CHECK_AFTER) if ordered_at else now
        )
        if due > now:
            continue
        if geps_quota.exhausted("result"):
            report["skipped"].append("суточные попытки на получение списка кончились")
            return

        geps_quota.take("result")
        try:
            page = await gateway.result(job["task_uuid"], 0, geps.MAX_PAGE_SIZE)
        except Exception as err:  # обращение к чужой системе, причин много
            logger.warning("Не удалось забрать список %s: %s", job["id"], type(err).__name__)
            geps_store.update_job(
                job["id"],
                checks=int(job.get("checks") or 0) + 1,
                next_check_at=(now + RETRY_CHECK_AFTER).isoformat(timespec="seconds"),
                error=str(err)[:300],
            )
            report["errors"] += 1
            continue

        status = str(page.get("status") or "")
        if page.get("ready"):
            messages = page.get("messages") or []
            added = geps_store.save_messages(job["id"], messages)
            geps_store.update_job(
                job["id"],
                state=geps_store.STATE_READY,
                ready_at=now.isoformat(timespec="seconds"),
                checks=int(job.get("checks") or 0) + 1,
                message_count=len(messages),
                error="",
            )
            report["ready"] += 1
            report["new_messages"] += added
            logger.info(
                "Список %s готов: уведомлений %d, новых %d", job["id"], len(messages), added
            )
        elif status == geps.SearchTaskStatus.ERROR.value:
            geps_store.update_job(
                job["id"],
                state=geps_store.STATE_FAILED,
                checks=int(job.get("checks") or 0) + 1,
                error="ГЭПС не смог подготовить список, нужен новый заказ",
            )
            report["errors"] += 1
        else:
            geps_store.update_job(
                job["id"],
                checks=int(job.get("checks") or 0) + 1,
                next_check_at=(now + RETRY_CHECK_AFTER).isoformat(timespec="seconds"),
            )
            report["waiting"] += 1


async def _order_if_needed(
    gateway: Gateway,
    now: datetime,
    report: Dict[str, Any],
) -> None:
    """Заказать список за нужные сутки, если его ещё не заказывали."""
    window = target_range(now)
    payload = window.to_payload()
    if geps_store.has_job_for_range(payload):
        return
    if geps_quota.exhausted("search"):
        report["skipped"].append("суточные попытки на заказ списка кончились")
        return
    try:
        window.validate_against(now)
    except Exception as err:
        report["skipped"].append(f"период не подошёл: {err}")
        return

    geps_quota.take("search")
    try:
        task_uuid = await gateway.search(payload)
    except Exception as err:
        logger.warning("Не удалось заказать список: %s", type(err).__name__)
        report["errors"] += 1
        return
    job = geps_store.create_job(payload, task_uuid)
    geps_store.update_job(
        job["id"], next_check_at=(now + FIRST_CHECK_AFTER).isoformat(timespec="seconds")
    )
    report["ordered"] += 1
    logger.info("Заказан список за %s", payload["startDateTime"])


async def _collect_details(gateway: Gateway, report: Dict[str, Any]) -> None:
    """Добрать карточки уведомлений. Лимитом не ограничены."""
    page = geps_store.list_messages(limit=DETAILS_PER_TICK, without_detail=True)
    for item in page["messages"]:
        thread_uuid = item.get("thread_uuid") or ""
        message_uuid = item.get("message_uuid") or ""
        if not thread_uuid or not message_uuid:
            continue
        try:
            detail = await gateway.message(thread_uuid, message_uuid)
        except Exception as err:
            logger.warning("Карточка %s не открылась: %s", message_uuid, type(err).__name__)
            report["errors"] += 1
            continue
        geps_store.save_detail(message_uuid, detail)
        report["details"] += 1


async def tick(gateway: Gateway, now: Optional[datetime] = None) -> Dict[str, Any]:
    """Один такт планировщика. Возвращает отчёт о том, что сделано."""
    moment = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    report: Dict[str, Any] = {
        "at": moment.isoformat(timespec="seconds"),
        "ordered": 0,
        "ready": 0,
        "waiting": 0,
        "expired": 0,
        "errors": 0,
        "new_messages": 0,
        "details": 0,
        "skipped": [],
    }
    await _collect_results(gateway, moment, report)
    await _order_if_needed(gateway, moment, report)
    await _collect_details(gateway, report)
    report["quota"] = geps_quota.describe()
    report["counts"] = geps_store.counts()
    return report


class Scheduler:
    """Фоновая задача, которая крутит :func:`tick`.

    Такт выполняется, только когда включён автоматический режим и есть
    действующий маркер доступа: без него ходить некуда, а будить оператора
    задача не умеет.
    """

    def __init__(
        self,
        gateway_factory: Callable[[], Awaitable[Optional[Gateway]]],
    ) -> None:
        self._gateway_factory = gateway_factory
        self._task: Optional[asyncio.Task] = None
        self._last_report: Dict[str, Any] = {}
        self._last_skip = ""

    def start(self) -> None:
        if self._task is not None:
            return
        self._task = asyncio.create_task(self._run(), name="geps-scheduler")
        logger.info(
            "Планировщик Госпочты запущен, автоматический режим: %s",
            "включён" if enabled() else "выключен",
        )

    async def stop(self) -> None:
        task, self._task = self._task, None
        if task is None:
            return
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

    @property
    def running(self) -> bool:
        return self._task is not None and not self._task.done()

    def describe(self) -> Dict[str, Any]:
        return {
            "running": self.running,
            "enabled": enabled(),
            "interval_seconds": interval_seconds(),
            "target_range": target_range().to_payload(),
            "last_report": self._last_report,
            "last_skip": self._last_skip,
            "quota": geps_quota.describe(),
            "counts": geps_store.counts(),
        }

    @staticmethod
    async def _close(gateway: Any) -> None:
        """Шлюз может держать соединение, и оставлять его открытым нельзя."""
        closer = getattr(gateway, "aclose", None)
        if closer is not None:
            try:
                await closer()
            except Exception:
                logger.debug("Шлюз ГЭПС закрыть не удалось", exc_info=True)

    async def run_once(self) -> Dict[str, Any]:
        """Один такт по требованию оператора, минуя выключатель."""
        gateway = await self._gateway_factory()
        if gateway is None:
            self._last_skip = "нет действующего маркера доступа"
            return {"skipped": self._last_skip}
        try:
            self._last_report = await tick(gateway)
        finally:
            await self._close(gateway)
        self._last_skip = ""
        return self._last_report

    async def _run(self) -> None:
        while True:
            try:
                await asyncio.sleep(interval_seconds())
                if not enabled():
                    self._last_skip = "автоматический режим выключен"
                    continue
                gateway = await self._gateway_factory()
                if gateway is None:
                    self._last_skip = "нет действующего маркера доступа"
                    continue
                try:
                    self._last_report = await tick(gateway)
                finally:
                    await self._close(gateway)
                self._last_skip = ""
            except asyncio.CancelledError:
                raise
            except Exception:
                # Фоновая задача не имеет права умереть: следующий такт может
                # пройти нормально, а падение оставит стенд без почты молча.
                logger.exception("Такт планировщика Госпочты не удался")
