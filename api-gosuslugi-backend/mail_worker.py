"""Автоматическая обработка почты: разбор запросов, вложения, сроки, ответы.

Переписка с поддержкой ЕПГУ идёт по понятному распорядку, и его можно
выполнять машинально. Робот ФГИС СЦ пишет в каждом письме одно и то же:
запрос зарегистрирован, статус изменился, добавлен файл, запрос выполнен.
На последнее он ждёт ответа: "Просим Вас в течение 3-х календарных дней
ответным письмом подтвердить решение запроса". Не ответили - запрос
закрывается сам, и историю приходится начинать заново.

Что делает один такт (:func:`tick`):

1. Перечитывает ящик и собирает запросы по номерам SCR.
2. Забирает вложения новых писем: сертификаты и ключи в свои каталоги,
   инструкции и архивы к документам.
3. Считает срок ответа по решённым запросам и показывает, сколько осталось.
4. Если оператор явно это разрешил, отправляет подтверждение решения.

Про последний пункт отдельно. Отправка письма наружу от имени организации -
не то действие, которое стоит включать по умолчанию: подтверждение решения
означает согласие с ним. Поэтому автоматический ответ выключен, включается
отдельным переключателем, ждёт заданное время после письма и пишет в журнал
каждое отправленное письмо. Всё остальное, чтение и раскладка файлов, наружу
ничего не отправляет и потому безопасно.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import certsources
import mail_state
import mailbox
import settings_store

logger = logging.getLogger("mail.worker")

# Срок из письма робота: три календарных дня на подтверждение решения.
REPLY_DEADLINE = timedelta(days=3)
# Через сколько после истечения срока перестаём показывать запрос: его уже
# закрыли без нас, и напоминать не о чем.
FORGET_AFTER = timedelta(days=7)
# Сколько записей журнала храним. Больше незачем, это не аудит.
LOG_KEEP = 60
# Сколько писем просматриваем за такт в поисках вложений.
LETTERS_PER_TICK = 20

# Кому автоматика вообще имеет право написать. Закрытый список: это
# единственное место системы, где письмо уходит наружу без человека.
SUPPORT_ADDRESSES = {"sd@sc.digital.gov.ru", "api@digital.gov.ru"}

_lock = threading.Lock()


# ---------- настройки ----------


def _flag(name: str, default: str = "0") -> bool:
    saved = settings_store.load().get(name)
    raw = saved if saved is not None else os.getenv(name, default)
    return str(raw).strip().lower() in {"1", "true", "да", "on"}


def enabled() -> bool:
    """Включена ли автоматическая обработка почты."""
    return _flag("MAIL_AUTO_ENABLED")


def collect_enabled() -> bool:
    """Забирать ли вложения. Наружу ничего не уходит, поэтому по умолчанию да."""
    return _flag("MAIL_AUTO_COLLECT", "1")


def confirm_enabled() -> bool:
    """Отправлять ли подтверждение решения. Выключено, это письмо наружу."""
    return _flag("MAIL_AUTO_CONFIRM")


def confirm_after_hours() -> int:
    """Сколько ждать после письма о решении, прежде чем подтверждать."""
    saved = settings_store.load().get("MAIL_AUTO_CONFIRM_AFTER")
    raw = saved if saved is not None else os.getenv("MAIL_AUTO_CONFIRM_AFTER", "48")
    try:
        value = int(str(raw).strip())
    except ValueError:
        value = 48
    # Раньше часа не подтверждаем и позже трёх суток тоже: срок истечёт.
    return max(1, min(value, 71))


def interval_seconds() -> int:
    try:
        value = int(os.getenv("MAIL_AUTO_INTERVAL", "900"))
    except ValueError:
        value = 900
    return max(60, value)


def state_path() -> Path:
    return Path(os.getenv("MAIL_AUTO_FILE", str(certsources.cert_dir() / "mail-auto.json")))


# ---------- журнал ----------


def load_state() -> Dict[str, Any]:
    path = state_path()
    if not path.exists():
        return {"confirmed": {}, "log": [], "last_run": ""}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        logger.warning("Журнал автоматики повреждён, начинаем заново")
        return {"confirmed": {}, "log": [], "last_run": ""}
    data.setdefault("confirmed", {})
    data.setdefault("log", [])
    data.setdefault("last_run", "")
    return data


def _save_state(state: Dict[str, Any]) -> None:
    path = state_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    state["log"] = state.get("log", [])[-LOG_KEEP:]
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(state, ensure_ascii=False, indent=1), encoding="utf-8")
    temporary.replace(path)


def note(kind: str, text: str, *, ticket: str = "") -> Dict[str, Any]:
    """Записать в журнал одно действие автоматики."""
    entry = {
        "at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "kind": kind,
        "text": text,
        "ticket": ticket,
    }
    with _lock:
        state = load_state()
        state["log"].append(entry)
        _save_state(state)
    return entry


def _remember_confirmed(ticket: str) -> None:
    with _lock:
        state = load_state()
        state["confirmed"][ticket] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        _save_state(state)


# ---------- сроки ----------


def _parse_time(value: str) -> Optional[datetime]:
    if not value:
        return None
    try:
        moment = datetime.fromisoformat(str(value))
    except ValueError:
        return None
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    return moment


def deadlines(threads: List[Dict[str, Any]], now: Optional[datetime] = None) -> List[Dict[str, Any]]:
    """Запросы, которые ждут нашего подтверждения, и сколько осталось.

    Считаем от письма, которым запрос объявлен выполненным: именно оно
    начинает трёхдневный срок.
    """
    moment = now or datetime.now(timezone.utc)
    waiting: List[Dict[str, Any]] = []
    confirmed = load_state().get("confirmed", {})
    for thread in threads:
        # Три дня даются на два случая: подтвердить решение и ответить на
        # запрос уточнения. Второй в интерфейсе подсвечен красным, и не
        # считать по нему срок было бы странно.
        if thread.get("status_kind") not in {"done", "action"}:
            continue
        if thread.get("status") == "Закрыт":
            continue
        started = _parse_time(thread.get("status_at", ""))
        if started is None:
            continue
        due = started + REPLY_DEADLINE
        # Давно просроченные запросы поддержка закрыла сама, и держать их в
        # списке "ждут ответа" значит превратить его в свалку.
        if moment - due > FORGET_AFTER:
            continue
        waiting.append(
            {
                "ticket": thread["ticket"],
                "topic": thread.get("topic", ""),
                "status_at": thread.get("status_at", ""),
                "due_at": due.isoformat(timespec="seconds"),
                "hours_left": round((due - moment).total_seconds() / 3600, 1),
                "overdue": due < moment,
                "answered": thread["ticket"] in confirmed,
                "kind": thread.get("status_kind", ""),
                "status_label": thread.get("status", ""),
                # Отвечаем на письмо, которым объявлено решение.
                "uid": thread.get("status_uid") or (thread.get("uids") or [""])[-1],
            }
        )
    waiting.sort(key=lambda item: item["hours_left"])
    return waiting


# ---------- письмо подтверждения ----------


def confirmation_body(ticket: str) -> str:
    """Текст подтверждения решения, подписанный реквизитами организации."""
    saved = settings_store.load()
    name = saved.get("CONTACT_NAME", "") or saved.get("contact_name", "")
    org = saved.get("ORG_SHORT_NAME", "") or saved.get("ORG_FULL_NAME", "")
    lines = [
        "Здравствуйте!",
        "",
        "Подтверждаем решение запроса SCR#%s. Вопрос закрыт, претензий нет." % ticket,
        "",
        "С уважением,",
    ]
    if name:
        lines.append(name)
    if org:
        lines.append(org)
    return "\n".join(lines)


# ---------- такт ----------


def tick(now: Optional[datetime] = None) -> Dict[str, Any]:
    """Один проход по ящику. Возвращает отчёт о том, что сделано."""
    moment = now or datetime.now(timezone.utc)
    report: Dict[str, Any] = {
        "at": moment.isoformat(timespec="seconds"),
        "threads": 0,
        "collected": [],
        "confirmed": [],
        "waiting": [],
        "skipped": [],
    }
    config = mailbox.load_config()
    if not config.configured:
        report["skipped"].append("почта не настроена")
        return report

    headers = mailbox.fetch_headers(config, scan=200)
    threads = mailbox.build_threads(headers)
    threads = mail_state.annotate(threads)
    report["threads"] = len(threads)

    if collect_enabled():
        report["collected"] = _collect(config)
    else:
        report["skipped"].append("забор вложений выключен")

    waiting = deadlines(threads, moment)
    report["waiting"] = waiting

    if confirm_enabled():
        report["confirmed"] = _confirm(config, waiting, moment)
    elif waiting:
        report["skipped"].append("автоматический ответ выключен")

    with _lock:
        state = load_state()
        state["last_run"] = report["at"]
        _save_state(state)
    return report


def _collect(config) -> List[Dict[str, Any]]:
    """Забрать новые вложения по каталогам. Наружу ничего не уходит."""
    import attachments

    try:
        items = mailbox.list_attachments(config, letters=LETTERS_PER_TICK)
    except mailbox.MailError as err:
        note("error", "Вложения прочитать не удалось: %s" % err)
        return []

    existing = set()
    for folder in (certsources.cert_dir(), certsources.keys_dir()):
        if folder.exists():
            existing.update(path.name for path in folder.rglob("*") if path.is_file())

    saved: List[Dict[str, Any]] = []
    for item in items:
        kind = attachments.guess_kind(item["name"])
        if kind == "unknown" or item.get("too_large") or item["name"] in existing:
            continue
        target = certsources.keys_dir() if kind == "key" else None
        try:
            result = mailbox.save_attachment(
                config, uid=item["uid"], index=item["index"], target_dir=target
            )
        except mailbox.MailError as err:
            note("error", "%s: %s" % (item["name"], err), ticket=item.get("ticket", ""))
            continue
        existing.add(result["name"])
        result["kind"] = kind
        result["ticket"] = item.get("ticket", "")
        saved.append(result)
        note("collect", "Забран файл %s" % result["name"], ticket=result["ticket"])
    return saved


def _confirm(config, waiting: List[Dict[str, Any]], now: datetime) -> List[Dict[str, Any]]:
    """Подтвердить решение запросов, которым подошёл срок.

    Осторожность здесь не лишняя: письмо уходит наружу от имени организации.
    Подтверждаем только то, что действительно выполнено, только один раз и
    только после выдержки, чтобы человек успел посмотреть решение сам.
    """
    ready = timedelta(hours=confirm_after_hours())
    sent: List[Dict[str, Any]] = []
    for item in waiting:
        if item["answered"] or item["overdue"] or not item["uid"]:
            continue
        # Уточняющий вопрос требует содержательного ответа: подтверждать
        # автоматически можно только объявленное решение.
        if item.get("kind") != "done":
            continue
        started = _parse_time(item["status_at"])
        if started is None or now - started < ready:
            continue
        try:
            original = mailbox.fetch_message(config, uid=item["uid"])
            # Тему письма подделать несложно. Отвечаем только на письма с
            # ведомственных адресов и только на известные адреса поддержки.
            if not mailbox.is_watched(original.get("from", "")):
                note("error", "Письмо не с ведомственного адреса, ответ не отправлен",
                     ticket=item["ticket"])
                continue
            if mailbox.address_only(original["reply_to"]) not in SUPPORT_ADDRESSES:
                note("error", "Адрес ответа вне списка поддержки, письмо не отправлено",
                     ticket=item["ticket"])
                continue
            body = confirmation_body(item["ticket"])
            mailbox.send_letter(
                config,
                to=original["reply_to"],
                subject=mailbox.reply_subject(original["subject"]),
                body=body + "\n\n" + mailbox.quote_original(original),
                in_reply_to=original.get("message_id", ""),
            )
        except mailbox.MailError as err:
            note("error", "Подтверждение не ушло: %s" % err, ticket=item["ticket"])
            continue
        _remember_confirmed(item["ticket"])
        mail_state.mark_read(item["ticket"], item["status_at"])
        note("confirm", "Отправлено подтверждение решения", ticket=item["ticket"])
        logger.warning("Автоматика подтвердила решение запроса SCR#%s", item["ticket"])
        sent.append({"ticket": item["ticket"], "to": original["reply_to"]})
    return sent


def describe() -> Dict[str, Any]:
    """Состояние автоматики для интерфейса."""
    state = load_state()
    return {
        "enabled": enabled(),
        "collect": collect_enabled(),
        "confirm": confirm_enabled(),
        "confirm_after_hours": confirm_after_hours(),
        "interval_seconds": interval_seconds(),
        "last_run": state.get("last_run", ""),
        "log": list(reversed(state.get("log", [])))[:LOG_KEEP],
        "confirmed": state.get("confirmed", {}),
    }


class Worker:
    """Фоновая задача, которая крутит :func:`tick`."""

    def __init__(self) -> None:
        self._task: Optional[asyncio.Task] = None
        self._last_report: Dict[str, Any] = {}

    def start(self) -> None:
        if self._task is not None:
            return
        self._task = asyncio.create_task(self._run(), name="mail-worker")
        logger.info(
            "Обработка почты запущена, автоматический режим: %s",
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

    async def run_once(self) -> Dict[str, Any]:
        """Такт по кнопке. Работает и при выключенном автоматическом режиме."""
        self._last_report = await asyncio.to_thread(tick)
        return self._last_report

    def describe(self) -> Dict[str, Any]:
        state = describe()
        state["running"] = self.running
        state["last_report"] = self._last_report
        return state

    async def _run(self) -> None:
        first = True
        while True:
            try:
                # Первый такт делаем почти сразу: ждать четверть часа после
                # запуска стенда, чтобы увидеть почту, незачем.
                await asyncio.sleep(10 if first else interval_seconds())
                first = False
                if not enabled():
                    continue
                self._last_report = await asyncio.to_thread(tick)
            except asyncio.CancelledError:
                raise
            except Exception:
                # Фоновая задача не имеет права умереть: следующий такт может
                # пройти нормально, а падение оставит почту без присмотра.
                logger.exception("Такт обработки почты не удался")
