"""Хранение Госпочты: заявки, уведомления и вложения.

Лимиты ГЭПС устроены так, что забирать одно и то же по второму разу нельзя:
пять заказов списка в сутки, пятнадцать получений результата, а сам результат
живёт семь дней и потом пропадает. Поэтому всё, что удалось получить, сразу
ложится на том и дальше читается уже отсюда.

Раскладка на томе (по умолчанию ``/var/lib/epgu-mail/geps``)::

    jobs.json                     заявки на список и их состояние
    messages.json                 уведомления: краткие данные и карточки
    files/<messageUuid>/<файл>    сохранённые вложения и подписи

Формат простой и читаемый глазами: при разборе инцидента важнее открыть файл,
чем сэкономить место.
"""

from __future__ import annotations

import json
import os
import re
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

DEFAULT_DIR = "/var/lib/epgu-mail/geps"

# Состояния заявки на список.
STATE_ORDERED = "ordered"    # заказана, список ещё готовится
STATE_READY = "ready"        # список получен и разложен
STATE_FAILED = "failed"      # ГЭПС ответил ошибкой или задача провалилась
STATE_EXPIRED = "expired"    # семь дней прошло, забирать больше нечего

_lock = threading.RLock()


def root() -> Path:
    return Path(os.getenv("GEPS_STORE_DIR", DEFAULT_DIR))


def jobs_path() -> Path:
    return root() / "jobs.json"


def messages_path() -> Path:
    return root() / "messages.json"


def files_root() -> Path:
    return root() / "files"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _read(path: Path) -> Dict[str, Any]:
    if not path.exists():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        # Битый файл не должен ронять выдачу: считаем, что данных нет.
        return {}
    return data if isinstance(data, dict) else {}


def _write(path: Path, data: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(data, ensure_ascii=False, indent=1), encoding="utf-8")
    temp.replace(path)


def safe_name(name: str, default: str = "attachment") -> str:
    """Имя файла, пригодное для записи на диск.

    Имя приходит от отправителя. Библиотека его уже чистит, но здесь оно
    попадает в путь, поэтому проверяем ещё раз: разделители, управляющие
    символы и попытки подняться вверх по дереву.
    """
    # Сначала берём последнюю часть пути: так "../../etc/passwd" превращается
    # в "passwd", а не в строку с подчёркиваниями вместо разделителей.
    base = str(name or "").replace("\\", "/").split("/")[-1]
    cleaned = re.sub(r'[\x00-\x1f<>:"|?*]', "_", base).strip()
    cleaned = cleaned.strip(". ")
    if not cleaned or cleaned in (".", ".."):
        return default
    return cleaned[:150]


# ---------- заявки ----------


def create_job(payload: Dict[str, str], task_uuid: str) -> Dict[str, Any]:
    """Записать заказанный список."""
    job = {
        "id": str(uuid.uuid4()),
        "created_at": now_iso(),
        "range": dict(payload),
        "task_uuid": task_uuid,
        "state": STATE_ORDERED,
        "checks": 0,
        "next_check_at": None,
        "ready_at": None,
        "message_count": 0,
        "error": "",
    }
    with _lock:
        jobs = _read(jobs_path())
        jobs[job["id"]] = job
        _write(jobs_path(), jobs)
    return dict(job)


def update_job(job_id: str, **changes: Any) -> Optional[Dict[str, Any]]:
    with _lock:
        jobs = _read(jobs_path())
        job = jobs.get(job_id)
        if job is None:
            return None
        job.update(changes)
        job["updated_at"] = now_iso()
        jobs[job_id] = job
        _write(jobs_path(), jobs)
        return dict(job)


def get_job(job_id: str) -> Optional[Dict[str, Any]]:
    with _lock:
        job = _read(jobs_path()).get(job_id)
    return dict(job) if job else None


def list_jobs(state: str = "", limit: int = 50) -> List[Dict[str, Any]]:
    """Заявки, свежие сверху."""
    with _lock:
        jobs = list(_read(jobs_path()).values())
    if state:
        jobs = [job for job in jobs if job.get("state") == state]
    jobs.sort(key=lambda item: item.get("created_at") or "", reverse=True)
    return [dict(job) for job in jobs[:limit]]


def pending_jobs() -> List[Dict[str, Any]]:
    """Заявки, за результатом которых ещё надо сходить."""
    return [job for job in list_jobs(limit=1000) if job.get("state") == STATE_ORDERED]


def has_job_for_range(payload: Dict[str, str]) -> bool:
    """Не заказывали ли уже этот же период.

    Заказов пять в сутки, повторять один и тот же период незачем.
    """
    wanted = (payload.get("startDateTime"), payload.get("endDateTime"))
    for job in list_jobs(limit=1000):
        window = job.get("range") or {}
        if (window.get("startDateTime"), window.get("endDateTime")) == wanted:
            if job.get("state") in (STATE_ORDERED, STATE_READY):
                return True
    return False


# ---------- уведомления ----------


def save_messages(job_id: str, messages: List[Dict[str, Any]]) -> int:
    """Разложить краткие данные из списка. Возвращает число новых."""
    stored_now = now_iso()
    added = 0
    with _lock:
        known = _read(messages_path())
        for item in messages:
            key = str(item.get("messageUuid") or "")
            if not key:
                continue
            record = known.get(key)
            if record is None:
                added += 1
                record = {
                    "message_uuid": key,
                    "job_id": job_id,
                    "stored_at": stored_now,
                    "detail": None,
                    "attachments": [],
                }
            record.update(
                {
                    "thread_uuid": item.get("threadUuid") or record.get("thread_uuid", ""),
                    "sender": item.get("sender") or record.get("sender", ""),
                    "subject": item.get("subject") or record.get("subject", ""),
                    "is_read": bool(item.get("isRead")),
                    "create_date": item.get("createDate") or record.get("create_date"),
                }
            )
            known[key] = record
        _write(messages_path(), known)
    return added


def save_detail(message_uuid: str, detail: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    """Сохранить карточку уведомления вместе с описанием вложений."""
    with _lock:
        known = _read(messages_path())
        record = known.get(message_uuid)
        if record is None:
            record = {
                "message_uuid": message_uuid,
                "job_id": "",
                "stored_at": now_iso(),
                "attachments": [],
            }
        saved_by_uuid = {
            item.get("attachment_uuid"): item
            for item in record.get("attachments") or []
        }
        attachments = []
        for item in detail.get("attachments") or []:
            key = item.get("attachmentUuid")
            previous = saved_by_uuid.get(key) or {}
            attachments.append(
                {
                    "attachment_uuid": key,
                    "file_name": item.get("fileName") or "",
                    "file_size": item.get("fileSize"),
                    "mime_type": item.get("mimeType") or "",
                    "signed": bool(item.get("signed")),
                    "status": item.get("status") or "",
                    "status_description": item.get("statusDescription") or "",
                    "downloadable": bool(item.get("downloadable")),
                    # Пути к уже скачанному не теряем при повторном чтении карточки.
                    "saved_path": previous.get("saved_path"),
                    "saved_at": previous.get("saved_at"),
                    "signature_path": previous.get("signature_path"),
                }
            )
        record.update(
            {
                "thread_uuid": detail.get("threadUuid") or record.get("thread_uuid", ""),
                "sender": detail.get("sender") or record.get("sender", ""),
                "subject": detail.get("subject") or record.get("subject", ""),
                "is_read": bool(detail.get("isRead")),
                "create_date": detail.get("createDate") or record.get("create_date"),
                "detail": {
                    "html": detail.get("html") or "",
                    "params": detail.get("params") or {},
                    "statuses": detail.get("statuses") or [],
                    "fetched_at": now_iso(),
                },
                "attachments": attachments,
            }
        )
        known[message_uuid] = record
        _write(messages_path(), known)
        return dict(record)


def save_attachment(
    message_uuid: str,
    attachment_uuid: str,
    content: bytes,
    file_name: str,
    *,
    signature: bool = False,
) -> Dict[str, Any]:
    """Положить вложение на том и запомнить путь."""
    folder = files_root() / safe_name(message_uuid, "message")
    folder.mkdir(parents=True, exist_ok=True)
    name = safe_name(file_name, "attachment")
    if signature and not name.endswith(".sig"):
        name = name + ".sig"
    target = folder / name
    target.write_bytes(content)

    with _lock:
        known = _read(messages_path())
        record = known.get(message_uuid)
        if record is not None:
            for item in record.get("attachments") or []:
                if item.get("attachment_uuid") == attachment_uuid:
                    if signature:
                        item["signature_path"] = str(target)
                    else:
                        item["saved_path"] = str(target)
                        item["saved_at"] = now_iso()
            known[message_uuid] = record
            _write(messages_path(), known)
    return {"path": str(target), "size": len(content), "file_name": name}


def get_message(message_uuid: str) -> Optional[Dict[str, Any]]:
    with _lock:
        record = _read(messages_path()).get(message_uuid)
    return dict(record) if record else None


def list_messages(
    *,
    offset: int = 0,
    limit: int = 10,
    only_unread: bool = False,
    without_detail: bool = False,
    thread_uuid: str = "",
) -> Dict[str, Any]:
    """Страница сохранённых уведомлений, свежие сверху."""
    with _lock:
        records = list(_read(messages_path()).values())
    if only_unread:
        records = [item for item in records if not item.get("is_read")]
    if without_detail:
        records = [item for item in records if not item.get("detail")]
    if thread_uuid:
        records = [item for item in records if item.get("thread_uuid") == thread_uuid]
    records.sort(key=lambda item: item.get("create_date") or item.get("stored_at") or "", reverse=True)
    page = records[offset : offset + limit]
    return {
        "messages": [dict(item) for item in page],
        "total": len(records),
        "offset": offset,
        "limit": limit,
    }


def counts() -> Dict[str, int]:
    with _lock:
        records = list(_read(messages_path()).values())
        jobs = list(_read(jobs_path()).values())
    return {
        "messages": len(records),
        "unread": sum(1 for item in records if not item.get("is_read")),
        "without_detail": sum(1 for item in records if not item.get("detail")),
        "attachments_saved": sum(
            1
            for item in records
            for att in item.get("attachments") or []
            if att.get("saved_path")
        ),
        "jobs": len(jobs),
        "jobs_pending": sum(1 for job in jobs if job.get("state") == STATE_ORDERED),
    }


def clear() -> None:
    """Забыть всё: заявки, уведомления и скачанные файлы."""
    import shutil

    with _lock:
        for path in (jobs_path(), messages_path()):
            try:
                path.unlink()
            except FileNotFoundError:
                pass
        shutil.rmtree(files_root(), ignore_errors=True)
