"""Отдача Госпочты внешним системам.

Отдельное приложение и отдельный процесс, как и приёмник входящих запросов.
Причина та же: наружу смотрит только он, а операторские методы (сертификаты,
маркер доступа, подача заявлений) не должны быть доступны из чужой сети даже
теоретически.

Запуск::

    uvicorn outbound:app --host 0.0.0.0 --port 5002

Что важно понимать про этот процесс:

* **Он никогда не ходит в ЕПГУ.** Отдаётся только то, что уже лежит на томе.
  Обращение к ГЭПС равнозначно входу на портал и запускает процессуальные
  сроки, поэтому решение «сходить за почтой» принимает оператор, а не чужая
  информационная система своим запросом.
* **По умолчанию он закрыт.** В отличие от приёмника, который обязан принимать
  всё подряд, здесь отдаются данные организации. Пока не задан ни секрет
  ``OUTBOUND_TOKEN``, ни список сетей ``OUTBOUND_ALLOW_NETS``, отвечает только
  ``/health``, а на данные приходит 503 с объяснением.

Два формата на выбор потребителя:

    JSON              наш формат, полный
    Letters/Letter    XML по схеме Госпочты, для интеграций, которые её ждут
"""

from __future__ import annotations

import json
import logging
import os
import re
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from fastapi import FastAPI, Query, Request
from fastapi.responses import FileResponse, JSONResponse, PlainTextResponse, Response

import geps_store
import inbound_guard

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
)
logger = logging.getLogger("outbound")

PREFIX = "OUTBOUND"
TOKEN_HEADER = "x-outbound-token"
MAX_PAGE = 200

app = FastAPI(
    title="Отдача Госпочты",
    description=(
        "Уведомления Госпочты организации для внешних систем. Только чтение "
        "того, что уже забрано: в ЕПГУ этот процесс не ходит."
    ),
    version="1.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
)


def is_open() -> bool:
    """Настроена ли хоть одна проверка отправителя.

    Пока не настроена, данные не отдаём совсем. Приёмник в такой ситуации
    продолжает принимать, потому что его задача - не потерять чужой запрос.
    Здесь наоборот: молча отдать почту организации кому попало нельзя.
    """
    return bool(inbound_guard.token(PREFIX) or inbound_guard.allow_nets(PREFIX))


def _sender(request: Request) -> str:
    peer = request.client.host if request.client else ""
    return inbound_guard.client_ip(peer, request.headers.get("x-forwarded-for", ""), PREFIX)


def _admit(request: Request) -> Optional[Response]:
    """Пускать ли запрос. Возвращает готовый отказ или ничего."""
    if not is_open():
        inbound_guard.note_rejected("отдача не настроена")
        return JSONResponse(
            status_code=503,
            content={
                "code": "NOT_CONFIGURED",
                "message": (
                    "Отдача закрыта: задайте OUTBOUND_TOKEN или OUTBOUND_ALLOW_NETS"
                ),
            },
        )

    ip = _sender(request)
    if not inbound_guard.net_allowed(ip, PREFIX):
        count = inbound_guard.note_rejected("сеть не разрешена")
        logger.warning("Отказано %s: сеть не разрешена (всего %d)", ip, count)
        return JSONResponse(status_code=403, content={"code": "FORBIDDEN"})

    if not inbound_guard.token_matches(request.headers.get(TOKEN_HEADER, ""), PREFIX):
        count = inbound_guard.note_rejected("неверный секрет")
        logger.warning("Отказано %s: неверный секрет (всего %d)", ip, count)
        return JSONResponse(status_code=401, content={"code": "UNAUTHORIZED"})

    if not inbound_guard.rate_ok(ip, PREFIX):
        inbound_guard.note_rejected("слишком часто")
        return JSONResponse(
            status_code=429,
            content={"code": "TOO_MANY_REQUESTS"},
            headers={"Retry-After": "60"},
        )
    return None


# ---------- преобразование записей ----------


def _public_message(record: Dict[str, Any], *, with_detail: bool) -> Dict[str, Any]:
    """Запись для внешней системы. Пути к файлам на нашем диске не отдаём."""
    attachments = []
    for item in record.get("attachments") or []:
        attachments.append(
            {
                "attachmentUuid": item.get("attachment_uuid"),
                "fileName": item.get("file_name"),
                "fileSize": item.get("file_size"),
                "mimeType": item.get("mime_type"),
                "signed": bool(item.get("signed")),
                "status": item.get("status"),
                # Скачать через нас можно только то, что уже лежит на диске:
                # за файлом в ЕПГУ этот процесс не пойдёт.
                "available": bool(item.get("saved_path")),
                "signatureAvailable": bool(item.get("signature_path")),
            }
        )
    public = {
        "messageUuid": record.get("message_uuid"),
        "threadUuid": record.get("thread_uuid"),
        "sender": record.get("sender"),
        "subject": record.get("subject"),
        "isRead": bool(record.get("is_read")),
        "createDate": record.get("create_date"),
        "storedAt": record.get("stored_at"),
        "attachments": attachments,
    }
    detail = record.get("detail") or {}
    if with_detail:
        public["html"] = detail.get("html") or ""
        public["text"] = strip_html(detail.get("html") or "")
        public["params"] = detail.get("params") or {}
        public["statuses"] = detail.get("statuses") or []
    else:
        public["hasDetail"] = bool(detail)
    return public


_TAG_RE = re.compile(r"<[^>]+>")
_SPACE_RE = re.compile(r"[ \t]+")


def strip_html(html: str) -> str:
    """Текст без разметки: интеграциям нужен текст, а не вёрстка ЕПГУ."""
    if not html:
        return ""
    text = re.sub(r"(?is)<(script|style).*?</\1>", " ", html)
    text = re.sub(r"(?i)<br\s*/?>", "\n", text)
    text = re.sub(r"(?i)</(p|div|tr|li|h[1-6])>", "\n", text)
    text = _TAG_RE.sub("", text)
    for entity, char in (
        ("&nbsp;", " "),
        ("&amp;", "&"),
        ("&lt;", "<"),
        ("&gt;", ">"),
        ("&quot;", '"'),
        ("&#39;", "'"),
    ):
        text = text.replace(entity, char)
    text = _SPACE_RE.sub(" ", text)
    lines = [line.strip() for line in text.splitlines()]
    return "\n".join(line for line in lines if line)


def letters_xml(records: List[Dict[str, Any]], request_id: str) -> bytes:
    """Выгрузка по схеме Госпочты: Letters/Letter.

    Формат взят из давно живущей интеграции с 1С, чтобы её не переписывать.
    Соответствие полей:

        Date      дата уведомления
        Sender    отправитель, как показывает ЕПГУ
        Subject   тема
        Text      текст без разметки
        Ref       messageUuid, по нему же качаются вложения
        DocType   последний статус уведомления или GEPS
        BodyJSON  полная запись в нашем формате, если нужны детали
        Files     имена вложений
    """
    root = ET.Element("Letters", {"RequestID": request_id})
    for record in records:
        detail = record.get("detail") or {}
        statuses = detail.get("statuses") or []
        letter = ET.SubElement(root, "Letter")
        ET.SubElement(letter, "Date").text = _xml_datetime(record.get("create_date"))
        ET.SubElement(letter, "Sender").text = record.get("sender") or ""
        ET.SubElement(letter, "Subject").text = record.get("subject") or ""
        ET.SubElement(letter, "Text").text = strip_html(detail.get("html") or "")
        ET.SubElement(letter, "Ref").text = record.get("message_uuid") or ""
        ET.SubElement(letter, "DocType").text = (
            str(statuses[-1].get("mnemonic")) if statuses else "GEPS"
        )
        ET.SubElement(letter, "BodyJSON").text = json.dumps(
            _public_message(record, with_detail=False), ensure_ascii=False
        )
        attachments = record.get("attachments") or []
        if attachments:
            files = ET.SubElement(letter, "Files")
            for item in attachments:
                ET.SubElement(files, "FileName").text = item.get("file_name") or ""
    return b'<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="utf-8")


def _xml_datetime(value: Any) -> str:
    """xs:dateTime. Если дата непонятна, ставим время выгрузки, но не мусор."""
    if value:
        try:
            return datetime.fromisoformat(str(value)).isoformat(timespec="seconds")
        except ValueError:
            pass
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _select(
    offset: int,
    limit: int,
    only_unread: bool,
    since: str,
) -> Tuple[List[Dict[str, Any]], int]:
    """Страница записей с фильтром по дате.

    ``since`` полезен интеграциям: они забирают только то, чего ещё не видели.
    """
    page = geps_store.list_messages(offset=0, limit=100000, only_unread=only_unread)
    records = page["messages"]
    if since:
        records = [
            item
            for item in records
            if str(item.get("create_date") or item.get("stored_at") or "") >= since
        ]
    return records[offset : offset + limit], len(records)


# ---------- маршруты ----------


@app.get("/health")
async def health() -> JSONResponse:
    """Живость. Отвечает всегда, данных не содержит."""
    return JSONResponse(
        content={"status": "Ok", "configured": is_open()}
    )


@app.get("/messages")
async def messages(
    request: Request,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=MAX_PAGE),
    only_unread: bool = Query(False),
    since: str = Query("", max_length=40),
) -> Response:
    """Уведомления в нашем формате."""
    denied = _admit(request)
    if denied is not None:
        return denied
    records, total = _select(offset, limit, only_unread, since)
    return JSONResponse(
        content={
            "messages": [_public_message(item, with_detail=False) for item in records],
            "total": total,
            "offset": offset,
            "limit": limit,
        }
    )


@app.get("/messages/{message_uuid}")
async def message(request: Request, message_uuid: str) -> Response:
    """Одно уведомление вместе с текстом и статусами."""
    denied = _admit(request)
    if denied is not None:
        return denied
    record = geps_store.get_message(message_uuid)
    if record is None:
        return JSONResponse(status_code=404, content={"code": "NOT_FOUND"})
    return JSONResponse(content=_public_message(record, with_detail=True))


@app.get("/messages/{message_uuid}/attachments/{attachment_uuid}")
async def attachment(
    request: Request,
    message_uuid: str,
    attachment_uuid: str,
    signature: bool = Query(False),
) -> Response:
    """Файл вложения или отсоединённая подпись, если они уже скачаны."""
    denied = _admit(request)
    if denied is not None:
        return denied
    record = geps_store.get_message(message_uuid)
    if record is None:
        return JSONResponse(status_code=404, content={"code": "NOT_FOUND"})
    for item in record.get("attachments") or []:
        if item.get("attachment_uuid") != attachment_uuid:
            continue
        stored = item.get("signature_path") if signature else item.get("saved_path")
        if not stored:
            return JSONResponse(
                status_code=409,
                content={
                    "code": "NOT_DOWNLOADED",
                    "message": "Файл ещё не скачан оператором",
                },
            )
        path = Path(stored).resolve()
        root = geps_store.files_root().resolve()
        # Путь берём из своего же хранилища, но проверяем: запись могли
        # подправить руками, а отдавать что-то за пределами каталога нельзя.
        if root not in path.parents or not path.is_file():
            logger.warning("Файл вне каталога хранилища: %s", stored)
            return JSONResponse(status_code=404, content={"code": "NOT_FOUND"})
        return FileResponse(
            path,
            media_type=item.get("mime_type") or "application/octet-stream",
            filename=path.name,
        )
    return JSONResponse(status_code=404, content={"code": "NOT_FOUND"})


@app.get("/letters")
async def letters(
    request: Request,
    offset: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=MAX_PAGE),
    only_unread: bool = Query(False),
    since: str = Query("", max_length=40),
    request_id: str = Query("", max_length=64),
) -> Response:
    """Те же уведомления в формате Letters/Letter."""
    denied = _admit(request)
    if denied is not None:
        return denied
    records, _ = _select(offset, limit, only_unread, since)
    body = letters_xml(records, request_id or datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S"))
    return Response(content=body, media_type="application/xml; charset=utf-8")


@app.get("/")
async def root(request: Request) -> Response:
    """Короткая справка о том, что здесь есть."""
    denied = _admit(request)
    if denied is not None:
        return denied
    return JSONResponse(
        content={
            "status": "ok",
            "endpoints": {
                "messages": "/messages",
                "message": "/messages/{messageUuid}",
                "attachment": "/messages/{messageUuid}/attachments/{attachmentUuid}",
                "letters": "/letters",
                "health": "/health",
            },
            "counts": geps_store.counts(),
        }
    )


@app.head("/health")
async def head_health() -> PlainTextResponse:
    return PlainTextResponse(content="", status_code=200)


@app.on_event("startup")
async def announce() -> None:
    state = inbound_guard.describe(PREFIX)
    if not is_open():
        logger.warning(
            "Отдача Госпочты закрыта: не задан ни OUTBOUND_TOKEN, ни "
            "OUTBOUND_ALLOW_NETS. Данные отдаваться не будут."
        )
    else:
        logger.info(
            "Отдача Госпочты открыта. Сети: %s. Секрет: %s. Частота: %s в минуту.",
            ", ".join(state["allow_nets"]) or "любые",
            "требуется" if state["token_required"] else "не требуется",
            state["rate_per_minute"],
        )
    if state["token_required"] and not inbound_guard.token_is_transferable(PREFIX):
        logger.error(
            "OUTBOUND_TOKEN содержит символы вне латиницы: такой заголовок "
            "потребитель передать не сможет."
        )


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=int(os.getenv("OUTBOUND_SERVER_PORT", "5002")))
