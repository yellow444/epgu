"""Операторские эндпоинты мастера настройки: почта и источники сертификатов.

Подключаются к основному приложению, которое слушает только localhost.
Публичный приёмник входящих запросов этих методов не имеет.

Письма никогда не уходят сами: отправка происходит только явным вызовом
``POST /mail/send`` с уже собранным текстом, который оператор видел.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

import certsources
import mailbox
import secret_store

logger = logging.getLogger(__name__)


class LetterRequest(BaseModel):
    to: str = Field(min_length=3, max_length=320)
    subject: str = Field(min_length=1, max_length=500)
    body: str = Field(min_length=1, max_length=100000)
    cc: str = Field(default="", max_length=320)


class ImportRequest(BaseModel):
    path: str
    store: str = "uMy"
    link_container: str = ""


def setup_router() -> APIRouter:
    router = APIRouter(tags=["setup"])

    # ---------- Почта ----------

    @router.get("/mail/config")
    async def mail_config_route():
        """Настройки ящика без пароля: что задано и куда падают вложения."""
        return JSONResponse(content=mailbox.load_config().describe())

    @router.post("/mail/check")
    async def mail_check_route():
        """Проверить вход по IMAP и SMTP."""
        config = mailbox.load_config()
        if not config.imap_host and not config.smtp_host:
            raise HTTPException(status_code=400, detail="Почта не настроена")
        return JSONResponse(content=mailbox.check_connection(config))

    @router.post("/mail/send")
    async def mail_send_route(letter: LetterRequest):
        """Отправить письмо. Только по явному действию оператора."""
        config = mailbox.load_config()
        try:
            result = mailbox.send_letter(
                config,
                to=letter.to,
                subject=letter.subject,
                body=letter.body,
                cc=letter.cc,
            )
        except mailbox.MailError as err:
            raise HTTPException(status_code=502, detail=str(err)) from err
        return JSONResponse(content=result)

    @router.get("/mail/messages")
    async def mail_messages_route(
        limit: int = Query(30, ge=1, le=100),
        only_watched: bool = Query(True),
    ):
        """Ответы из ящика. По умолчанию только от ведомственных адресов."""
        config = mailbox.load_config()
        try:
            messages = mailbox.fetch_messages(
                config, limit=limit, only_watched=only_watched
            )
        except mailbox.MailError as err:
            raise HTTPException(status_code=502, detail=str(err)) from err
        return JSONResponse(content={"messages": messages, "watched": list(mailbox.WATCHED_DOMAINS)})

    @router.post("/mail/messages/{uid}/attachments/{index}/save")
    async def mail_save_attachment_route(uid: str, index: int):
        """Сохранить вложение в каталог сертификатов. Установка - отдельно."""
        config = mailbox.load_config()
        try:
            result = mailbox.save_attachment(config, uid=uid, index=index)
        except mailbox.MailError as err:
            raise HTTPException(status_code=502, detail=str(err)) from err
        return JSONResponse(content=result)

    # ---------- Источники сертификатов ----------

    @router.get("/certsources")
    async def certsources_route():
        """Папка с сертификатами, что видит КриптоПро и гайд по токену."""
        return JSONResponse(
            content={
                "folder": certsources.scan_folder(),
                "readers": certsources.readers_status(),
                "usb_guide": certsources.usb_guide(),
                "cryptopro": certsources.cryptopro_available(),
            }
        )

    @router.post("/certsources/import")
    async def certsources_import_route(request: ImportRequest):
        """Установить сертификат из каталога в хранилище КриптоПро."""
        folder = certsources.cert_dir().resolve()
        candidate = Path(request.path).resolve()
        # Путь приходит из UI, но проверяем его как чужой: ставить можно
        # только то, что лежит в каталоге сертификатов.
        if folder not in candidate.parents:
            raise HTTPException(
                status_code=400,
                detail="Устанавливать можно только файлы из каталога сертификатов",
            )
        try:
            result = certsources.import_certificate(
                candidate,
                request.store,
                link_container=request.link_container,
                pin=secret_store.get_secret("KeyPin"),
            )
        except FileNotFoundError as err:
            raise HTTPException(status_code=404, detail="Файл не найден") from err
        except ValueError as err:
            raise HTTPException(status_code=400, detail=str(err)) from err
        except RuntimeError as err:
            raise HTTPException(status_code=503, detail=str(err)) from err
        if not result["installed"]:
            raise HTTPException(status_code=502, detail="КриптоПро отказал в установке")
        return JSONResponse(content=result)

    return router
