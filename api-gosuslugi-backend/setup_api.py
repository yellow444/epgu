"""Операторские эндпоинты мастера настройки: почта и источники сертификатов.

Подключаются к основному приложению, которое слушает только localhost.
Публичный приёмник входящих запросов этих методов не имеет.

Письма никогда не уходят сами: отправка происходит только явным вызовом
``POST /mail/send`` с уже собранным текстом, который оператор видел.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

import certsources
import maildiscovery
import mail_state
import mailbox
import secret_store
import settings_store

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


class ProfileRequest(BaseModel):
    """Реквизиты организации, которыми заполняются письма Оператору."""

    org_full_name: str = Field(default="", max_length=300)
    org_short_name: str = Field(default="", max_length=200)
    org_inn: str = Field(default="", max_length=12)
    org_ogrn: str = Field(default="", max_length=15)
    org_oktmo: str = Field(default="", max_length=11)
    org_role: str = Field(default="", max_length=50)
    is_mnemonic: str = Field(default="", max_length=100)
    contact_name: str = Field(default="", max_length=200)
    contact_role: str = Field(default="", max_length=200)
    contact_phone: str = Field(default="", max_length=50)
    contact_email: str = Field(default="", max_length=320)


class ReadRequest(BaseModel):
    """Какие запросы отметить. Пустой список - все сразу."""

    tickets: List[str] = Field(default_factory=list)


class ResetRequest(BaseModel):
    """Что стирать при общем сбросе. Настройки стираются всегда."""

    clear_inbound: bool = False
    clear_files: bool = False


class DiscoverRequest(BaseModel):
    """Адрес ящика или домен, по которому ищем серверы."""

    address: str = Field(min_length=3, max_length=320)


class MailSettingsRequest(BaseModel):
    """Что оператор сохраняет из интерфейса. Пустая строка стирает значение."""

    imap_host: str = Field(default="", max_length=255)
    imap_port: str = Field(default="", max_length=5)
    smtp_host: str = Field(default="", max_length=255)
    smtp_port: str = Field(default="", max_length=5)
    user: str = Field(default="", max_length=320)
    sender: str = Field(default="", max_length=320)
    use_ssl: bool = True
    # Пустой пароль не стирает сохранённый: иначе любое сохранение формы,
    # где поле пароля не заполняли, обнуляло бы его.
    password: Optional[str] = Field(default=None, max_length=512)


# Кэш последнего разбора ящика. Открытие страницы дёргает список запросов
# автоматически, и без кэша каждый заход шёл бы в IMAP по полминуты.
_THREADS_CACHE: Dict[str, Any] = {"at": None, "threads": [], "scanned": 0}
THREADS_TTL_SECONDS = 60


def _threads_cached(config, scan: int, refresh: bool):
    now = datetime.now(timezone.utc)
    cached_at = _THREADS_CACHE["at"]
    fresh = (
        cached_at is not None
        and (now - cached_at).total_seconds() < THREADS_TTL_SECONDS
    )
    if fresh and not refresh:
        return (
            [dict(item) for item in _THREADS_CACHE["threads"]],
            cached_at.isoformat(timespec="seconds"),
            _THREADS_CACHE["scanned"],
        )
    headers = mailbox.fetch_headers(config, scan=scan)
    threads = mailbox.build_threads(headers)
    _THREADS_CACHE.update({"at": now, "threads": threads, "scanned": len(headers)})
    return (
        [dict(item) for item in threads],
        now.isoformat(timespec="seconds"),
        len(headers),
    )


def setup_router() -> APIRouter:
    router = APIRouter(tags=["setup"])

    # ---------- Почта ----------

    @router.get("/mail/config")
    async def mail_config_route():
        """Настройки ящика без пароля: что задано и куда падают вложения."""
        return JSONResponse(content=mailbox.load_config().describe())

    @router.post("/mail/settings")
    async def mail_settings_route(settings: MailSettingsRequest):
        """Сохранить настройки ящика из интерфейса.

        Значения ложатся в файл на томе и действуют сразу, перезапускать
        контейнер не нужно. Они важнее переменных окружения, с которыми
        контейнер стартовал.
        """
        values = {
            "MAIL_IMAP_HOST": settings.imap_host.strip(),
            "MAIL_IMAP_PORT": settings.imap_port.strip(),
            "MAIL_SMTP_HOST": settings.smtp_host.strip(),
            "MAIL_SMTP_PORT": settings.smtp_port.strip(),
            "MAIL_USER": settings.user.strip(),
            "MAIL_FROM": settings.sender.strip(),
            "MAIL_USE_SSL": "1" if settings.use_ssl else "0",
        }
        if settings.password is not None and settings.password != "":
            values["MAIL_PASSWORD"] = settings.password
        for name in ("MAIL_IMAP_PORT", "MAIL_SMTP_PORT"):
            if values[name] and not values[name].isdigit():
                raise HTTPException(status_code=400, detail="Порт должен быть числом")
        try:
            saved = settings_store.save(values)
        except ValueError as err:
            raise HTTPException(status_code=400, detail=str(err)) from err
        except OSError as err:
            logger.warning("Не удалось записать настройки: %s", type(err).__name__)
            raise HTTPException(
                status_code=500, detail="Не удалось записать файл настроек"
            ) from err
        return JSONResponse(
            content={
                "saved": saved,
                "config": mailbox.load_config().describe(),
                # Чтобы перенести настройки на другую машину или закрепить их
                # в .env, который переживёт удаление тома.
                "dotenv": settings_store.dotenv_fragment(),
            }
        )

    @router.get("/setup/profile")
    async def setup_profile_get_route():
        """Реквизиты организации для подстановки в письма."""
        saved = settings_store.load()
        return JSONResponse(
            content={
                "profile": {
                    key: saved.get(key, "")
                    for key in settings_store.PROFILE_FIELDS
                },
                "placeholders": {
                    key: list(values)
                    for key, values in settings_store.PROFILE_FIELDS.items()
                },
            }
        )

    @router.post("/setup/profile")
    async def setup_profile_save_route(profile: ProfileRequest):
        """Сохранить реквизиты. Они не секретны, но и наружу не публикуются."""
        values = {
            key: (getattr(profile, key.lower(), "") or "").strip()
            for key in settings_store.PROFILE_FIELDS
        }
        try:
            settings_store.save(values)
        except ValueError as err:
            raise HTTPException(status_code=400, detail=str(err)) from err
        except OSError as err:
            logger.warning("Не удалось записать реквизиты: %s", type(err).__name__)
            raise HTTPException(
                status_code=500, detail="Не удалось записать файл настроек"
            ) from err
        saved = settings_store.load()
        return JSONResponse(
            content={
                "profile": {
                    key: saved.get(key, "") for key in settings_store.PROFILE_FIELDS
                }
            }
        )

    @router.post("/setup/reset")
    async def setup_reset_route(request: ResetRequest):
        """Общий сброс: вернуть стенд к состоянию до настройки.

        Что стирается, оператор выбирает сам. Файлы из каталога сертификатов
        удаляются только по явному согласию: там может лежать единственная
        копия сертификата организации.
        """
        cleared: Dict[str, Any] = {}

        settings_result = settings_store.clear()
        mail_state.clear()
        secret_store.clear_runtime_secrets()
        cleared["settings"] = settings_result["removed"]

        if request.clear_inbound:
            import inbound_store

            cleared["inbound_messages"] = inbound_store.count()
            inbound_store.clear()

        if request.clear_files:
            folder = certsources.cert_dir()
            removed = 0
            if folder.exists():
                for entry in folder.iterdir():
                    if entry.is_file() and entry.name != "settings.env":
                        try:
                            entry.unlink()
                            removed += 1
                        except OSError:
                            logger.info("Файл удалить не удалось: %s", entry.name)
            cleared["files"] = removed

        logger.info("Общий сброс выполнен: %s", cleared)
        return JSONResponse(
            content={
                "cleared": cleared,
                "config": mailbox.load_config().describe(),
                # Сессию оператора чистит основное приложение: маркер и выбор
                # сертификата живут в его памяти.
                "next": "Очистите сессию через /session/clear и настройте заново",
            }
        )

    @router.post("/mail/discover")
    async def mail_discover_route(request: DiscoverRequest):
        """Определить адреса серверов по домену ящика через DNS."""
        try:
            result = maildiscovery.discover(request.address)
        except ValueError as err:
            raise HTTPException(status_code=400, detail=str(err)) from err
        result["checked_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        return JSONResponse(content=result)

    @router.post("/mail/check")
    async def mail_check_route():
        """Проверить вход по IMAP и SMTP."""
        config = mailbox.load_config()
        if not config.imap_host and not config.smtp_host:
            raise HTTPException(status_code=400, detail="Почта не настроена")
        result = mailbox.check_connection(config)
        # Время проверки: без него непонятно, свежий это результат или прошлый.
        result["checked_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        result["imap_host"] = config.imap_host
        result["smtp_host"] = config.smtp_host
        return JSONResponse(content=result)

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

    @router.get("/mail/threads")
    async def mail_threads_route(
        scan: int = Query(200, ge=10, le=1000),
        limit: int = Query(10, ge=1, le=100),
        offset: int = Query(0, ge=0),
        state: str = Query("attention", pattern="^(attention|active|unread|all)$"),
        refresh: bool = Query(False),
    ):
        """Запросы в поддержку: номер, тема, статус и последнее движение.

        Читаются только заголовки, поэтому список статусов виден без открытия
        писем и без выкачивания их тел. Результат кэшируется на несколько
        десятков секунд, чтобы открытие страницы не ходило в IMAP каждый раз.
        """
        config = mailbox.load_config()
        if not config.configured:
            raise HTTPException(status_code=400, detail="Почта не настроена")
        try:
            threads, checked_at, scanned = _threads_cached(config, scan, refresh)
        except mailbox.MailError as err:
            raise HTTPException(status_code=502, detail=str(err)) from err

        threads = mail_state.annotate(threads)
        counts = {
            "all": len(threads),
            "active": sum(1 for item in threads if item["active"]),
            "unread": sum(1 for item in threads if item["unread"]),
        }
        if state == "active":
            selected = [item for item in threads if item["active"]]
        elif state == "unread":
            selected = [item for item in threads if item["unread"]]
        elif state == "attention":
            # То, на что стоит смотреть: ещё в работе или есть непрочитанное
            # движение. Закрытые и просмотренные не мешаются.
            selected = [item for item in threads if item["active"] or item["unread"]]
        else:
            selected = threads
        counts["attention"] = sum(1 for item in threads if item["active"] or item["unread"])

        return JSONResponse(
            content={
                "threads": selected[offset : offset + limit],
                "total": len(selected),
                "offset": offset,
                "limit": limit,
                "counts": counts,
                "scanned": scanned,
                "checked_at": checked_at,
            }
        )

    @router.post("/mail/threads/read")
    async def mail_threads_read_route(request: ReadRequest):
        """Отметить прочитанным. Свой учёт, флаги IMAP не трогаем."""
        config = mailbox.load_config()
        try:
            threads, _, _ = _threads_cached(config, 200, False)
        except mailbox.MailError as err:
            raise HTTPException(status_code=502, detail=str(err)) from err
        if request.tickets:
            wanted = set(request.tickets)
            chosen = [item for item in threads if item["ticket"] in wanted]
        else:
            chosen = threads
        changed = mail_state.mark_many(chosen)
        return JSONResponse(content={"marked": changed})

    @router.post("/mail/threads/unread")
    async def mail_threads_unread_route(request: ReadRequest):
        """Снять отметку прочитанного, чтобы вернуть запрос в поле зрения."""
        for ticket in request.tickets:
            mail_state.forget(ticket)
        return JSONResponse(content={"cleared": len(request.tickets)})

    @router.get("/mail/messages")
    async def mail_messages_route(
        limit: int = Query(10, ge=1, le=100),
        offset: int = Query(0, ge=0),
        only_watched: bool = Query(True),
        ticket: str = Query("", max_length=20),
    ):
        """Страница писем. По умолчанию только от ведомственных адресов."""
        config = mailbox.load_config()
        try:
            page = mailbox.fetch_messages(
                config,
                limit=limit,
                offset=offset,
                only_watched=only_watched,
                ticket=ticket,
            )
        except mailbox.MailError as err:
            raise HTTPException(status_code=502, detail=str(err)) from err
        page["watched"] = list(mailbox.WATCHED_DOMAINS)
        return JSONResponse(content=page)

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
