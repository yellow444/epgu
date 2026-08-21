"""Операторские эндпоинты мастера настройки: почта и источники сертификатов.

Подключаются к основному приложению, которое слушает только localhost.
Публичный приёмник входящих запросов этих методов не имеет.

Письма не уходят сами: отправка идёт явным вызовом ``POST /mail/send`` или
``POST /mail/reply`` с уже собранным текстом, который оператор видел.
Исключение одно и включается отдельно: автоматическое подтверждение решения
запроса, см. ``mail_worker`` и docs/context/13-mail-automation.md.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, File, Form, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel, Field

import certsources
import maildiscovery
import mail_state
import mailbox
import secret_store
import settings_store

logger = logging.getLogger(__name__)

# Предел ручной загрузки: инструкции и архивы бывают тяжёлыми, но не такими.
UPLOAD_LIMIT_BYTES = 50 * 1024 * 1024

# Служебные файлы стенда лежат в том же каталоге, что и вложения. Файл с
# таким именем принять нельзя: в settings.env лежит пароль почтового ящика.
RESERVED_NAMES = {"settings.env", "mail-state.json", "mail-auto.json"}

# Что безопасно показывать прямо в браузере. Всё остальное отдаётся как
# поток байтов и с заголовком attachment: вложение приходит от кого угодно,
# а страница в origin приложения имела бы доступ к его данным.
INLINE_TYPES = {
    "application/pdf",
    "image/png",
    "image/jpeg",
    "image/gif",
    "text/plain",
}


def _file_headers(name: str, media: str, download: bool) -> Dict[str, str]:
    """Заголовки отдачи файла: тип, поведение браузера и запрет угадывания."""
    safe = name.encode("ascii", "ignore").decode("ascii") or "file"
    inline = not download and media in INLINE_TYPES
    headers = {
        "Content-Disposition": '%s; filename="%s"' % ("inline" if inline else "attachment", safe),
        # Тип пришёл снаружи, угадывать его браузер не должен.
        "X-Content-Type-Options": "nosniff",
    }
    if not inline:
        # Файл уходит вложением и не отображается, поэтому запираем его
        # полностью. Для показываемых типов такой заголовок гасит встроенный
        # просмотрщик PDF: sandbox запрещает плагины, и вместо документа
        # получается серый прямоугольник.
        headers["Content-Security-Policy"] = "sandbox; default-src 'none'"
    return headers


class LetterRequest(BaseModel):
    to: str = Field(min_length=3, max_length=320)
    subject: str = Field(min_length=1, max_length=500)
    body: str = Field(min_length=1, max_length=100000)
    cc: str = Field(default="", max_length=320)


class ReplyRequest(BaseModel):
    """Ответ на письмо поддержки. Тему и адресата берём из самого письма."""

    uid: str = Field(min_length=1, max_length=40)
    body: str = Field(min_length=1, max_length=100000)
    quote: bool = True
    cc: str = Field(default="", max_length=320)
    # Имена файлов из каталога сертификатов: путь браузер не задаёт.
    attach: List[str] = Field(default_factory=list)


class AutoMailRequest(BaseModel):
    """Что разрешено автоматике. Отправка писем наружу - отдельно от чтения."""

    enabled: Optional[bool] = None
    collect: Optional[bool] = None
    confirm: Optional[bool] = None
    confirm_after_hours: Optional[int] = Field(default=None, ge=1, le=71)


class ImportRequest(BaseModel):
    path: str
    store: str = "uMy"
    link_container: str = ""


class ExtractRequest(BaseModel):
    """Из какого файла достать вложения. Пустой список - всё, что внутри."""

    path: str = Field(max_length=400)
    only: List[str] = Field(default_factory=list)


class ProfileRequest(BaseModel):
    """Реквизиты организации, которыми заполняются письма Оператору."""

    org_full_name: Optional[str] = Field(default=None, max_length=300)
    org_short_name: Optional[str] = Field(default=None, max_length=200)
    org_inn: Optional[str] = Field(default=None, max_length=12)
    org_ogrn: Optional[str] = Field(default=None, max_length=15)
    org_oktmo: Optional[str] = Field(default=None, max_length=11)
    org_role: Optional[str] = Field(default=None, max_length=50)
    is_mnemonic: Optional[str] = Field(default=None, max_length=100)
    contact_name: Optional[str] = Field(default=None, max_length=200)
    contact_role: Optional[str] = Field(default=None, max_length=200)
    contact_phone: Optional[str] = Field(default=None, max_length=50)
    contact_email: Optional[str] = Field(default=None, max_length=320)


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
_THREADS_CACHE: Dict[str, Any] = {"at": None, "threads": [], "scanned": 0, "scan": 0}
THREADS_TTL_SECONDS = 60


def _saved_file_names() -> set:
    """Имена файлов, которые уже лежат у нас: и документы, и ключи.

    Нужно, чтобы не тащить из письма второй раз то же самое. Ключевой
    контейнер лежит в другом каталоге, и забыть про него легко.
    """
    names = set()
    for folder in (certsources.cert_dir(), certsources.keys_dir()):
        if not folder.exists():
            continue
        for path in folder.rglob("*"):
            if path.is_file():
                names.add(path.name)
    return names


def _subject_fields(cert: Any) -> Dict[str, str]:
    """Реквизиты организации из subject сертификата.

    Разбор берём из приложения: там он уже умеет кавычки и русские названия
    полей вроде "ИНН ЮЛ". Перепечатывать эти данные руками из окна в окно
    незачем, они лежат в сертификате.
    """
    import app as application

    subject_name = application._certificate_text_attribute(cert, "SubjectName")
    try:
        parts = application.parse_string_to_json(subject_name)
    except (TypeError, ValueError):
        parts = {}
    parts = {str(key).strip().upper(): str(value).strip() for key, value in parts.items()}
    full_name = parts.get("O", "")
    person = " ".join(
        part for part in (parts.get("SN", ""), parts.get("G", "")) if part
    ).strip()
    return {
        "ORG_FULL_NAME": full_name,
        "ORG_SHORT_NAME": full_name[:200],
        "ORG_INN": parts.get("ИНН ЮЛ", "") or parts.get("ИНН", ""),
        "ORG_OGRN": parts.get("ОГРН", ""),
        "CONTACT_NAME": person,
        "CONTACT_ROLE": parts.get("T", ""),
    }


def _threads_cached(config, scan: int, refresh: bool):
    now = datetime.now(timezone.utc)
    cached_at = _THREADS_CACHE["at"]
    fresh = (
        cached_at is not None
        and (now - cached_at).total_seconds() < THREADS_TTL_SECONDS
        # Окно просмотра часть ключа: иначе оператор двигает scan и минуту
        # не видит разницы.
        and _THREADS_CACHE.get("scan") == scan
    )
    if fresh and not refresh:
        return (
            [dict(item) for item in _THREADS_CACHE["threads"]],
            cached_at.isoformat(timespec="seconds"),
            _THREADS_CACHE["scanned"],
        )
    headers = mailbox.fetch_headers(config, scan=scan)
    threads = mailbox.build_threads(headers)
    _THREADS_CACHE.update(
        {"at": now, "threads": threads, "scanned": len(headers), "scan": scan}
    )
    return (
        [dict(item) for item in threads],
        now.isoformat(timespec="seconds"),
        len(headers),
    )


def setup_router() -> APIRouter:
    router = APIRouter(tags=["setup"])

    # ---------- Почта ----------

    @router.post("/setup/profile/from-certificate")
    def setup_profile_from_certificate_route():
        """Заполнить реквизиты из выбранного сертификата.

        В сертификате организации уже лежит всё, что мы просим вводить руками:
        наименование, ИНН, ОГРН и ФИО владельца. Перепечатывать это из окна в
        окно бессмысленно.
        """
        import app as application

        cert_id = getattr(application, "CURRENT_CERT_ID", "") or ""
        certificates = getattr(application, "CERTIFICATES", {})
        cert = certificates.get(cert_id) or next(iter(certificates.values()), None)
        if cert is None:
            raise HTTPException(
                status_code=404,
                detail="Сертификатов нет: выберите сертификат на шаге Сертификат",
            )
        fields = _subject_fields(cert)
        values = {key: value for key, value in fields.items() if value}
        if values:
            try:
                settings_store.save(values)
            except (ValueError, OSError) as err:
                raise HTTPException(status_code=500, detail=str(err)) from err
        saved = settings_store.load()
        return JSONResponse(
            content={
                "filled": sorted(values),
                "profile": {
                    key: saved.get(key, "") for key in settings_store.PROFILE_FIELDS
                },
            }
        )

    @router.get("/mail/config")
    def mail_config_route():
        """Настройки ящика без пароля: что задано и куда падают вложения."""
        return JSONResponse(content=mailbox.load_config().describe())

    @router.post("/mail/settings")
    def mail_settings_route(settings: MailSettingsRequest):
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
    def setup_profile_get_route():
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
    def setup_profile_save_route(profile: ProfileRequest):
        """Сохранить реквизиты. Они не секретны, но и наружу не публикуются.

        Присланное поле перезаписывается, непереданное остаётся как было:
        окно ответа сохраняет два поля из одиннадцати, и обнулять остальные
        оно не должно.
        """
        values = {}
        for key in settings_store.PROFILE_FIELDS:
            value = getattr(profile, key.lower(), None)
            if value is None:
                continue
            values[key] = value.strip()
        if not values:
            saved = settings_store.load()
            return JSONResponse(
                content={
                    "profile": {
                        key: saved.get(key, "") for key in settings_store.PROFILE_FIELDS
                    }
                }
            )
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
    def setup_reset_route(request: ResetRequest):
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

        # Госпочта: заявки, уведомления, скачанные вложения и счётчик суточных
        # попыток. Счётчик стирается вместе с остальным намеренно: сброс делают
        # на чистом стенде, а не для того, чтобы обойти лимит ЕПГУ, который
        # всё равно считается на его стороне.
        import geps_quota
        import geps_store

        cleared["geps_messages"] = geps_store.counts()["messages"]
        geps_store.clear()
        geps_quota.clear()

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
    def mail_discover_route(request: DiscoverRequest):
        """Определить адреса серверов по домену ящика через DNS."""
        try:
            result = maildiscovery.discover(request.address)
        except ValueError as err:
            raise HTTPException(status_code=400, detail=str(err)) from err
        result["checked_at"] = datetime.now(timezone.utc).isoformat(timespec="seconds")
        return JSONResponse(content=result)

    @router.post("/mail/check")
    def mail_check_route():
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
    def mail_send_route(letter: LetterRequest):
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

    @router.get("/mail/messages/{uid}")
    def mail_message_route(uid: str):
        """Одно письмо целиком: текст, вложения, статус запроса.

        Нужно, чтобы прочитать письмо, из-за которого запрос ждёт ответа, не
        разыскивая его в переписке.
        """
        config = mailbox.load_config()
        try:
            message = mailbox.fetch_message(config, uid=uid)
        except mailbox.MailError as err:
            raise HTTPException(status_code=502, detail=str(err)) from err
        return JSONResponse(content=message)

    @router.get("/mail/messages/{uid}/reply")
    def mail_reply_draft_route(uid: str):
        """Заготовка ответа на письмо: кому, тема, цитата.

        Ничего не отправляет. Нужна и для ответа отсюда, и для того, чтобы
        унести текст в свой почтовый клиент.
        """
        config = mailbox.load_config()
        try:
            original = mailbox.fetch_message(config, uid=uid)
        except mailbox.MailError as err:
            raise HTTPException(status_code=502, detail=str(err)) from err
        return JSONResponse(
            content={
                "to": original["reply_to"],
                # Робот пишет с noreply, а ответ ждёт на адресе поддержки.
                # Интерфейс должен показать подмену, а не молчать про неё.
                "to_replaced": original.get("reply_to_replaced", False),
                "from_address": original.get("from", ""),
                "subject": mailbox.reply_subject(original["subject"]),
                "quote": mailbox.quote_original(original),
                "ticket": original.get("ticket", ""),
                "received_at": original.get("received_at", ""),
                "from": original.get("from", ""),
                "message_id": original.get("message_id", ""),
                "references": original.get("references", ""),
                "files": sorted(
                    path.name
                    for path in certsources.cert_dir().glob("*")
                    if path.is_file()
                ),
            }
        )

    @router.post("/mail/reply")
    def mail_reply_route(reply: ReplyRequest):
        """Ответить в переписку. Только по явному действию оператора.

        Адрес, тема и Message-Id берутся из письма на сервере: браузер их не
        подсказывает, иначе ответ можно было бы увести чужому адресату.
        """
        config = mailbox.load_config()
        try:
            original = mailbox.fetch_message(config, uid=reply.uid)
            body = reply.body
            if reply.quote:
                body = body.rstrip() + "\n\n" + mailbox.quote_original(original)
            attach = []
            for name in reply.attach:
                candidate = (certsources.cert_dir() / Path(name).name).resolve()
                if candidate.is_file() and certsources.cert_dir().resolve() in candidate.parents:
                    attach.append(candidate)
                else:
                    raise HTTPException(status_code=400, detail="Файл %s не найден" % name)
            result = mailbox.send_letter(
                config,
                to=original["reply_to"],
                subject=mailbox.reply_subject(original["subject"]),
                body=body,
                cc=reply.cc,
                in_reply_to=original.get("message_id", ""),
                references=original.get("references", ""),
                attach=attach,
            )
        except mailbox.MailError as err:
            raise HTTPException(status_code=502, detail=str(err)) from err
        ticket = original.get("ticket", "")
        if ticket:
            # Ответили - значит запрос больше не ждёт нас.
            mail_state.mark_read(ticket, original.get("received_at", ""))
        # Список запросов кэшируется на минуту, и без сброса оператор ещё
        # минуту видел бы "нужен ответ от нас" по запросу, на который ответил.
        _THREADS_CACHE["at"] = None
        result["ticket"] = ticket
        result["in_reply_to"] = original.get("message_id", "")
        result["attached"] = [path.name for path in attach]
        logger.info("Ответ отправлен по запросу %s", ticket or "без номера")
        return JSONResponse(content=result)

    @router.get("/mail/auto")
    def mail_auto_state_route():
        """Что настроено у автоматики и что она успела сделать."""
        import mail_worker

        return JSONResponse(content=mail_worker.describe())

    @router.post("/mail/auto")
    def mail_auto_save_route(request: AutoMailRequest):
        """Разрешить или запретить автоматическую обработку почты.

        Подтверждение решения отправляет письмо наружу от имени организации,
        поэтому включается отдельно от всего остального и пишется в лог.
        """
        import mail_worker

        # Пишем только то, что прислали: переключатель в интерфейсе может
        # менять один флаг, и это не повод сбрасывать остальные.
        values = {}
        if request.enabled is not None:
            values["MAIL_AUTO_ENABLED"] = "1" if request.enabled else "0"
        if request.collect is not None:
            values["MAIL_AUTO_COLLECT"] = "1" if request.collect else "0"
        if request.confirm is not None:
            values["MAIL_AUTO_CONFIRM"] = "1" if request.confirm else "0"
        if request.confirm_after_hours is not None:
            values["MAIL_AUTO_CONFIRM_AFTER"] = str(request.confirm_after_hours)
        if not values:
            return JSONResponse(content=mail_worker.describe())
        try:
            settings_store.save(values)
        except (ValueError, OSError) as err:
            raise HTTPException(status_code=400, detail=str(err)) from err
        if request.enabled and request.confirm:
            logger.warning(
                "Оператор разрешил автоматические подтверждения решений через %d ч",
                request.confirm_after_hours,
            )
        return JSONResponse(content=mail_worker.describe())

    @router.get("/mail/deadlines")
    def mail_deadlines_route():
        """Запросы, которые ждут подтверждения, и сколько времени осталось."""
        import mail_worker

        config = mailbox.load_config()
        if not config.configured:
            return JSONResponse(content={"configured": False, "waiting": []})
        try:
            threads, _, _ = _threads_cached(config, 200, False)
        except mailbox.MailError as err:
            raise HTTPException(status_code=502, detail=str(err)) from err
        return JSONResponse(
            content={"configured": True, "waiting": mail_worker.deadlines(threads)}
        )

    @router.get("/mail/threads")
    def mail_threads_route(
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
    def mail_threads_read_route(request: ReadRequest):
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
    def mail_threads_unread_route(request: ReadRequest):
        """Снять отметку прочитанного, чтобы вернуть запрос в поле зрения."""
        for ticket in request.tickets:
            mail_state.forget(ticket)
        return JSONResponse(content={"cleared": len(request.tickets)})

    @router.get("/mail/messages")
    def mail_messages_route(
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

    @router.get("/mail/attachments")
    def mail_attachments_route(letters: int = Query(20, ge=1, le=50)):
        """Вложения последних писем одним списком, с пометкой уже сохранённых."""
        config = mailbox.load_config()
        if not config.configured:
            return JSONResponse(content={"configured": False, "attachments": []})
        import attachments

        try:
            items = mailbox.list_attachments(config, letters=letters)
        except mailbox.MailError as err:
            raise HTTPException(status_code=502, detail=str(err)) from err
        saved_names = _saved_file_names()
        for item in items:
            item["kind"] = attachments.guess_kind(item["name"])
            item["saved"] = item["name"] in saved_names
        return JSONResponse(content={"configured": True, "attachments": items})

    @router.post("/mail/messages/{uid}/attachments/{index}/save")
    def mail_save_attachment_route(
        uid: str,
        index: int,
        target: str = Query("certs", pattern="^(certs|keys)$"),
    ):
        """Сохранить вложение на диск. Установка - отдельное действие.

        Ключевой контейнер кладём в каталог ключей: в папке с документами
        КриптоПро его не увидит.
        """
        config = mailbox.load_config()
        folder = certsources.keys_dir() if target == "keys" else None
        try:
            result = mailbox.save_attachment(config, uid=uid, index=index, target_dir=folder)
        except mailbox.MailError as err:
            raise HTTPException(status_code=502, detail=str(err)) from err
        result["target"] = target
        return JSONResponse(content=result)

    @router.get("/mail/messages/{uid}/attachments/{index}/preview")
    def mail_attachment_preview_route(uid: str, index: int):
        """Что внутри вложения: текст, ссылки, вложенные файлы, подсказки.

        Файл на диск не ложится: он разбирается во временном каталоге и
        оттуда исчезает. Смотреть до сохранения - нормальное желание.
        """
        import tempfile

        import attachments

        config = mailbox.load_config()
        try:
            found = mailbox.read_attachment(config, uid=uid, index=index)
        except mailbox.MailError as err:
            raise HTTPException(status_code=502, detail=str(err)) from err
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / found["name"]
            path.write_bytes(found["data"])
            described = attachments.describe(path)
        described.pop("path", None)
        described["content_type"] = found["content_type"]
        described["uid"] = uid
        described["index"] = index
        return JSONResponse(content=described)

    @router.get("/mail/messages/{uid}/attachments/{index}/raw")
    def mail_attachment_raw_route(uid: str, index: int, download: bool = False):
        """Само вложение байтами, для показа в интерфейсе.

        Отдаём с ``inline``: PDF открывается прямо на странице, а не падает
        в загрузки браузера непонятно куда.
        """
        from fastapi.responses import Response

        config = mailbox.load_config()
        try:
            found = mailbox.read_attachment(config, uid=uid, index=index)
        except mailbox.MailError as err:
            raise HTTPException(status_code=502, detail=str(err)) from err
        media = found["content_type"] or "application/octet-stream"
        headers = _file_headers(found["name"], media, download)
        if media not in INLINE_TYPES:
            # Тип пришёл из письма. Показывать в браузере чужой HTML или SVG
            # в origin приложения нельзя: страница получила бы его данные.
            media = "application/octet-stream"
        return Response(content=found["data"], media_type=media, headers=headers)

    @router.post("/mail/attachments/collect")
    def mail_collect_attachments_route(letters: int = Query(20, ge=1, le=50)):
        """Забрать из писем сертификаты, ключи, архивы и документы.

        Одна кнопка вместо обхода писем руками. Инструкции в PDF и документы
        Word забираем тоже: ключевой контейнер и ссылку на УЦ присылают внутри
        них, а разбор такого файла у нас уже есть. Ставить ничего не ставим:
        файлы просто оказываются в нужных каталогах, дальше решает оператор.
        """
        import attachments

        config = mailbox.load_config()
        if not config.configured:
            raise HTTPException(status_code=409, detail="Почта не настроена")
        try:
            items = mailbox.list_attachments(config, letters=letters)
        except mailbox.MailError as err:
            raise HTTPException(status_code=502, detail=str(err)) from err

        saved: List[Dict[str, Any]] = []
        skipped: List[str] = []
        existing = _saved_file_names()
        for item in items:
            kind = attachments.guess_kind(item["name"])
            if kind == "unknown":
                skipped.append("%s: непонятный файл, заберите вручную" % item["name"])
                continue
            if item.get("too_large"):
                skipped.append("%s: вложение слишком большое" % item["name"])
                continue
            if item["name"] in existing:
                skipped.append("%s: уже сохранено" % item["name"])
                continue
            folder = certsources.keys_dir() if kind == "key" else None
            try:
                result = mailbox.save_attachment(
                    config, uid=item["uid"], index=item["index"], target_dir=folder
                )
            except mailbox.MailError as err:
                skipped.append("%s: %s" % (item["name"], err))
                continue
            result["kind"] = kind
            result["ticket"] = item.get("ticket", "")
            saved.append(result)
            existing.add(result["name"])
        logger.info("Из писем забрано файлов: %d, пропущено: %d", len(saved), len(skipped))
        return JSONResponse(content={"saved": saved, "skipped": skipped})

    # ---------- Источники сертификатов ----------

    @router.get("/certsources")
    def certsources_route():
        """Папка с сертификатами, что видит КриптоПро и гайд по токену."""
        return JSONResponse(
            content={
                "folder": certsources.scan_folder(),
                "readers": certsources.readers_status(),
                "usb_guide": certsources.usb_guide(),
                "cryptopro": certsources.cryptopro_available(),
                # Копии ключей, сделанные перед удалением сертификатов.
                "key_backups": certsources.list_key_backups(),
            }
        )

    @router.post("/certsources/upload")
    def certsources_upload_route(
        files: List[UploadFile] = File(...),
        target: str = Form("certs"),
    ):
        """Положить файлы руками: инструкцию, сертификат, архив, контейнер.

        Почта нужна не всем и не всегда настроена. Тот же файл можно принести
        руками, и дальше он проходит ровно тот же путь: разбор, извлечение
        вложений, установка сертификата.

        ``target`` выбирает, куда класть: ``certs`` в каталог вложений,
        ``keys`` в каталог ключевых контейнеров. Файлы ключа кладут отдельно:
        КриптоПро ищет их в своём каталоге, а не среди документов.
        """
        import attachments

        if target not in {"certs", "keys"}:
            raise HTTPException(status_code=400, detail="target: certs или keys")
        folder = certsources.cert_dir() if target == "certs" else certsources.keys_dir()
        try:
            folder.mkdir(parents=True, exist_ok=True)
        except OSError as err:
            raise HTTPException(status_code=500, detail="Каталог недоступен для записи") from err

        saved: List[Dict[str, Any]] = []
        for upload in files:
            name = attachments._safe_name(upload.filename or "")
            if not name:
                raise HTTPException(status_code=400, detail="Некорректное имя файла")
            payload = upload.file.read()
            if len(payload) > UPLOAD_LIMIT_BYTES:
                raise HTTPException(
                    status_code=413,
                    detail="Файл %s больше %d МБ" % (name, UPLOAD_LIMIT_BYTES // 1024 // 1024),
                )
            if name.lower() in RESERVED_NAMES:
                raise HTTPException(
                    status_code=400,
                    detail="Имя %s занято служебным файлом стенда" % name,
                )
            destination = folder / name
            # Имя пришло снаружи: чужая загрузка не должна затирать уже
            # лежащий файл, как это сделано и при сохранении из письма.
            counter = 1
            while destination.exists():
                destination = folder / ("%s-%d%s" % (Path(name).stem, counter, Path(name).suffix))
                counter += 1
            try:
                destination.write_bytes(payload)
            except OSError as err:
                raise HTTPException(status_code=500, detail="Не удалось записать файл") from err
            logger.info("Загружен файл вручную: %s, %d байт", name, len(payload))
            saved.append(attachments.describe(destination))
        return JSONResponse(content={"saved": saved, "target": target, "folder": str(folder)})

    @router.get("/certsources/inspect")
    def certsources_inspect_route(path: str = Query(..., max_length=400)):
        """Разобрать сохранённое вложение: текст, ссылки, вложенные файлы.

        Читать инструкции глазами и распаковывать архивы руками означает
        потерять смысл автоматизации, поэтому разбор делает сам стенд.
        """
        import attachments

        folder = certsources.cert_dir().resolve()
        candidate = Path(path).resolve()
        # Путь приходит из UI, проверяем его как чужой.
        if folder not in candidate.parents:
            raise HTTPException(
                status_code=400,
                detail="Разбирать можно только файлы из каталога вложений",
            )
        result = attachments.describe(candidate)
        if not result.get("exists"):
            raise HTTPException(status_code=404, detail="Файл не найден")
        return JSONResponse(content=result)

    @router.post("/certsources/extract")
    def certsources_extract_route(request: ExtractRequest):
        """Достать вложенные файлы из архива или документа на диск."""
        import attachments

        folder = certsources.cert_dir().resolve()
        candidate = Path(request.path).resolve()
        if folder not in candidate.parents:
            raise HTTPException(
                status_code=400,
                detail="Извлекать можно только из файлов каталога вложений",
            )
        if not candidate.is_file():
            raise HTTPException(status_code=404, detail="Файл не найден")
        result = attachments.extract(
            candidate,
            folder,
            only=request.only or None,
            keys_dir=certsources.keys_dir(),
        )
        if not result["extracted"] and result["skipped"]:
            raise HTTPException(status_code=400, detail="; ".join(result["skipped"])[:300])
        return JSONResponse(content=result)

    @router.get("/certsources/file")
    def certsources_file_route(path: str, download: bool = False):
        """Отдать файл из каталога вложений.

        По умолчанию ``inline``: PDF открывается прямо в интерфейсе. С
        ``download=1`` браузер честно сохраняет файл себе, и это разные вещи,
        которые до сих пор путались в одной кнопке.
        """
        import mimetypes

        folder = certsources.cert_dir().resolve()
        candidate = Path(path).resolve()
        if folder not in candidate.parents or not candidate.is_file():
            raise HTTPException(status_code=400, detail="Файл вне каталога вложений")
        media = mimetypes.guess_type(candidate.name)[0] or "application/octet-stream"
        headers = _file_headers(candidate.name, media, download)
        if media not in INLINE_TYPES:
            media = "application/octet-stream"
        return FileResponse(candidate, media_type=media, headers=headers)

    @router.post("/certsources/import")
    def certsources_import_route(request: ImportRequest):
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
