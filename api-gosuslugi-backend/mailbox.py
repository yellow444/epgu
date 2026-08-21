"""Почтовый ящик оператора: отправка писем в поддержку и разбор ответов.

Переписка с УЦ и с поддержкой ЕПГУ идёт письмами: заявка на тестовый
сертификат, полномочие API-Key, настройка параметров ИС. Ответ приходит
вложением, и до сих пор оператор перекладывал его руками.

Модуль намеренно на стандартной библиотеке (imaplib, smtplib, email): лишняя
зависимость ради IMAP тут не нужна.

Что модуль не делает:

- не отправляет письма сам. Отправка происходит только по явному вызову с уже
  собранным письмом. Единственное исключение живёт в ``mail_worker``: он умеет
  подтверждать решение запроса, если оператор отдельно это разрешил, и только
  на ведомственный адрес поддержки;
- не устанавливает вложения. Он их только сохраняет в каталог, установка -
  отдельное действие оператора;
- не пишет пароль ни в лог, ни в ответ API.
"""

from __future__ import annotations

import email
import imaplib
import logging
import os
import re
import smtplib
import socket
import ssl
from dataclasses import dataclass, field
from email.header import decode_header, make_header
from email.message import EmailMessage
from email.utils import (
    formataddr,
    formatdate,
    getaddresses,
    make_msgid,
    parseaddr,
    parsedate_to_datetime,
)
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import secret_store
import settings_store

logger = logging.getLogger(__name__)

# Адреса, ответы с которых интересны: поддержка ЕПГУ, УЦ, техпортал.
WATCHED_DOMAINS = ("gov.ru", "sc.digital.gov.ru", "digital.gov.ru", "gosuslugi.ru")

# Куда отвечать, если письмо пришло с адреса noreply. Это адрес первой линии
# ФГИС СЦ, он же стоит в шаблонах писем.
SUPPORT_ADDRESS = "sd@sc.digital.gov.ru"

# Имя файла из вложения приходит от внешнего отправителя, поэтому берётся
# только базовое имя и только безопасные символы.
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")

# Таблица для имён вложений. Ставится до чистки, поэтому русское имя файла
# остаётся читаемым: "Инструкция.pdf" превращается в "Instrukciya.pdf".
TRANSLIT = {
    "а": "a", "б": "b", "в": "v", "г": "g", "д": "d", "е": "e", "ё": "e",
    "ж": "zh", "з": "z", "и": "i", "й": "y", "к": "k", "л": "l", "м": "m",
    "н": "n", "о": "o", "п": "p", "р": "r", "с": "s", "т": "t", "у": "u",
    "ф": "f", "х": "h", "ц": "c", "ч": "ch", "ш": "sh", "щ": "sch",
    "ъ": "", "ы": "y", "ь": "", "э": "e", "ю": "yu", "я": "ya",
    "А": "A", "Б": "B", "В": "V", "Г": "G", "Д": "D", "Е": "E", "Ё": "E",
    "Ж": "Zh", "З": "Z", "И": "I", "Й": "Y", "К": "K", "Л": "L", "М": "M",
    "Н": "N", "О": "O", "П": "P", "Р": "R", "С": "S", "Т": "T", "У": "U",
    "Ф": "F", "Х": "H", "Ц": "C", "Ч": "Ch", "Ш": "Sh", "Щ": "Sch",
    "Ъ": "", "Ы": "Y", "Ь": "", "Э": "E", "Ю": "Yu", "Я": "Ya",
}

MAX_ATTACHMENT_BYTES = int(os.getenv("MAIL_MAX_ATTACHMENT", str(20 * 1024 * 1024)))


CONNECT_TIMEOUT = int(os.getenv("MAIL_TIMEOUT", "20"))


class MailError(RuntimeError):
    """Ошибка работы с почтой без раскрытия учётных данных."""


def describe_network_error(exc: Exception, host: str, port: int) -> str:
    """Человеческая причина отказа.

    Общее "не удалось подключиться" бесполезно: чаще всего виноват неверный
    адрес сервера, и это видно по типу ошибки. Учётные данные в текст не
    попадают, только имя хоста и порт.
    """
    if isinstance(exc, socket.gaierror):
        return (
            f"Имя {host} не разрешается. Проверьте адрес сервера: у хостингов "
            "он обычно отличается от домена почты."
        )
    if isinstance(exc, ConnectionRefusedError):
        return f"{host} отклонил соединение на порту {port}. Проверьте порт."
    if isinstance(exc, (socket.timeout, TimeoutError)):
        return (
            f"{host} не ответил за {CONNECT_TIMEOUT} с на порту {port}. "
            "Порт закрыт или сервер недоступен."
        )
    if isinstance(exc, ssl.SSLError):
        return (
            f"Ошибка TLS при подключении к {host}:{port}. Проверьте порт и "
            "переключатель шифрования: обычно 993 и 465 идут с SSL."
        )
    return f"Сеть недоступна при подключении к {host}:{port} ({type(exc).__name__})."


@dataclass
class MailConfig:
    imap_host: str = ""
    imap_port: int = 993
    smtp_host: str = ""
    smtp_port: int = 465
    user: str = ""
    sender: str = ""
    use_ssl: bool = True
    inbox_dir: Path = field(default_factory=lambda: Path("/var/lib/epgu-mail"))

    @property
    def configured(self) -> bool:
        return bool(self.imap_host and self.user and secret_store.get_secret("MAIL_PASSWORD"))

    def describe(self) -> Dict[str, Any]:
        """Описание для UI. Пароль сюда не попадает никогда."""
        return {
            "configured": self.configured,
            "imap": {"host": self.imap_host, "port": self.imap_port},
            "smtp": {"host": self.smtp_host, "port": self.smtp_port},
            "user": self.user,
            "sender": self.sender or self.user,
            "use_ssl": self.use_ssl,
            "inbox_dir": str(self.inbox_dir),
            "password": secret_store.describe("MAIL_PASSWORD"),
            "watched": list(WATCHED_DOMAINS),
        }


def _port(name: str, default: int) -> int:
    raw = settings_store.get(name, str(default)).strip()
    try:
        return int(raw)
    except ValueError:
        logger.info("Некорректный порт в %s, беру значение по умолчанию", name)
        return default


def load_config() -> MailConfig:
    """Настройки ящика: сохранённое из интерфейса важнее окружения."""
    return MailConfig(
        imap_host=settings_store.get("MAIL_IMAP_HOST", "").strip(),
        imap_port=_port("MAIL_IMAP_PORT", 993),
        smtp_host=settings_store.get("MAIL_SMTP_HOST", "").strip(),
        smtp_port=_port("MAIL_SMTP_PORT", 465),
        user=settings_store.get("MAIL_USER", "").strip(),
        sender=settings_store.get("MAIL_FROM", "").strip(),
        use_ssl=settings_store.get("MAIL_USE_SSL", "1").strip().lower()
        not in {"0", "false", "no"},
        inbox_dir=Path(os.getenv("MAIL_INBOX_DIR", "/var/lib/epgu-mail")),
    )


# Поддержка ЕПГУ ведёт переписку тикетами: номер SCR#NNNNNNN стоит в теме
# каждого письма, а сам статус написан там же словами. Это единственное, чем
# письма связываются в один запрос, поэтому разбираем тему.
TICKET = re.compile(r"SCR#(\d+)", re.IGNORECASE)

# Порядок важен: первое совпадение выигрывает, поэтому более частные формулировки
# стоят выше общих.
STATUS_RULES = (
    (re.compile(r"требуется дополнительная информация", re.I), "Нужен ответ от нас", "action"),
    (re.compile(r"добавлен файл", re.I), "Добавлен файл", "file"),
    (re.compile(r"добавлен комментарий", re.I), "Добавлен комментарий", "comment"),
    (re.compile(r"закрыт", re.I), "Закрыт", "done"),
    (re.compile(r"выполнен", re.I), "Выполнен", "done"),
    (re.compile(r"статус работ.*[«\"]([^»\"]+)[»\"]", re.I), None, "progress"),
    (re.compile(r"присвоен номер", re.I), "Принят в работу", "progress"),
    (re.compile(r"зарегистрирован", re.I), "Зарегистрирован", "new"),
)

# События, которые не меняют статус запроса, а только сообщают о движении.
EVENT_KINDS = {"comment", "file"}


def parse_ticket(subject: str) -> str:
    match = TICKET.search(subject or "")
    return match.group(1) if match else ""


def parse_status(subject: str) -> Tuple[str, str]:
    """Статус и его вид по теме письма."""
    for pattern, label, kind in STATUS_RULES:
        match = pattern.search(subject or "")
        if not match:
            continue
        if label is None:
            # Статус написан в кавычках внутри темы, берём его как есть.
            return match.group(1).strip(), kind
        return label, kind
    return "", ""


def parse_topic(subject: str) -> str:
    """Тема запроса без служебной обвязки про номер и статус."""
    text = subject or ""
    for marker in ("Тема запроса:", "Тема :", "Тема:"):
        if marker in text:
            return text.split(marker, 1)[1].strip()
    return TICKET.sub("", text).strip(" .:")


def _decode(value: Optional[str]) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def translit(value: str) -> str:
    """Кириллица латиницей. Имя должно остаться узнаваемым.

    Вложения от УЦ и поддержки почти всегда названы по-русски, а вычищать
    кириллицу подчёркиваниями значит превращать "Инструкция.pdf" в мусор.
    """
    return "".join(TRANSLIT.get(letter, TRANSLIT.get(letter.lower(), letter)) for letter in value)


def safe_attachment_name(raw: Optional[str], index: int) -> str:
    """Безопасное имя файла с сохранением расширения.

    Расширение отделяется до чистки: по нему определяется тип файла, и
    потерять его значит потерять и сертификат, и инструкцию среди файлов
    без имени.
    """
    source = Path(_decode(raw) or "").name
    suffix = Path(source).suffix.lower()[:10]
    suffix = _SAFE_NAME.sub("", suffix)
    stem = translit(Path(source).stem)
    stem = _SAFE_NAME.sub("_", stem).strip("._")
    if not stem:
        stem = f"attachment-{index}"
    return (stem[:100] + suffix)[:120]


def _uid_from_prefix(prefix: bytes) -> str:
    """Достать UID из префикса ответа FETCH.

    Ответ выглядит как ``12 (UID 3456 BODY[...] {size}``: первое число это
    порядковый номер письма в сессии, и он меняется, стоит кому-то удалить
    письмо из ящика. Настоящий UID стоит после слова UID, его и берём.
    """
    text = prefix.decode("ascii", "replace")
    match = re.search(r"UID\s+(\d+)", text, re.IGNORECASE)
    if match:
        return match.group(1)
    # Старый сервер мог не вернуть UID: тогда номер сессии лучше, чем ничего.
    return text.split()[0] if text.split() else ""


def _is_watched(address: str) -> bool:
    address = address.lower()
    return any(domain in address for domain in WATCHED_DOMAINS)


def is_watched(address: str) -> bool:
    """Ведомственный ли адрес. Публичное имя для проверок снаружи модуля."""
    return _is_watched(address or "")


def address_only(value: str) -> str:
    """Голый адрес из строки вида "Имя <box@example.org>"."""
    match = re.search(r"<([^>]+)>", str(value or ""))
    return (match.group(1) if match else str(value or "")).strip().lower()


def attachment_kind(name: str) -> str:
    """Вид вложения по имени файла: сертификат, ключ, архив, документ."""
    import attachments

    return attachments.guess_kind(name)


def _is_noreply(address: str) -> bool:
    lowered = (address or "").lower()
    return any(marker in lowered for marker in ("noreply", "no-reply", "donotreply"))


def reply_address(reply_to: Optional[str], sender: str) -> str:
    """Куда на самом деле уйдёт ответ.

    Робот ФГИС СЦ пишет с адреса noreply, а ответ ждёт на адрес поддержки.
    Отправить ответ в noreply значит пропустить срок, думая, что ответил.
    """
    explicit = _decode(reply_to)
    if explicit:
        return explicit
    if _is_noreply(sender):
        return SUPPORT_ADDRESS
    return sender


def _imap_connect(config: MailConfig) -> imaplib.IMAP4:
    if not config.imap_host:
        raise MailError("IMAP-сервер не задан")
    password = secret_store.get_secret("MAIL_PASSWORD")
    if not password:
        raise MailError("Пароль почтового ящика не задан")
    try:
        if config.use_ssl:
            client: imaplib.IMAP4 = imaplib.IMAP4_SSL(
                config.imap_host,
                config.imap_port,
                ssl_context=ssl.create_default_context(),
                timeout=CONNECT_TIMEOUT,
            )
        else:
            client = imaplib.IMAP4(
                config.imap_host, config.imap_port, timeout=CONNECT_TIMEOUT
            )
            client.starttls(ssl_context=ssl.create_default_context())
        client.login(config.user, password)
        return client
    except imaplib.IMAP4.error as err:
        # Текст ошибки IMAP может содержать логин, наружу его не отдаём.
        logger.warning("IMAP login failed: %s", type(err).__name__)
        raise MailError(
            "IMAP отклонил вход. Проверьте логин и пароль приложения, а также "
            "что доступ по IMAP включён в настройках ящика."
        ) from err
    except OSError as err:
        logger.warning("IMAP connection failed: %s", type(err).__name__)
        raise MailError(
            describe_network_error(err, config.imap_host, config.imap_port)
        ) from err


def check_connection(config: MailConfig) -> Dict[str, Any]:
    """Проверить вход по IMAP и SMTP. Возвращает результат по каждому."""
    result: Dict[str, Any] = {"imap": {"ok": False}, "smtp": {"ok": False}}
    try:
        client = _imap_connect(config)
        try:
            status, _ = client.select("INBOX", readonly=True)
            result["imap"] = {"ok": status == "OK", "detail": "Вход выполнен, INBOX открыт"}
        finally:
            try:
                client.logout()
            except Exception:
                pass
    except MailError as err:
        result["imap"] = {"ok": False, "detail": str(err)}

    if not config.smtp_host:
        result["smtp"] = {"ok": False, "detail": "SMTP-сервер не задан"}
        return result
    password = secret_store.get_secret("MAIL_PASSWORD")
    try:
        with _smtp_connect(config, password) as server:
            server.noop()
        result["smtp"] = {"ok": True, "detail": "Вход выполнен"}
    except MailError as err:
        result["smtp"] = {"ok": False, "detail": str(err)}
    return result


def _smtp_connect(config: MailConfig, password: str) -> smtplib.SMTP:
    context = ssl.create_default_context()
    try:
        if config.use_ssl and config.smtp_port == 465:
            server: smtplib.SMTP = smtplib.SMTP_SSL(
                config.smtp_host, config.smtp_port, context=context, timeout=CONNECT_TIMEOUT
            )
        else:
            server = smtplib.SMTP(
                config.smtp_host, config.smtp_port, timeout=CONNECT_TIMEOUT
            )
            server.starttls(context=context)
        if password:
            server.login(config.user, password)
        return server
    except smtplib.SMTPAuthenticationError as err:
        logger.warning("SMTP auth failed: %s", type(err).__name__)
        raise MailError(
            "SMTP отклонил вход. Проверьте логин и пароль приложения."
        ) from err
    except OSError as err:
        logger.warning("SMTP connection failed: %s", type(err).__name__)
        raise MailError(
            describe_network_error(err, config.smtp_host, config.smtp_port)
        ) from err
    except smtplib.SMTPException as err:
        logger.warning("SMTP protocol failure: %s", type(err).__name__)
        raise MailError(
            f"SMTP-сервер {config.smtp_host} ответил ошибкой протокола "
            f"({type(err).__name__})."
        ) from err


# Адрес в конверте и в заголовке обязан быть в ASCII: SMTPUTF8 поддерживают
# не все серверы, и наш точно нет.
_ADDRESS = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


def parse_addresses(*values: str) -> List[Tuple[str, str]]:
    """Разобрать строку получателей на пары имя и адрес.

    Имя у поддержки написано кириллицей, а адрес обязан быть латиницей.
    Разбираем строку на части: имя потом кодируется по RFC 2047, а в конверт
    SMTP уходит только адрес.
    """
    pairs = []
    for name, addr in getaddresses([value or "" for value in values]):
        clean = str(addr or "").strip()
        if _ADDRESS.match(clean):
            pairs.append((str(name or "").strip(), clean))
    return pairs


def _header_addresses(value: str) -> str:
    """Адреса для заголовка письма с человекочитаемыми именами."""
    return ", ".join(formataddr(pair) for pair in parse_addresses(value))


def send_letter(
    config: MailConfig,
    *,
    to: str,
    subject: str,
    body: str,
    cc: str = "",
    in_reply_to: str = "",
    references: str = "",
    attach: Optional[List[Path]] = None,
) -> Dict[str, Any]:
    """Отправить одно письмо. Вызывается только по явному действию оператора.

    ``in_reply_to`` цепляет письмо к существующей переписке: поддержка ведёт
    тикеты по теме, но почтовые клиенты и роботы сшивают ветку по заголовкам
    In-Reply-To и References. Без них ответ может уехать в отдельный тикет.
    """
    if not config.smtp_host:
        raise MailError("SMTP-сервер не задан")
    if not to.strip():
        raise MailError("Не указан адрес получателя")
    if not parse_addresses(to):
        raise MailError("Не разобрать адрес получателя: %s" % to.strip()[:120])
    password = secret_store.get_secret("MAIL_PASSWORD")

    message = EmailMessage()
    message["From"] = config.sender or config.user
    # Имя получателя кириллицей кодируем по RFC 2047, а не отправляем как есть.
    message["To"] = _header_addresses(to)
    if cc.strip():
        message["Cc"] = _header_addresses(cc)
    message["Subject"] = subject
    # Свои Date и Message-ID: по ним на наш ответ можно сослаться потом, а
    # клиент оператора видит письмо в той же ветке.
    message["Date"] = formatdate(localtime=True)
    domain = (config.sender or config.user or "localhost").split("@")[-1] or "localhost"
    message["Message-ID"] = make_msgid(domain=domain)
    if in_reply_to.strip():
        message["In-Reply-To"] = in_reply_to.strip()
        chain = " ".join(part for part in (references.strip(), in_reply_to.strip()) if part)
        message["References"] = chain
    message.set_content(body)
    for path in attach or []:
        data = Path(path).read_bytes()
        subtype = Path(path).suffix.lstrip(".").lower() or "octet-stream"
        message.add_attachment(
            data, maintype="application", subtype=subtype, filename=Path(path).name
        )

    # В конверт SMTP идут только адреса. Отправитель письма подписан как
    # "Федеральный ситуационный центр <sd@...>", и если положить эту строку
    # целиком, smtplib падает на кодировании конверта в ASCII, а сервер
    # отвечает, что SMTPUTF8 не поддерживает.
    recipients = [addr for _, addr in parse_addresses(to, cc)]
    if not recipients:
        raise MailError("Не разобрать адрес получателя: %s" % to.strip()[:120])
    sender = parseaddr(config.sender or config.user)[1] or (config.sender or config.user)
    with _smtp_connect(config, password) as server:
        server.send_message(message, from_addr=sender, to_addrs=recipients)
    logger.info("Письмо отправлено, получателей: %s", len(recipients))
    return {"sent": True, "recipients": recipients, "subject": subject}


def _message_summary(uid: str, message: email.message.Message) -> Dict[str, Any]:
    sender = _decode(message.get("From"))
    date_raw = message.get("Date")
    try:
        received = parsedate_to_datetime(date_raw).isoformat() if date_raw else ""
    except (TypeError, ValueError):
        received = date_raw or ""
    attachments = []
    index = 0
    for part in message.walk():
        if part.get_content_maintype() == "multipart":
            continue
        disposition = (part.get("Content-Disposition") or "").lower()
        filename = part.get_filename()
        if "attachment" not in disposition and not filename:
            continue
        # Точный размер стоил бы раскодировки всех вложений страницы, а это
        # сотни мегабайт в памяти. Для показа хватает оценки по base64.
        raw = part.get_payload(decode=False)
        size = int(len(raw) * 3 / 4) if isinstance(raw, str) else 0
        name = safe_attachment_name(filename, index)
        attachments.append(
            {
                "index": index,
                "name": name,
                "size": size,
                "content_type": part.get_content_type(),
                "too_large": size > MAX_ATTACHMENT_BYTES,
                # Вид файла нужен интерфейсу, чтобы не предлагать положить
                # инструкцию в каталог ключей.
                "kind": attachment_kind(name),
            }
        )
        index += 1
    body = ""
    for part in message.walk():
        # Вложенный текстовый файл телом письма не является.
        if "attachment" in (part.get("Content-Disposition") or "").lower():
            continue
        if part.get_content_type() == "text/plain":
            raw = part.get_payload(decode=True) or b""
            body = raw.decode(part.get_content_charset() or "utf-8", "replace")
            break
    return {
        "uid": uid,
        "from": sender,
        # Отвечать надо на Reply-To, если он задан: у роботов поддержки
        # обратный адрес отличается от того, с которого письмо пришло.
        "reply_to": reply_address(message.get("Reply-To"), sender),
        "reply_to_replaced": bool(_is_noreply(sender) and not _decode(message.get("Reply-To"))),
        "to": _decode(message.get("To")),
        "message_id": (message.get("Message-Id") or "").strip(),
        "references": (message.get("References") or "").strip(),
        "subject": _decode(message.get("Subject")),
        "received_at": received,
        "watched": _is_watched(sender),
        "attachments": attachments,
        "body": body[:20000],
    }


def fetch_headers(config: MailConfig, *, scan: int = 200) -> List[Dict[str, Any]]:
    """Только заголовки последних писем.

    Для списка запросов тела не нужны, а тянуть их по IMAP дорого: на трёх
    десятках писем это уже секунды. Здесь запрашиваются четыре поля заголовка.
    """
    client = _imap_connect(config)
    try:
        client.select("INBOX", readonly=True)
        status, data = client.uid("SEARCH", None, "ALL")
        if status != "OK":
            raise MailError("IMAP не отдал список писем")
        uids = data[0].split()[-scan:]
        if not uids:
            return []
        request = b",".join(uids).decode("ascii")
        status, payload = client.uid(
            "FETCH", request, "(UID BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE)])"
        )
        if status != "OK":
            raise MailError("IMAP не отдал заголовки писем")
        headers: List[Dict[str, Any]] = []
        index = 0
        for item in payload:
            if not isinstance(item, tuple):
                continue
            raw_uid = _uid_from_prefix(item[0])
            message = email.message_from_bytes(item[1])
            sender = _decode(message.get("From"))
            subject = _decode(message.get("Subject"))
            date_raw = message.get("Date")
            try:
                received = parsedate_to_datetime(date_raw).isoformat() if date_raw else ""
            except (TypeError, ValueError):
                received = date_raw or ""
            headers.append(
                {
                    "uid": raw_uid,
                    "seq": index,
                    "from": sender,
                    "subject": subject,
                    "received_at": received,
                    "watched": _is_watched(sender),
                }
            )
            index += 1
        return headers
    finally:
        try:
            client.logout()
        except Exception:
            pass


def build_threads(headers: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Сгруппировать письма в запросы по номеру SCR и вывести статус.

    Статусом запроса считается последнее письмо, которое действительно меняет
    состояние. Комментарии и файлы статус не меняют, они показываются как
    последнее движение: иначе запрос с приложенным сертификатом выглядел бы
    вечно висящим в "добавлен файл".
    """
    threads: Dict[str, Dict[str, Any]] = {}
    for header in headers:
        ticket = parse_ticket(header["subject"])
        if not ticket:
            continue
        status, kind = parse_status(header["subject"])
        thread = threads.setdefault(
            ticket,
            {
                "ticket": ticket,
                "topic": parse_topic(header["subject"]),
                "status": "",
                "status_kind": "",
                "status_at": "",
                "last_event": "",
                "last_at": "",
                "messages": 0,
                "has_files": False,
                "needs_action": False,
                "status_uid": "",
                "status_subject": "",
                "uids": [],
            },
        )
        thread["messages"] += 1
        thread["uids"].append(header["uid"])
        if not thread["topic"]:
            thread["topic"] = parse_topic(header["subject"])
        received = header.get("received_at") or ""
        if received >= thread["last_at"]:
            thread["last_at"] = received
            thread["last_event"] = status or header["subject"]
        if kind == "file":
            thread["has_files"] = True
        if kind and kind not in EVENT_KINDS and received >= thread["status_at"]:
            thread["status"] = status
            thread["status_kind"] = kind
            thread["status_at"] = received
            # Отвечать надо на то письмо, которым объявлено решение, а не на
            # позднейший комментарий: он статус не меняет.
            thread["status_uid"] = header["uid"]
            thread["status_subject"] = header["subject"]
    ordered = sorted(threads.values(), key=lambda item: item["last_at"], reverse=True)
    for thread in ordered:
        if not thread["status"]:
            thread["status"] = "Без статуса"
            thread["status_kind"] = "new"
        # Ответа ждут только сейчас: запрос, который когда-то просил
        # уточнение, а потом закрылся, подсвечивать нельзя.
        thread["needs_action"] = thread["status_kind"] == "action"
    return ordered


def fetch_messages(
    config: MailConfig,
    *,
    limit: int = 30,
    offset: int = 0,
    only_watched: bool = True,
    ticket: str = "",
) -> Dict[str, Any]:
    """Страница писем, свежие сверху.

    Отбор идёт по заголовкам, а тела тянутся только для отобранной страницы:
    в ящике поддержки писем быстро становится много, и грузить всё ради
    десятка на экране незачем.
    """
    headers = fetch_headers(config, scan=500)
    if ticket:
        # Номер запроса - фильтр достаточно узкий сам по себе. Отбор по
        # ведомственным доменам поверх него прятал письма УЦ с обычного
        # адреса, и запрос выглядел как переписка без единого письма.
        selected = [item for item in reversed(headers) if parse_ticket(item["subject"]) == ticket]
    else:
        selected = [item for item in reversed(headers) if not only_watched or item["watched"]]
    total = len(selected)
    page = selected[offset : offset + limit]

    summaries: List[Dict[str, Any]] = []
    if page:
        client = _imap_connect(config)
        try:
            client.select("INBOX", readonly=True)
            for item in page:
                status, payload = client.uid("FETCH", item["uid"], "(RFC822)")
                if status != "OK" or not payload or not isinstance(payload[0], tuple):
                    continue
                message = email.message_from_bytes(payload[0][1])
                summary = _message_summary(item["uid"], message)
                summary["ticket"] = parse_ticket(summary["subject"])
                summary["status"], summary["status_kind"] = parse_status(summary["subject"])
                summaries.append(summary)
        finally:
            try:
                client.logout()
            except Exception:
                pass
    return {
        "messages": summaries,
        "total": total,
        "offset": offset,
        "limit": limit,
    }


def fetch_message(config: MailConfig, *, uid: str) -> Dict[str, Any]:
    """Одно письмо целиком по его номеру в ящике.

    Нужно для ответа: адрес, тема и Message-Id берутся из самого письма, а не
    из того, что прислал браузер. Так ответ не уедет чужому адресату.
    """
    client = _imap_connect(config)
    try:
        client.select("INBOX", readonly=True)
        status, payload = client.uid("FETCH", str(uid), "(RFC822)")
        if status != "OK" or not payload or not isinstance(payload[0], tuple):
            raise MailError("Письмо не найдено")
        message = email.message_from_bytes(payload[0][1])
    finally:
        try:
            client.logout()
        except Exception:
            pass
    summary = _message_summary(str(uid), message)
    summary["ticket"] = parse_ticket(summary["subject"])
    summary["status"], summary["status_kind"] = parse_status(summary["subject"])
    return summary


def reply_subject(subject: str) -> str:
    """Тема ответа - ровно та же, что в письме.

    Робот поддержки просит об этом прямым текстом: "просьба не менять тему
    письма". По теме сшивается тикет, и даже привычное Re: тут лишнее.
    """
    return (subject or "").strip()


def quote_original(message: Dict[str, Any], limit: int = 4000) -> str:
    """Процитировать исходное письмо под ответом.

    Ответ ставится выше цитаты: об этом прямо просит робот поддержки, иначе
    текст теряется при разборе на их стороне.
    """
    head = "%s пишет:" % (message.get("from") or "Отправитель")
    body = (message.get("body") or "")[:limit]
    quoted = "\n".join("> " + line for line in body.splitlines())
    return head + "\n" + quoted


def list_attachments(config: MailConfig, *, letters: int = 20) -> List[Dict[str, Any]]:
    """Вложения последних писем одним списком.

    Оператору нужен ответ на простой вопрос: что вообще прислали. Раскрывать
    ради этого каждое письмо по очереди неудобно, поэтому здесь плоский список
    с обратной ссылкой на письмо.
    """
    page = fetch_messages(config, limit=letters, offset=0, only_watched=True)
    items: List[Dict[str, Any]] = []
    for message in page.get("messages", []):
        for attachment in message.get("attachments", []):
            item = dict(attachment)
            item["uid"] = message["uid"]
            item["ticket"] = message.get("ticket", "")
            item["subject"] = message.get("subject", "")
            item["from"] = message.get("from", "")
            item["received_at"] = message.get("received_at", "")
            items.append(item)
    return items


def read_attachment(config: MailConfig, *, uid: str, index: int) -> Dict[str, Any]:
    """Достать вложение из письма в память, ничего не сохраняя.

    Нужно для просмотра: смотреть файл оператор должен до того, как решит,
    класть его на диск или нет.
    """
    client = _imap_connect(config)
    try:
        client.select("INBOX", readonly=True)
        status, payload = client.uid("FETCH", str(uid), "(RFC822)")
        if status != "OK" or not payload or not isinstance(payload[0], tuple):
            raise MailError("Письмо не найдено")
        message = email.message_from_bytes(payload[0][1])
    finally:
        try:
            client.logout()
        except Exception:
            pass

    current = 0
    for part in message.walk():
        if part.get_content_maintype() == "multipart":
            continue
        disposition = (part.get("Content-Disposition") or "").lower()
        filename = part.get_filename()
        if "attachment" not in disposition and not filename:
            continue
        if current != index:
            current += 1
            continue
        data = part.get_payload(decode=True) or b""
        if len(data) > MAX_ATTACHMENT_BYTES:
            raise MailError("Вложение больше допустимого размера")
        return {
            "name": safe_attachment_name(filename, index),
            "content_type": part.get_content_type(),
            "data": data,
        }
    raise MailError("Вложение с таким номером не найдено")


def save_attachment(
    config: MailConfig,
    *,
    uid: str,
    index: int,
    target_dir: Optional[Path] = None,
) -> Dict[str, Any]:
    """Сохранить вложение в каталог входящих. Установка - отдельный шаг.

    Каталог можно задать явно: ключевой контейнер должен лечь к ключам, а не
    к документам, и решает это вызывающая сторона.
    """
    found = read_attachment(config, uid=uid, index=index)
    data = found["data"]
    folder = Path(target_dir) if target_dir else config.inbox_dir
    folder.mkdir(parents=True, exist_ok=True)
    target = folder / found["name"]
    # Имя пришло снаружи: не даём перезаписать уже сохранённое.
    counter = 1
    while target.exists():
        target = folder / f"{target.stem}-{counter}{target.suffix}"
        counter += 1
    target.write_bytes(data)
    logger.info("Вложение сохранено: %s, %s байт", target.name, len(data))
    return {"saved": True, "path": str(target), "name": target.name, "size": len(data)}
