"""Почтовый ящик оператора: отправка писем в поддержку и разбор ответов.

Переписка с УЦ и с поддержкой ЕПГУ идёт письмами: заявка на тестовый
сертификат, полномочие API-Key, настройка параметров ИС. Ответ приходит
вложением, и до сих пор оператор перекладывал его руками.

Модуль намеренно на стандартной библиотеке (imaplib, smtplib, email): лишняя
зависимость ради IMAP тут не нужна.

Что модуль не делает:

- не отправляет письма сам. Отправка происходит только по явному вызову с уже
  собранным письмом, автоматических рассылок в ведомства нет;
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
from email.utils import parsedate_to_datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

import secret_store
import settings_store

logger = logging.getLogger(__name__)

# Адреса, ответы с которых интересны: поддержка ЕПГУ, УЦ, техпортал.
WATCHED_DOMAINS = ("gov.ru", "sc.digital.gov.ru", "digital.gov.ru", "gosuslugi.ru")

# Имя файла из вложения приходит от внешнего отправителя, поэтому берётся
# только базовое имя и только безопасные символы.
_SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")

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


def _decode(value: Optional[str]) -> str:
    if not value:
        return ""
    try:
        return str(make_header(decode_header(value)))
    except Exception:
        return value


def safe_attachment_name(raw: Optional[str], index: int) -> str:
    name = Path(_decode(raw) or "").name
    name = _SAFE_NAME.sub("_", name).strip("._") or f"attachment-{index}"
    return name[:120]


def _is_watched(address: str) -> bool:
    address = address.lower()
    return any(domain in address for domain in WATCHED_DOMAINS)


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


def send_letter(
    config: MailConfig,
    *,
    to: str,
    subject: str,
    body: str,
    cc: str = "",
) -> Dict[str, Any]:
    """Отправить одно письмо. Вызывается только по явному действию оператора."""
    if not config.smtp_host:
        raise MailError("SMTP-сервер не задан")
    if not to.strip():
        raise MailError("Не указан адрес получателя")
    password = secret_store.get_secret("MAIL_PASSWORD")

    message = EmailMessage()
    message["From"] = config.sender or config.user
    message["To"] = to
    if cc.strip():
        message["Cc"] = cc
    message["Subject"] = subject
    message.set_content(body)

    recipients = [addr.strip() for addr in (to + "," + cc).split(",") if addr.strip()]
    with _smtp_connect(config, password) as server:
        server.send_message(message, to_addrs=recipients)
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
        payload = part.get_payload(decode=True) or b""
        attachments.append(
            {
                "index": index,
                "name": safe_attachment_name(filename, index),
                "size": len(payload),
                "content_type": part.get_content_type(),
                "too_large": len(payload) > MAX_ATTACHMENT_BYTES,
            }
        )
        index += 1
    body = ""
    for part in message.walk():
        if part.get_content_type() == "text/plain":
            raw = part.get_payload(decode=True) or b""
            body = raw.decode(part.get_content_charset() or "utf-8", "replace")
            break
    return {
        "uid": uid,
        "from": sender,
        "subject": _decode(message.get("Subject")),
        "received_at": received,
        "watched": _is_watched(sender),
        "attachments": attachments,
        "body": body[:20000],
    }


def fetch_messages(config: MailConfig, *, limit: int = 30, only_watched: bool = True) -> List[Dict[str, Any]]:
    """Последние письма ящика, свежие сверху."""
    client = _imap_connect(config)
    try:
        client.select("INBOX", readonly=True)
        status, data = client.search(None, "ALL")
        if status != "OK":
            raise MailError("IMAP не отдал список писем")
        uids = data[0].split()
        summaries: List[Dict[str, Any]] = []
        for uid in reversed(uids):
            if len(summaries) >= limit:
                break
            status, payload = client.fetch(uid, "(RFC822)")
            if status != "OK" or not payload or not isinstance(payload[0], tuple):
                continue
            message = email.message_from_bytes(payload[0][1])
            summary = _message_summary(uid.decode("ascii", "replace"), message)
            if only_watched and not summary["watched"]:
                continue
            summaries.append(summary)
        return summaries
    finally:
        try:
            client.logout()
        except Exception:
            pass


def save_attachment(config: MailConfig, *, uid: str, index: int) -> Dict[str, Any]:
    """Сохранить вложение в каталог входящих. Установка - отдельный шаг."""
    client = _imap_connect(config)
    try:
        client.select("INBOX", readonly=True)
        status, payload = client.fetch(uid.encode("ascii"), "(RFC822)")
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
        name = safe_attachment_name(filename, index)
        config.inbox_dir.mkdir(parents=True, exist_ok=True)
        target = config.inbox_dir / name
        # Имя пришло снаружи: не даём перезаписать уже сохранённое.
        counter = 1
        while target.exists():
            target = config.inbox_dir / f"{target.stem}-{counter}{target.suffix}"
            counter += 1
        target.write_bytes(data)
        logger.info("Вложение сохранено: %s, %s байт", target.name, len(data))
        return {"saved": True, "path": str(target), "name": target.name, "size": len(data)}
    raise MailError("Вложение с таким номером не найдено")
