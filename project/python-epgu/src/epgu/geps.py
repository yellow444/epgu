# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025 yellow444 <yellow444@gmail.com>
"""Госпочта организации (ГЭПС): уведомления из личного кабинета на ЕПГУ.

Источник: «Спецификация API ГЭПС. Приложение "Получение уведомлений Госпочты и
Новости"», версия 1.0 от 29.01.2026. Все методы идут через прокси API ЕПГУ,
то есть с обычным маркером доступа организации.

Порядок работы задан спецификацией и обойти его нельзя::

    заказать список -> дождаться готовности -> карточка -> вложение

Что важно знать до того, как это включать:

* Диапазон поиска не больше суток, глубина не больше 30 дней.
* Пять заказов списка в сутки и пятнадцать получений готового списка.
  Карточки и вложения без ограничения по количеству.
* Список готовится асинхронно, спецификация советует приходить за ним через
  час, и живёт он семь дней.
* Нужна роль «Руководитель организации» или «Администратор», иначе 403.
* **Чтение равнозначно входу на портал.** По ряду постановлений уведомление
  считается вручённым с момента входа, поэтому запускать это фоном «на всякий
  случай» нельзя: так можно молча начать течение процессуальных сроков.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Any, Dict, Mapping, Optional, Sequence

from .errors import ConfigError, ValidationError

BASE_PATH = "/api/gusmev/proxy/geps-api-ext/api/messages/v1"

MAX_RANGE = timedelta(days=1)
MAX_DEPTH = timedelta(days=30)
MAX_PAGE_SIZE = 1000
RESULT_LIFETIME = timedelta(days=7)
RECOMMENDED_WAIT = timedelta(hours=1)

# Лимиты из приложения А спецификации, на сутки.
DAILY_SEARCH_LIMIT = 5
DAILY_RESULT_LIMIT = 15

_UUID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


class StatusFilter(str, Enum):
    """Фильтр по признаку прочтения при заказе списка."""

    ANY = "ANY"
    READ = "READ"
    UNREAD = "UNREAD"


class SearchTaskStatus(str, Enum):
    """Готовность заказанного списка."""

    SEARCH = "SEARCH"
    PROCESSING = "PROCESSING"
    COMPLETED = "COMPLETED"
    ERROR = "ERROR"

    @property
    def is_final(self) -> bool:
        return self in (SearchTaskStatus.COMPLETED, SearchTaskStatus.ERROR)

    @property
    def is_ready(self) -> bool:
        return self is SearchTaskStatus.COMPLETED


class AttachmentStatus(str, Enum):
    """Состояние вложения."""

    READY = "READY"
    DOWNLOADING = "DOWNLOADING"
    DELETED = "DELETED"
    UNKNOWN = "UNKNOWN"

    @classmethod
    def parse(cls, value: Any) -> "AttachmentStatus":
        try:
            return cls(str(value).upper())
        except ValueError:
            return cls.UNKNOWN

    @property
    def downloadable(self) -> bool:
        return self is AttachmentStatus.READY


class FileType(str, Enum):
    """Что скачиваем: сам файл или отсоединённую подпись к нему."""

    FILE = "file"
    SIGNATURE = "sig"


def _uuid(value: str, field_name: str) -> str:
    text = str(value or "").strip()
    if not _UUID_RE.match(text):
        raise ValidationError(f"{field_name}: ожидается UUID, получено {value!r}")
    return text


def _moment(value: Any, field_name: str) -> datetime:
    if isinstance(value, datetime):
        moment = value
    else:
        text = str(value or "").strip()
        if not text:
            raise ValidationError(f"{field_name} обязателен")
        try:
            moment = datetime.fromisoformat(text.replace("Z", "+00:00"))
        except ValueError as exc:
            raise ValidationError(f"{field_name}: не разобрал дату {value!r}") from exc
    if moment.tzinfo is None:
        raise ValidationError(
            f"{field_name}: нужна дата со смещением часового пояса, "
            "иначе граница суток будет другой на сервере и у нас"
        )
    return moment


def _parse_moment(value: Any) -> Optional[datetime]:
    """Мягкий разбор даты из ответа: непонятное не роняет весь список."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        return None


@dataclass(frozen=True)
class SearchRange:
    """Период поиска уведомлений.

    Спецификация ограничивает и длину периода, и глубину. Проверяем это здесь,
    а не на сервере: каждый отклонённый заказ съедает одну из пяти суточных
    попыток.
    """

    start: datetime
    end: datetime
    status: StatusFilter = StatusFilter.ANY

    def __post_init__(self) -> None:
        start = _moment(self.start, "startDateTime")
        end = _moment(self.end, "endDateTime")
        object.__setattr__(self, "start", start)
        object.__setattr__(self, "end", end)
        if not isinstance(self.status, StatusFilter):
            object.__setattr__(self, "status", StatusFilter(str(self.status).upper()))
        if end <= start:
            raise ValidationError(
                "endDateTime должен быть больше startDateTime: "
                f"{start.isoformat()} и {end.isoformat()}"
            )
        if end - start > MAX_RANGE:
            raise ValidationError(
                "Период поиска не больше суток, запрошено "
                f"{(end - start)}"
            )

    def validate_against(self, now: datetime) -> None:
        """Проверить глубину и то, что период не в будущем."""
        now = _moment(now, "now")
        if self.end > now:
            raise ValidationError("endDateTime должен быть меньше текущего времени")
        if now - self.start > MAX_DEPTH:
            raise ValidationError(
                "Глубина поиска не больше 30 дней, запрошено "
                f"{(now - self.start).days} дней"
            )

    def to_payload(self) -> Dict[str, str]:
        return {
            "startDateTime": self.start.isoformat(timespec="milliseconds"),
            "endDateTime": self.end.isoformat(timespec="milliseconds"),
            "statusFilter": self.status.value,
        }


@dataclass(frozen=True)
class MessageBrief:
    """Строка списка уведомлений."""

    thread_uuid: str
    message_uuid: str
    feed_title: str
    feed_subtitle: str
    is_read: bool
    create_date: Optional[datetime]

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "MessageBrief":
        if not isinstance(payload, Mapping):
            raise ValidationError("Элемент списка уведомлений не является объектом")
        return cls(
            thread_uuid=str(payload.get("threadUuid") or ""),
            message_uuid=str(payload.get("messageUuid") or ""),
            feed_title=str(payload.get("feedTitle") or ""),
            feed_subtitle=str(payload.get("feedSubtitle") or ""),
            is_read=bool(payload.get("isRead")),
            create_date=_parse_moment(payload.get("createDate")),
        )


@dataclass(frozen=True)
class SearchResult:
    """Ответ сервиса получения сформированного списка."""

    status: SearchTaskStatus
    messages: Sequence[MessageBrief] = ()
    offset: int = 0
    limit: int = MAX_PAGE_SIZE
    total: Optional[int] = None

    @property
    def ready(self) -> bool:
        return self.status.is_ready

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "SearchResult":
        if not isinstance(payload, Mapping):
            raise ValidationError("Ответ списка уведомлений не является объектом")
        raw_status = str(payload.get("searchTaskStatus") or "").upper()
        try:
            status = SearchTaskStatus(raw_status)
        except ValueError as exc:
            raise ValidationError(
                f"Неизвестное состояние задачи: {payload.get('searchTaskStatus')!r}"
            ) from exc
        messages = [
            MessageBrief.from_payload(item)
            for item in payload.get("messageList") or []
        ]
        total = payload.get("total")
        return cls(
            status=status,
            messages=tuple(messages),
            offset=int(payload.get("offset") or 0),
            limit=int(payload.get("limit") or MAX_PAGE_SIZE),
            total=int(total) if total is not None else None,
        )


@dataclass(frozen=True)
class Attachment:
    """Вложение уведомления."""

    message_uuid: str
    attachment_uuid: str
    file_name: str
    mime_type: str
    signed: bool
    status: AttachmentStatus
    status_description: str = ""
    file_size: Optional[int] = None

    @property
    def downloadable(self) -> bool:
        return self.status.downloadable

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "Attachment":
        if not isinstance(payload, Mapping):
            raise ValidationError("Вложение не является объектом")
        size = payload.get("fileSize")
        return cls(
            message_uuid=str(payload.get("messageUuid") or ""),
            attachment_uuid=str(payload.get("attachmentUuid") or ""),
            file_name=str(payload.get("fileName") or ""),
            mime_type=str(payload.get("mimeType") or ""),
            signed=bool(payload.get("signed")),
            status=AttachmentStatus.parse(payload.get("statusMnemonic")),
            status_description=str(payload.get("statusDescription") or ""),
            file_size=int(size) if size is not None else None,
        )


@dataclass(frozen=True)
class MessageStatus:
    """Запись в истории статусов уведомления."""

    mnemonic: str
    description: str = ""
    originator: str = ""
    create_date: Optional[datetime] = None

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "MessageStatus":
        if not isinstance(payload, Mapping):
            raise ValidationError("Статус уведомления не является объектом")
        return cls(
            mnemonic=str(payload.get("mnemonic") or ""),
            description=str(payload.get("description") or ""),
            originator=str(payload.get("originatorUserName") or ""),
            create_date=_parse_moment(payload.get("createDate")),
        )


@dataclass(frozen=True)
class MessageDetail:
    """Карточка уведомления.

    ``text`` приходит в виде HTML со стилями ЕПГУ. Это чужая разметка, и
    вставлять её в свою страницу как есть нельзя.
    """

    thread_uuid: str
    message_uuid: str
    text: str
    is_read: bool
    create_date: Optional[datetime]
    params: Mapping[str, Any] = field(default_factory=dict)
    attachments: Sequence[Attachment] = ()
    statuses: Sequence[MessageStatus] = ()

    @property
    def sender(self) -> str:
        """Отправитель так, как его показывает ЕПГУ."""
        return str(self.params.get("feed_title") or self.params.get("inner_title") or "")

    @property
    def subject(self) -> str:
        return str(
            self.params.get("feed_subtitle") or self.params.get("inner_subtitle") or ""
        )

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> "MessageDetail":
        if not isinstance(payload, Mapping):
            raise ValidationError("Карточка уведомления не является объектом")
        params = payload.get("params")
        return cls(
            thread_uuid=str(payload.get("threadUuid") or ""),
            message_uuid=str(payload.get("messageUuid") or ""),
            text=str(payload.get("text") or ""),
            is_read=bool(payload.get("isRead")),
            create_date=_parse_moment(payload.get("createDate")),
            params=dict(params) if isinstance(params, Mapping) else {},
            attachments=tuple(
                Attachment.from_payload(item)
                for item in payload.get("attachmentList") or []
            ),
            statuses=tuple(
                MessageStatus.from_payload(item)
                for item in payload.get("statusList") or []
            ),
        )


@dataclass(frozen=True)
class AttachmentFile:
    """Скачанное вложение или отсоединённая подпись к нему."""

    content: bytes
    file_name: str
    mime_type: str

    def __len__(self) -> int:
        return len(self.content)


def search_path() -> str:
    return f"{BASE_PATH}/search"


def result_path(task_uuid: str) -> str:
    return f"{search_path()}/{_uuid(task_uuid, 'searchTaskUuid')}"


def message_path(thread_uuid: str, message_uuid: str) -> str:
    return "{0}/message/{1}/{2}".format(
        BASE_PATH,
        _uuid(thread_uuid, "threadUuid"),
        _uuid(message_uuid, "messageUuid"),
    )


def attachment_path(
    message_uuid: str,
    attachment_uuid: str,
    file_type: FileType = FileType.FILE,
) -> str:
    if not isinstance(file_type, FileType):
        try:
            file_type = FileType(str(file_type).lower())
        except ValueError as exc:
            raise ConfigError(f"Неизвестный тип файла: {file_type!r}") from exc
    return "{0}/attachment/{1}/{2}/{3}".format(
        BASE_PATH,
        _uuid(message_uuid, "messageUuid"),
        _uuid(attachment_uuid, "attachmentUuid"),
        file_type.value,
    )


def page_params(offset: int = 0, limit: int = MAX_PAGE_SIZE) -> Dict[str, int]:
    """Параметры постраничной выдачи готового списка."""
    if offset < 0:
        raise ValidationError("offset не может быть отрицательным")
    if limit < 1 or limit > MAX_PAGE_SIZE:
        raise ValidationError(f"limit от 1 до {MAX_PAGE_SIZE}, получено {limit}")
    return {"offset": offset, "limit": limit}


def file_name_from_headers(headers: Mapping[str, str], default: str = "attachment") -> str:
    """Имя файла из Content-Disposition.

    Отправитель волен прислать что угодно, включая путь. Берём только имя и
    выбрасываем разделители: файл потом сохраняют на диск.
    """
    raw = ""
    for name, value in headers.items():
        if name.lower() == "content-disposition":
            raw = value or ""
            break
    name = ""
    match = re.search(r"filename\*\s*=\s*(?:UTF-8'')?([^;]+)", raw, re.IGNORECASE)
    if match:
        from urllib.parse import unquote

        name = unquote(match.group(1).strip().strip('"'))
    else:
        match = re.search(r'filename\s*=\s*"?([^";]+)"?', raw, re.IGNORECASE)
        if match:
            name = match.group(1).strip()
    name = name.replace("\\", "/").split("/")[-1].strip()
    name = re.sub(r'[\x00-\x1f<>:"|?*]', "", name)
    if name in ("", ".", ".."):
        return default
    return name


def daily_limit(kind: str) -> int:
    """Суточный лимит на сервис. Нужен тем, кто ведёт свой учёт обращений."""
    limits = {"search": DAILY_SEARCH_LIMIT, "result": DAILY_RESULT_LIMIT}
    if kind not in limits:
        raise ConfigError(f"Неизвестный сервис ГЭПС: {kind!r}")
    return limits[kind]


def suggested_range(now: datetime, days_back: int = 1) -> SearchRange:
    """Готовый период: сутки, отстоящие от текущего момента на ``days_back``.

    Удобно для регулярного забора: один заказ в сутки на предыдущие сутки.
    """
    now = _moment(now, "now")
    end = now - timedelta(days=days_back - 1) if days_back > 1 else now
    start = end - MAX_RANGE
    if now - start > MAX_DEPTH:
        raise ValidationError("Запрошенные сутки глубже 30 дней")
    return SearchRange(start=start, end=end)


__all__ = [
    "BASE_PATH",
    "MAX_RANGE",
    "MAX_DEPTH",
    "MAX_PAGE_SIZE",
    "RESULT_LIFETIME",
    "RECOMMENDED_WAIT",
    "DAILY_SEARCH_LIMIT",
    "DAILY_RESULT_LIMIT",
    "StatusFilter",
    "SearchTaskStatus",
    "AttachmentStatus",
    "FileType",
    "SearchRange",
    "MessageBrief",
    "SearchResult",
    "Attachment",
    "MessageStatus",
    "MessageDetail",
    "AttachmentFile",
    "search_path",
    "result_path",
    "message_path",
    "attachment_path",
    "page_params",
    "file_name_from_headers",
    "daily_limit",
    "suggested_range",
]
