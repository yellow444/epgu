"""Типизированные модели данных API ЕПГУ (gusmev).

Модели намеренно «толерантны»: ответы ЕПГУ часто содержат больше полей, чем
описано в спецификации, и набор полей отличается между тестовым и боевым
контурами. Поэтому каждая модель хранит исходный словарь в ``raw`` и парсит
только то, что нужно для типовых сценариев.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


def _to_int(value: Any) -> Optional[int]:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


@dataclass
class OrderMeta:
    """Параметры услуги для создания заявления (POST /api/gusmev/order).

    Соответствует телу запроса ``order``. Значения по умолчанию подобраны под
    типовую тестовую услугу из репозитория, но в реальном использовании их нужно
    указывать под конкретную услугу из техпортала.
    """

    region: str
    service_code: str
    target_code: str

    def to_payload(self) -> Dict[str, str]:
        return {
            "region": self.region,
            "serviceCode": self.service_code,
            "targetCode": self.target_code,
        }


@dataclass
class OrderFile:
    """Файл, приложенный к заявлению, из ответа ЕПГУ."""

    file_name: str
    link: str
    raw: Dict[str, Any] = field(default_factory=dict)

    @property
    def object_type(self) -> str:
        """Последний сегмент ``link`` - используется при скачивании файла."""
        return self.link.rstrip("/").split("/")[-1] if self.link else ""

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "OrderFile":
        return cls(
            file_name=data.get("fileName", ""),
            link=data.get("link", ""),
            raw=data,
        )


@dataclass
class Order:
    """Заявление и его текущий статус (ответ POST /api/gusmev/order/{id})."""

    order_id: int
    status_code: Optional[int] = None
    status_history_id: Optional[int] = None
    files: List[OrderFile] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_response(cls, data: Dict[str, Any]) -> "Order":
        """Разбирает ответ ЕПГУ.

        ЕПГУ возвращает поле ``order`` строкой с вложенным JSON - это учитывается.
        """
        order_obj = data
        nested = data.get("order")
        if isinstance(nested, str):
            try:
                order_obj = json.loads(nested)
            except json.JSONDecodeError:
                order_obj = data
        elif isinstance(nested, dict):
            order_obj = nested

        files = [
            OrderFile.from_dict(f)
            for f in order_obj.get("orderResponseFiles", []) or []
        ]
        return cls(
            order_id=_to_int(order_obj.get("orderId")) or _to_int(data.get("orderId")) or 0,
            status_code=_to_int(order_obj.get("orderStatusId")),
            status_history_id=_to_int(order_obj.get("currentStatusHistoryId")),
            files=files,
            raw=order_obj,
        )

    def file(self, file_name: str) -> Optional[OrderFile]:
        """Возвращает приложенный файл по имени или ``None``."""
        for f in self.files:
            if f.file_name == file_name:
                return f
        return None


@dataclass
class OrderStatus:
    """Краткий статус заявления (getOrdersStatus / getUpdatedAfter)."""

    order_id: int
    status_code: Optional[int] = None
    raw: Dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "OrderStatus":
        return cls(
            order_id=_to_int(data.get("orderId")) or 0,
            status_code=_to_int(data.get("orderStatusId") or data.get("statusId")),
            raw=data,
        )
