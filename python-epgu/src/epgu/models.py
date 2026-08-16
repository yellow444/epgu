# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025 yellow444 <yellow444@gmail.com>
"""Typed, forward-compatible models for the EPGU API.

EPGU responses contain a large number of service-specific and undocumented
fields.  The models below expose the stable fields from API specification 1.14
and retain the complete source object in ``raw`` so callers do not lose data
when the service adds another field.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Union, overload
from urllib.parse import unquote, urlparse


def _to_int(value: Any) -> Optional[int]:
    """Convert an API scalar to ``int`` without treating ``0`` as missing."""
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _as_dict(value: Any) -> Dict[str, Any]:
    return dict(value) if isinstance(value, Mapping) else {}


@dataclass(frozen=True)
class OrderMeta:
    """Metadata required to create an application.

    Args:
        region: applicant/service region code.
        service_code: EPGU service code (``serviceCode`` on the wire).
        target_code: service target code (``targetCode`` on the wire).
    """

    region: str
    service_code: str
    target_code: str

    def __post_init__(self) -> None:
        for name in ("service_code", "target_code"):
            if not getattr(self, name):
                raise ValueError(f"{name} must not be empty")
        if re.fullmatch(r"\d{2,11}", self.region) is None:
            raise ValueError("region must be a 2..11 digit OKATO code")

    def to_payload(self) -> Dict[str, str]:
        """Return the exact JSON object expected by EPGU."""
        return {
            "region": self.region,
            "serviceCode": self.service_code,
            "targetCode": self.target_code,
        }


@dataclass
class OrderFile:
    """A request or response attachment from application details."""

    file_name: str
    link: str
    file_id: str = ""
    file_size: Optional[int] = None
    mime_type: str = ""
    has_digital_signature: bool = False
    file_type: str = ""
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def mnemonic(self) -> str:
        """Filename encoded in a ``terrabyte://`` attachment link."""
        parts = self._terrabyte_parts()
        return parts[-2] if parts else ""

    @property
    def object_type(self) -> str:
        """Object type encoded in a ``terrabyte://`` attachment link."""
        parts = self._terrabyte_parts()
        if parts:
            return parts[-1]
        # Compatibility with old responses containing an ordinary URL/path.
        return self.link.rstrip("/").split("/")[-1] if self.link else ""

    def _terrabyte_parts(self) -> List[str]:
        parsed = urlparse(self.link)
        if parsed.scheme.lower() != "terrabyte":
            return []
        parts = parsed.path.strip("/").split("/")
        if len(parts) < 2 or not parts[-2] or not parts[-1]:
            return []
        return [unquote(part) for part in parts]

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "OrderFile":
        """Create an attachment model from a wire response object."""
        return cls(
            file_name=str(data.get("fileName") or ""),
            link=str(data.get("link") or ""),
            file_id=str(data.get("id") or ""),
            file_size=_to_int(data.get("fileSize")),
            mime_type=str(data.get("mimeType") or ""),
            has_digital_signature=bool(data.get("hasDigitalSignature", False)),
            file_type=str(data.get("type") or ""),
            raw=dict(data),
        )


@dataclass
class Order:
    """Application details returned by ``POST /api/gusmev/order/{id}``.

    ``code``, ``message`` and ``message_id`` come from the response envelope;
    the remaining attributes are parsed from its JSON-encoded ``order`` field.
    All request and response attachments are available through ``files`` and
    separately through ``attachment_files`` / ``response_files``.
    """

    order_id: int
    status_code: Optional[int] = None
    status_name: Optional[str] = None
    status_history_id: Optional[int] = None
    cancel_allowed: bool = False
    final_status: bool = False
    closed: bool = False
    updated: Optional[str] = None
    code: Optional[str] = None
    message: Optional[str] = None
    message_id: Optional[str] = None
    files: List[OrderFile] = field(default_factory=list)
    attachment_files: List[OrderFile] = field(default_factory=list)
    response_files: List[OrderFile] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_response(cls, data: Mapping[str, Any]) -> "Order":
        """Parse an EPGU response, including its JSON-encoded ``order`` field.

        Raises:
            ValueError: if ``data`` or a non-empty ``order`` value has an
                unsupported shape.  Silently accepting malformed payloads
                would otherwise turn real application IDs into ``0``.
        """
        if not isinstance(data, Mapping):
            raise ValueError("order response must be a JSON object")

        nested = data.get("order")
        if isinstance(nested, str):
            if not nested.strip():
                order_obj: Dict[str, Any] = {}
            else:
                try:
                    decoded = json.loads(nested)
                except json.JSONDecodeError as exc:
                    raise ValueError("the 'order' field is not valid JSON") from exc
                if not isinstance(decoded, Mapping):
                    raise ValueError("the decoded 'order' field must be a JSON object")
                order_obj = dict(decoded)
        elif isinstance(nested, Mapping):
            order_obj = dict(nested)
        elif nested is None:
            # Some mocks/older gateways return the details object directly.
            order_obj = dict(data)
        else:
            raise ValueError("the 'order' field must be a JSON string or object")

        attachment_files = [
            OrderFile.from_dict(item)
            for item in order_obj.get("orderAttachmentFiles", []) or []
            if isinstance(item, Mapping)
        ]
        response_files = [
            OrderFile.from_dict(item)
            for item in order_obj.get("orderResponseFiles", []) or []
            if isinstance(item, Mapping)
        ]
        current_status = _as_dict(order_obj.get("currentStatusHistory"))

        order_id = _to_int(order_obj.get("id"))
        if order_id is None:
            order_id = _to_int(order_obj.get("orderId"))
        if order_id is None:
            order_id = _to_int(data.get("orderId"))
        if order_id is None or order_id <= 0:
            raise ValueError("order response does not contain a positive application id")

        status_code = _to_int(order_obj.get("orderStatusId"))
        if status_code is None:
            status_code = _to_int(current_status.get("statusId"))

        status_history_id = _to_int(order_obj.get("currentStatusHistoryId"))
        if status_history_id is None:
            status_history_id = _to_int(current_status.get("id"))

        return cls(
            order_id=order_id,
            status_code=status_code,
            status_name=(
                str(order_obj.get("orderStatusName"))
                if order_obj.get("orderStatusName") is not None
                else (str(current_status.get("title")) if current_status.get("title") else None)
            ),
            status_history_id=status_history_id,
            cancel_allowed=bool(current_status.get("cancelAllowed", False)),
            final_status=bool(current_status.get("finalStatus", False)),
            closed=bool(order_obj.get("closed", False)),
            updated=str(order_obj.get("updated")) if order_obj.get("updated") else None,
            code=str(data.get("code")) if data.get("code") is not None else None,
            message=str(data.get("message")) if data.get("message") is not None else None,
            message_id=(
                str(data.get("messageId") or data.get("message_id"))
                if data.get("messageId") or data.get("message_id")
                else None
            ),
            files=[*attachment_files, *response_files],
            attachment_files=attachment_files,
            response_files=response_files,
            raw=order_obj,
        )

    def file(self, file_name: str) -> Optional[OrderFile]:
        """Return the first attachment with ``file_name``, or ``None``."""
        return next((item for item in self.files if item.file_name == file_name), None)


@dataclass
class OrderStatus:
    """Application status from ``getOrdersStatus`` / ``getUpdatedAfter``."""

    order_id: int
    status_code: Optional[int] = None
    status_name: Optional[str] = None
    updated: Optional[str] = None
    search_status: Optional[str] = None
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "OrderStatus":
        """Parse both specification 1.14 and legacy flattened responses."""
        status = _as_dict(data.get("status"))
        status_code = _to_int(status.get("statusId"))
        if status_code is None:
            status_code = _to_int(data.get("orderStatusId"))
        if status_code is None:
            status_code = _to_int(data.get("statusId"))

        status_name = status.get("statusName")
        if status_name is None:
            status_name = data.get("statusName")

        updated = status.get("updated")
        if updated is None:
            updated = data.get("updated")

        return cls(
            order_id=_to_int(data.get("orderId")) or 0,
            status_code=status_code,
            status_name=str(status_name) if status_name is not None else None,
            updated=str(updated) if updated is not None else None,
            search_status=(
                str(data.get("orderSearchStatus"))
                if data.get("orderSearchStatus") is not None
                else None
            ),
            raw=dict(data),
        )


@dataclass
class OrdersPage:
    """Paginated status response while remaining convenient to iterate/index."""

    items: List[OrderStatus] = field(default_factory=list)
    count: int = 0
    total_count: int = 0
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)

    @property
    def content(self) -> List[OrderStatus]:
        """Alias matching the EPGU wire field name."""
        return self.items

    def __len__(self) -> int:
        return len(self.items)

    def __iter__(self) -> Iterator[OrderStatus]:
        return iter(self.items)

    @overload
    def __getitem__(self, index: int) -> OrderStatus: ...

    @overload
    def __getitem__(self, index: slice) -> List[OrderStatus]: ...

    def __getitem__(self, index: Union[int, slice]) -> Union[OrderStatus, List[OrderStatus]]:
        return self.items[index]

    @classmethod
    def from_response(cls, data: Any) -> "OrdersPage":
        """Parse the documented envelope plus known legacy list envelopes."""
        items_data: Any
        if isinstance(data, list):
            items_data = data
            raw: Dict[str, Any] = {"content": data}
            count = total_count = len(data)
        elif isinstance(data, Mapping):
            raw = dict(data)
            items_data = data.get("content")
            if not isinstance(items_data, list):
                for key in ("orders", "items", "data"):
                    if isinstance(data.get(key), list):
                        items_data = data[key]
                        break
            if not isinstance(items_data, list):
                items_data = []
            parsed_count = _to_int(data.get("count"))
            parsed_total_count = _to_int(data.get("totalCount"))
            count = len(items_data) if parsed_count is None else parsed_count
            total_count = count if parsed_total_count is None else parsed_total_count
        else:
            raise ValueError("status response must be a JSON object or array")

        items = [OrderStatus.from_dict(item) for item in items_data if isinstance(item, Mapping)]
        return cls(items=items, count=count, total_count=total_count, raw=raw)


@dataclass
class DictionaryItem:
    """One NSI dictionary item from ``/api/nsi/v1/dictionary/{code}``."""

    value: str
    title: str
    parent_value: Optional[str] = None
    is_leaf: bool = False
    children: List[Dict[str, Any]] = field(default_factory=list)
    attributes: List[Dict[str, Any]] = field(default_factory=list)
    attribute_values: Dict[str, Any] = field(default_factory=dict)
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "DictionaryItem":
        """Построить типизированный элемент из JSON-объекта НСИ."""
        return cls(
            value=str(data.get("value") or ""),
            title=str(data.get("title") or ""),
            parent_value=(
                str(data.get("parentValue")) if data.get("parentValue") is not None else None
            ),
            is_leaf=bool(data.get("isLeaf", False)),
            children=[
                dict(item) for item in data.get("children", []) or [] if isinstance(item, Mapping)
            ],
            attributes=[
                dict(item) for item in data.get("attributes", []) or [] if isinstance(item, Mapping)
            ],
            attribute_values=_as_dict(data.get("attributeValues")),
            raw=dict(data),
        )


@dataclass
class DictionaryResult(Sequence[DictionaryItem]):
    """Typed NSI result with operation status and total item count."""

    items: List[DictionaryItem] = field(default_factory=list)
    total: int = 0
    error_code: int = 0
    error_message: str = ""
    field_errors: List[Dict[str, Any]] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict, repr=False)

    def __len__(self) -> int:
        return len(self.items)

    def __iter__(self) -> Iterator[DictionaryItem]:
        return iter(self.items)

    @overload
    def __getitem__(self, index: int) -> DictionaryItem: ...

    @overload
    def __getitem__(self, index: slice) -> List[DictionaryItem]: ...

    def __getitem__(self, index: Union[int, slice]) -> Union[DictionaryItem, List[DictionaryItem]]:
        return self.items[index]

    @classmethod
    def from_response(cls, data: Any) -> "DictionaryResult":
        """Разобрать документированный конверт ответа справочника НСИ."""
        if not isinstance(data, Mapping):
            raise ValueError("dictionary response must be a JSON object")
        error = _as_dict(data.get("error"))
        item_values = data.get("items")
        if item_values is None:
            item_values = []
        if not isinstance(item_values, list):
            raise ValueError("dictionary 'items' field must be an array")
        field_values = data.get("fieldErrors")
        if field_values is None:
            field_values = []
        if not isinstance(field_values, list):
            raise ValueError("dictionary 'fieldErrors' field must be an array")
        return cls(
            items=[
                DictionaryItem.from_dict(item) for item in item_values if isinstance(item, Mapping)
            ],
            total=_to_int(data.get("total")) or 0,
            error_code=_to_int(error.get("code")) or 0,
            error_message=str(error.get("message") or ""),
            field_errors=[dict(item) for item in field_values if isinstance(item, Mapping)],
            raw=dict(data),
        )
