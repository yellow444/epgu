"""Типовой сценарий подачи заявления «под ключ»."""

from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any, Dict, Optional, Union

from ..archive import OrderArchive
from ..client import EpguClient
from ..models import Order, OrderMeta


@dataclass
class SubmitResult:
    """Итог подачи заявления."""

    order_id: int
    push_response: Dict[str, Any]
    order: Optional[Order] = None


def submit_application(
    client: EpguClient,
    meta: Union[OrderMeta, Dict[str, str]],
    archive: OrderArchive,
    *,
    chunked: bool = True,
    push_meta: Optional[Dict[str, Any]] = None,
    wait: bool = False,
    poll_interval: float = 5.0,
    timeout: float = 300.0,
) -> SubmitResult:
    """Создать заявление, загрузить документы и (опционально) дождаться статуса.

    Args:
        client: настроенный :class:`~epgu.client.EpguClient`.
        meta: параметры услуги (регион/код услуги/код цели).
        archive: собранный комплект документов.
        chunked: использовать ``push/chunked`` (рекомендуется) вместо ``push``.
        push_meta: тело ``meta`` для загрузки; если ``None`` - берётся из ``meta``.
        wait: дождаться ли изменения статуса заявления.
        poll_interval: пауза между опросами статуса, сек.
        timeout: максимальное время ожидания статуса, сек.

    Returns:
        :class:`SubmitResult` с ``order_id``, ответом загрузки и (если ``wait``)
        актуальным состоянием заявления.
    """
    order_id = client.create_order(meta)

    archive_bytes = archive.to_bytes()
    meta_payload = push_meta if push_meta is not None else (
        meta.to_payload() if isinstance(meta, OrderMeta) else dict(meta)
    )

    if chunked:
        push_response = client.push_chunked(meta_payload, archive_bytes, order_id=order_id)
    else:
        push_response = client.push(meta_payload, archive_bytes)

    order: Optional[Order] = None
    if wait:
        order = _wait_for_update(
            client, order_id, meta, poll_interval=poll_interval, timeout=timeout
        )

    return SubmitResult(order_id=order_id, push_response=push_response, order=order)


def _wait_for_update(
    client: EpguClient,
    order_id: int,
    meta: Union[OrderMeta, Dict[str, str]],
    *,
    poll_interval: float,
    timeout: float,
) -> Order:
    deadline = time.monotonic() + timeout
    last: Optional[Order] = None
    while True:
        last = client.order_info(order_id, meta)
        # status_code > 0 означает, что ведомство начало обработку.
        if last.status_code:
            return last
        if time.monotonic() >= deadline:
            return last
        time.sleep(poll_interval)
