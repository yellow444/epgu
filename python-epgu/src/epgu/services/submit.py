# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025 yellow444 <yellow444@gmail.com>
"""Типовой сценарий подачи заявления «под ключ»."""

from __future__ import annotations

import time
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Mapping, Optional, Union

from ..archive import OrderArchive
from ..client import EpguClient
from ..errors import ApiError
from ..models import Order, OrderMeta
from ..signature.base import Signer
from .goskey import (
    BytesValue,
    DecipherRequest,
    IndividualSignRequest,
    LegalEntitySignRequest,
    TransportMode,
    TreasurySignRequest,
    build_signed_archive,
    select_transport,
    validate_submission_window,
)

GoskeyRequest = Union[
    IndividualSignRequest,
    LegalEntitySignRequest,
    TreasurySignRequest,
    DecipherRequest,
]


@dataclass
class SubmitResult:
    """Итог подачи заявления."""

    order_id: int
    push_response: Dict[str, Any]
    order: Optional[Order] = None


@dataclass(frozen=True)
class GoskeySubmitResult:
    """Итог типизированной подачи комплекта документов в Госключ."""

    order_id: int
    transport: TransportMode
    archive_size: int
    push_response: Dict[str, Any]


def submit_goskey(
    client: EpguClient,
    region: str,
    request: GoskeyRequest,
    documents: Mapping[str, BytesValue],
    signer: Signer,
    *,
    order_id: Optional[int] = None,
    now: Optional[datetime] = None,
) -> GoskeySubmitResult:
    """Проверить, подписать и отправить запрос Госключа одной операцией.

    Capability конкретного запроса определяет ``serviceCode`` и ``targetCode``.
    Для ZIP размером не более 50 000 000 байт без заранее выданного номера
    используется прямой ``/push``. В остальных случаях метод резервирует номер
    (если он не передан) и вызывает ``/push/chunked``.

    Reference-only варианты завершаются ошибкой до подписи и сетевого вызова.
    Временное окно Госключа проверяется после построения архива, непосредственно
    перед отправкой.
    """

    if not isinstance(
        request,
        (IndividualSignRequest, LegalEntitySignRequest, TreasurySignRequest, DecipherRequest),
    ):
        raise TypeError("request должен быть типизированным запросом Госключа")

    capability = request.capability
    capability.require_verified()
    meta = OrderMeta(
        region=region,
        service_code=capability.service_code,
        target_code=capability.target_code,
    )
    expiration = (
        request.expiration if isinstance(request, DecipherRequest) else request.sign_expiration
    )
    validate_submission_window(expiration, now=now)
    archive = build_signed_archive(request, documents, signer)
    # Проверяем повторно после потенциально долгой КЭП-подписи и сборки ZIP.
    validate_submission_window(expiration, now=now)
    decision = select_transport(len(archive), order_id=order_id)
    meta_payload = meta.to_payload()

    submitted_order_id: int
    if decision.mode is TransportMode.PUSH:
        response = client.push(meta_payload, archive)
        submitted_order_id = _response_order_id(response)
    else:
        candidate_order_id = (
            client.create_order(meta) if decision.reserve_order else decision.order_id
        )
        if candidate_order_id is None:  # Defensive guard for future decision variants.
            raise ApiError("Не удалось определить orderId для chunked-отправки")
        submitted_order_id = candidate_order_id
        response = client.push_chunked(
            meta_payload,
            archive,
            order_id=submitted_order_id,
        )
        _response_order_id(response, expected=submitted_order_id)

    return GoskeySubmitResult(
        order_id=submitted_order_id,
        transport=decision.mode,
        archive_size=len(archive),
        push_response=response,
    )


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
    if wait and poll_interval <= 0:
        raise ValueError("poll_interval должен быть положительным")
    if wait and timeout < 0:
        raise ValueError("timeout должен быть >= 0")

    archive_bytes = archive.to_bytes()
    meta_payload = (
        push_meta
        if push_meta is not None
        else (meta.to_payload() if isinstance(meta, OrderMeta) else dict(meta))
    )

    if chunked:
        order_id = client.create_order(meta)
        push_response = client.push_chunked(meta_payload, archive_bytes, order_id=order_id)
    else:
        push_response = client.push(meta_payload, archive_bytes)
        returned_order_id = push_response.get("orderId")
        if returned_order_id is None:
            raise ValueError("Ответ push не содержит корректный orderId")
        try:
            order_id = int(returned_order_id)
        except (TypeError, ValueError) as exc:
            raise ValueError("Ответ push не содержит корректный orderId") from exc
        if order_id <= 0:
            raise ValueError("Ответ push не содержит положительный orderId")

    order: Optional[Order] = None
    if wait:
        order = _wait_for_update(client, order_id, poll_interval=poll_interval, timeout=timeout)

    return SubmitResult(order_id=order_id, push_response=push_response, order=order)


def _response_order_id(
    response: Dict[str, Any],
    *,
    expected: Optional[int] = None,
) -> int:
    value = response.get("orderId") if isinstance(response, dict) else None
    if value is None:
        raise ApiError("Ответ отправки не содержит корректный orderId", body=response)
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ApiError("Ответ отправки не содержит корректный orderId", body=response) from exc
    if parsed <= 0:
        raise ApiError("Ответ отправки не содержит положительный orderId", body=response)
    if expected is not None and parsed != expected:
        raise ApiError(
            "ЕПГУ вернул orderId {0} вместо ожидаемого {1}".format(parsed, expected),
            body=response,
        )
    return parsed


def _wait_for_update(
    client: EpguClient,
    order_id: int,
    *,
    poll_interval: float,
    timeout: float,
) -> Order:
    deadline = time.monotonic() + timeout
    last: Optional[Order] = None
    while True:
        last = client.order_info(order_id)
        # status_code > 0 означает, что ведомство начало обработку.
        if last.status_code:
            return last
        if time.monotonic() >= deadline:
            return last
        time.sleep(min(poll_interval, max(0.0, deadline - time.monotonic())))
