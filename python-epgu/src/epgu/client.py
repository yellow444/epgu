# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (c) 2025 yellow444 <yellow444@gmail.com>
"""Клиент API ЕПГУ (gusmev): заявления, статусы, файлы, справочники."""

from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional, Union
from urllib.parse import quote, unquote, urlparse

import httpx

from .auth.base import StaticToken, TokenProvider
from .const import USER_AGENT, Env
from .errors import ApiError, ConfigError, HttpError
from .models import DictionaryResult, Order, OrderMeta, OrdersPage

TokenSource = Union[TokenProvider, str]
DEFAULT_CHUNK_SIZE = 5_000_000
MAX_CHUNK_SIZE = 50_000_000
MAX_DIRECT_ARCHIVE_SIZE = 50_000_000
CHUNK_UPLOAD_DEADLINE_SECONDS = 300.0


class EpguClient:
    """Высокоуровневый клиент для работы с заявлениями ЕПГУ.

    Args:
        token: источник маркера доступа - либо строка (готовый маркер), либо
            провайдер (:class:`~epgu.auth.OrgTokenProvider` и т.п.),
            который при необходимости сам обновит маркер.
        env: контур (:data:`epgu.const.TEST` / :data:`epgu.const.PROD`).
        client: внешний ``httpx.Client`` (необязательно).
        timeout: таймаут запросов по умолчанию.

    Клиент можно использовать как контекстный менеджер::

        with EpguClient(provider, env=TEST) as epgu:
            order_id = epgu.create_order(meta)
    """

    def __init__(
        self,
        token: TokenSource,
        *,
        env: Env,
        client: Optional[httpx.Client] = None,
        timeout: float = 60.0,
    ) -> None:
        self._token: TokenProvider = StaticToken(token) if isinstance(token, str) else token
        self.env = env
        self._timeout = timeout
        self._client = client
        self._owns_client = client is None

    # --- инфраструктура -------------------------------------------------

    def _http(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=self._timeout, follow_redirects=True)
        return self._client

    @staticmethod
    def _to_order_payload(meta: Union[OrderMeta, Dict[str, str]]) -> Dict[str, str]:
        if isinstance(meta, OrderMeta):
            return meta.to_payload()
        if isinstance(meta, dict):
            return dict(meta)
        raise ConfigError(f"Некорректный тип метаданных: {type(meta)!r}")

    @staticmethod
    def _extract_api_error(response: httpx.Response) -> Union[ApiError, HttpError]:
        content_type = response.headers.get("content-type", "").lower()
        body_text = response.text
        body_payload: Any = body_text
        code = None
        message: Any = None

        if "application/json" in content_type:
            try:
                body_payload = response.json()
            except json.JSONDecodeError:
                pass
            else:
                if isinstance(body_payload, dict):
                    code = body_payload.get("code")
                    message = (
                        body_payload.get("message")
                        or body_payload.get("errorMessage")
                        or body_payload.get("description")
                    )
                    if code is None and isinstance(body_payload.get("error"), dict):
                        nested_error = body_payload["error"]
                        code = nested_error.get("code")
                        message = nested_error.get("message") or message

        if code is None:
            return HttpError(
                "ЕПГУ вернул HTTP-ошибку",
                status_code=response.status_code,
                body=body_payload,
                url=str(response.request.url),
            )

        return ApiError(
            "ЕПГУ вернул ошибку API (код {0})".format(code),
            code=str(code),
            status_code=response.status_code,
            body=body_payload,
            url=str(response.request.url),
        )

    @staticmethod
    def _parse_attachment_link(link: str) -> Dict[str, str]:
        parsed = urlparse(link)
        parts = parsed.path.strip("/").split("/")
        if parsed.scheme.lower() != "terrabyte" or len(parts) < 2 or not parts[-2] or not parts[-1]:
            raise ConfigError(f"Некорректный формат ссылки приложения: {link!r}")
        return {
            "mnemonic": unquote(parts[-2]),
            "object_type": unquote(parts[-1]),
        }

    def _auth_headers(self) -> Dict[str, str]:
        token = self._token.get_token()
        return {
            "Authorization": f"Bearer {token.access_token}",
            "User-Agent": USER_AGENT,
        }

    def _request(self, method: str, path: str, **kwargs: Any) -> httpx.Response:
        url = f"{self.env.epgu}{path}"
        headers = {**self._auth_headers(), **kwargs.pop("headers", {})}
        try:
            resp = self._http().request(method, url, headers=headers, **kwargs)
        except httpx.HTTPError as exc:
            raise HttpError("Сетевая ошибка при обращении к ЕПГУ", url=url) from exc
        # В API ЕПГУ 204 означает, что объект не найден. Считать такой ответ
        # успешным опасно: последующий JSON-парсинг маскирует реальную причину.
        if resp.status_code == 204:
            raise HttpError(
                "ЕПГУ вернул пустой ответ: объект не найден",
                status_code=resp.status_code,
                body=None,
                url=str(resp.request.url),
            )
        if not 200 <= resp.status_code < 300:
            raise self._extract_api_error(resp)
        return resp

    @staticmethod
    def _json(resp: httpx.Response) -> Any:
        try:
            return resp.json()
        except json.JSONDecodeError as exc:
            raise ApiError(
                "Не удалось разобрать JSON ответа ЕПГУ",
                status_code=resp.status_code,
                body=resp.text,
                url=str(resp.request.url),
            ) from exc

    # --- заявления ------------------------------------------------------

    def create_order(self, meta: Union[OrderMeta, Dict[str, str]]) -> int:
        """Создать заявление (черновик). Возвращает ``orderId``.

        POST ``/api/gusmev/order``
        """
        payload = self._to_order_payload(meta)
        resp = self._request("POST", "/api/gusmev/order", json=payload)
        data = self._json(resp)
        order_id = data.get("orderId") if isinstance(data, dict) else None
        if order_id is None:
            raise ApiError("В ответе ЕПГУ нет orderId", body=data)
        try:
            parsed_order_id = int(order_id)
        except (TypeError, ValueError) as exc:
            raise ApiError("Некорректный orderId в ответе ЕПГУ", body=data) from exc
        if parsed_order_id <= 0:
            raise ApiError("Некорректный orderId в ответе ЕПГУ", body=data)
        return parsed_order_id

    def order_info(
        self,
        order_id: int,
        meta: Optional[Union[OrderMeta, Dict[str, str]]] = None,
    ) -> Order:
        """Получить детали и статус заявления.

        POST ``/api/gusmev/order/{orderId}``. Параметр ``meta`` сохранён для
        обратной совместимости и намеренно не отправляется: v1.14 требует
        только идентификатор в path.
        """
        _ = meta
        resp = self._request("POST", f"/api/gusmev/order/{order_id}")
        data = self._json(resp)
        try:
            return Order.from_response(data)
        except ValueError as exc:
            raise ApiError(f"Некорректный ответ деталей заявления: {exc}", body=data) from exc

    def cancel_order(
        self,
        order_id: int,
        meta: Optional[Union[OrderMeta, Dict[str, str]]] = None,
    ) -> Dict[str, Any]:
        """Отменить заявление.

        POST ``/api/gusmev/order/{orderId}/cancel``. Устаревший ``meta``
        принимается, но по контракту v1.14 тело запроса не отправляется.
        """
        _ = meta
        resp = self._request(
            "POST",
            f"/api/gusmev/order/{order_id}/cancel",
        )
        if not resp.content.strip():
            return {}
        return self._json(resp)

    def push(
        self,
        meta: Dict[str, Any],
        archive: bytes,
        *,
        archive_name: str = "piev_epgu.zip",
    ) -> Dict[str, Any]:
        """Отправить комплект документов одним архивом.

        POST ``/api/gusmev/push`` (multipart: ``meta`` + ``file``)
        """
        if not archive:
            raise ValueError("archive не должен быть пустым")
        if len(archive) > MAX_DIRECT_ARCHIVE_SIZE:
            raise ValueError("archive для /push не должен превышать 50 000 000 байт")
        if not archive_name:
            raise ValueError("archive_name не должен быть пустым")
        files = {
            "meta": (None, json.dumps(meta), "application/json"),
            "file": (archive_name, archive, "application/octet-stream"),
        }
        resp = self._request("POST", "/api/gusmev/push", files=files)
        result = self._json(resp)
        returned_order_id = result.get("orderId") if isinstance(result, dict) else None
        if returned_order_id is None:
            raise ApiError("ЕПГУ не вернул корректный orderId", body=result)
        try:
            if int(returned_order_id) <= 0:
                raise ValueError
        except (TypeError, ValueError) as exc:
            raise ApiError("ЕПГУ не вернул корректный orderId", body=result) from exc
        return result

    def push_chunked(
        self,
        meta: Dict[str, Any],
        archive: bytes,
        *,
        order_id: int,
        chunk: Optional[int] = None,
        chunks: Optional[int] = None,
        archive_name: str = "piev_epgu.zip",
        chunk_size: int = DEFAULT_CHUNK_SIZE,
    ) -> Dict[str, Any]:
        """Отправить архив после резервирования номера заявления.

        По умолчанию архив автоматически делится на части по 5 МБ. Поля
        ``chunk``/``chunks`` остаются для совместимости и ручной отправки одной
        заранее подготовленной части. Номер части в форме начинается с нуля,
        а расширение файла — с ``.z001``, как требует контракт ЕПГУ.
        """
        if order_id <= 0:
            raise ValueError("order_id должен быть положительным")
        if not archive:
            raise ValueError("archive не должен быть пустым")
        if not DEFAULT_CHUNK_SIZE <= chunk_size <= MAX_CHUNK_SIZE:
            raise ValueError("chunk_size должен быть от 5 000 000 до 50 000 000 байт")

        if chunk is not None or chunks is not None:
            if chunk is None or chunks is None:
                raise ValueError("chunk и chunks должны передаваться вместе")
            started_at = time.monotonic()
            manual_result = self._push_chunk(
                meta,
                archive,
                order_id=order_id,
                chunk=chunk,
                chunks=chunks,
                archive_name=archive_name,
                timeout=CHUNK_UPLOAD_DEADLINE_SECONDS,
            )
            if time.monotonic() - started_at > CHUNK_UPLOAD_DEADLINE_SECONDS:
                raise HttpError("Отправка частей превысила лимит 5 минут")
            return manual_result

        total = max(1, (len(archive) + chunk_size - 1) // chunk_size)
        started_at = time.monotonic()
        result: Dict[str, Any] = {}
        for current in range(total):
            remaining = CHUNK_UPLOAD_DEADLINE_SECONDS - (time.monotonic() - started_at)
            if remaining <= 0:
                raise HttpError("Отправка частей превысила лимит 5 минут")
            start = current * chunk_size
            result = self._push_chunk(
                meta,
                archive[start : start + chunk_size],
                order_id=order_id,
                chunk=current,
                chunks=total,
                archive_name=archive_name,
                timeout=remaining,
            )
        if time.monotonic() - started_at > CHUNK_UPLOAD_DEADLINE_SECONDS:
            raise HttpError("Отправка частей превысила лимит 5 минут")
        return result

    def _push_chunk(
        self,
        meta: Dict[str, Any],
        data: bytes,
        *,
        order_id: int,
        chunk: int,
        chunks: int,
        archive_name: str,
        timeout: Optional[float] = None,
    ) -> Dict[str, Any]:
        if chunks < 1:
            raise ValueError("chunks должен быть >= 1")
        if chunk < 0 or chunk >= chunks:
            raise ValueError("chunk должен быть в диапазоне [0, chunks)")
        if not data or len(data) > MAX_CHUNK_SIZE:
            raise ValueError("каждая часть должна содержать от 1 до 50 000 000 байт")
        if chunks > 1 and chunk < chunks - 1 and len(data) < DEFAULT_CHUNK_SIZE:
            raise ValueError("непоследняя часть должна быть не меньше 5 000 000 байт")
        if not archive_name:
            raise ValueError("archive_name не должен быть пустым")
        if chunks == 1:
            filename = archive_name
        else:
            archive_base = (
                archive_name[:-4] if archive_name.lower().endswith(".zip") else archive_name
            )
            filename = f"{archive_base}.z{chunk + 1:03d}"
        files = {
            "meta": (None, json.dumps(meta), "application/json"),
            "file": (filename, data, "application/octet-stream"),
            "orderId": (None, str(order_id)),
        }
        if chunks > 1:
            files["chunk"] = (None, str(chunk))
            files["chunks"] = (None, str(chunks))
        request_kwargs: Dict[str, Any] = {"files": files}
        if timeout is not None:
            request_kwargs["timeout"] = timeout
        resp = self._request("POST", "/api/gusmev/push/chunked", **request_kwargs)
        expected_status = 200 if chunk == chunks - 1 else 206
        if resp.status_code != expected_status:
            raise HttpError(
                f"ЕПГУ вернул HTTP {resp.status_code}, ожидался {expected_status}",
                status_code=resp.status_code,
                body=resp.text,
                url=str(resp.request.url),
            )
        result = self._json(resp)
        returned_order_id = result.get("orderId") if isinstance(result, dict) else None
        if returned_order_id is None:
            raise ApiError("ЕПГУ не вернул корректный orderId", body=result)
        try:
            parsed_order_id = int(returned_order_id)
        except (TypeError, ValueError) as exc:
            raise ApiError("ЕПГУ не вернул корректный orderId", body=result) from exc
        if parsed_order_id != order_id:
            raise ApiError(
                f"ЕПГУ вернул другой orderId: {returned_order_id} вместо {order_id}",
                body=result,
            )
        return result

    # --- статусы --------------------------------------------------------

    def orders_status(
        self,
        order_ids: List[int],
        *,
        page_num: int = 0,
        page_size: int = 50,
    ) -> OrdersPage:
        """Статусы заявлений по их идентификаторам.

        GET ``/api/gusmev/order/getOrdersStatus``
        """
        if not order_ids or any(order_id <= 0 for order_id in order_ids):
            raise ValueError("order_ids должен содержать положительные идентификаторы")
        self._validate_pagination(page_num, page_size)
        params = {
            "pageNum": page_num,
            "pageSize": page_size,
            "orderIds": ",".join(str(i) for i in order_ids),
        }
        resp = self._request("GET", "/api/gusmev/order/getOrdersStatus", params=params)
        return OrdersPage.from_response(self._json(resp))

    def updated_after(
        self,
        updated_after: str,
        *,
        page_num: int = 0,
        page_size: int = 50,
    ) -> OrdersPage:
        """Заявления, обновлённые после указанной даты/времени.

        GET ``/api/gusmev/order/getUpdatedAfter``
        """
        if not updated_after:
            raise ValueError("updated_after не должен быть пустым")
        self._validate_pagination(page_num, page_size)
        params = {"pageNum": page_num, "pageSize": page_size, "updatedAfter": updated_after}
        resp = self._request("GET", "/api/gusmev/order/getUpdatedAfter", params=params)
        return OrdersPage.from_response(self._json(resp))

    # --- справочники и файлы -------------------------------------------

    def dictionary(
        self,
        code: str,
        *,
        tree_filtering: str = "ONELEVEL",
        parent_ref_item_value: Optional[str] = None,
        page_num: Optional[int] = None,
        page_size: Optional[int] = None,
    ) -> DictionaryResult:
        """Получить справочник НСИ по коду.

        POST ``/api/nsi/v1/dictionary/{code}``
        """
        if not code:
            raise ValueError("code не должен быть пустым")
        if tree_filtering not in {"ONELEVEL", "SUBTREE"}:
            raise ValueError("tree_filtering должен быть ONELEVEL или SUBTREE")
        if page_num is not None and page_num < 0:
            raise ValueError("page_num должен быть >= 0")
        if page_size is not None and page_size <= 0:
            raise ValueError("page_size должен быть > 0")
        payload: Dict[str, Any] = {"treeFiltering": tree_filtering}
        if parent_ref_item_value is not None:
            payload["parentRefItemValue"] = parent_ref_item_value
        if page_num is not None:
            payload["pageNum"] = page_num
        if page_size is not None:
            payload["pageSize"] = page_size
        encoded_code = quote(code, safe="")
        resp = self._request("POST", f"/api/nsi/v1/dictionary/{encoded_code}", json=payload)
        data = self._json(resp)
        result = DictionaryResult.from_response(data)
        if result.error_code != 0:
            raise ApiError(
                f"ЕПГУ вернул ошибку справочника: {result.error_message}",
                code=str(result.error_code),
                status_code=resp.status_code,
                body=data,
                url=str(resp.request.url),
            )
        return result

    def download_file(
        self,
        object_id: Union[str, int],
        object_type: Optional[str] = None,
        *,
        mnemonic: Optional[str] = None,
        eservice_code: Optional[str] = None,
        status_history_id: Optional[Union[str, int]] = None,
    ) -> bytes:
        """Скачать файл результата заявления (ZIP). Возвращает байты.

        Поддерживаются legacy и современный контракты:

        - Legacy: ``object_type``, ``mnemonic`` и ``eservice_code`` передаются явно.
        - Current v1.14: ``object_id`` — ссылка ``terrabyte://...``, а
          ``status_history_id`` — ``currentStatusHistoryId`` из деталей заявки.
        """
        if object_type is None:
            if not isinstance(object_id, str):
                raise ConfigError("Для нового формата object_id должен быть ссылкой-строкой")
            parsed = self._parse_attachment_link(object_id)
            if status_history_id is None or int(status_history_id) <= 0:
                raise ConfigError(
                    "Для ссылки terrabyte необходимо передать status_history_id "
                    "из Order.currentStatusHistoryId"
                )
            object_id = status_history_id
            object_type = parsed["object_type"]
            if mnemonic is None:
                mnemonic = parsed["mnemonic"]
            else:
                # Если передали mnemonic явно, считаем это override.
                pass
            if eservice_code is None:
                raise ConfigError("Для скачивания необходимо передать eservice_code")

        if mnemonic is None:
            raise ConfigError("Для legacy вызова download_file необходимо явно указать mnemonic")
        if eservice_code is None:
            raise ConfigError(
                "Для legacy вызова download_file необходимо явно указать eservice_code"
            )
        params = {"mnemonic": mnemonic, "eserviceCode": eservice_code}
        encoded_object_id = quote(str(object_id), safe="")
        encoded_object_type = quote(str(object_type), safe="")
        path = f"/api/gusmev/files/download/{encoded_object_id}/{encoded_object_type}"
        resp = self._request("GET", path, params=params)
        return resp.content

    @staticmethod
    def _validate_pagination(page_num: int, page_size: int) -> None:
        if page_num < 0:
            raise ValueError("page_num должен быть >= 0")
        if page_size <= 0:
            raise ValueError("page_size должен быть > 0")

    # --- управление ресурсами ------------------------------------------

    def close(self) -> None:
        """Закрыть созданный библиотекой HTTP-клиент; внешний клиент не закрывается."""
        if self._owns_client and self._client is not None:
            self._client.close()
            self._client = None

    def __enter__(self) -> "EpguClient":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
