"""Клиент API ЕПГУ (gusmev): заявления, статусы, файлы, справочники."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Union

import httpx

from .auth.base import StaticToken, TokenProvider
from .const import USER_AGENT, Env
from .errors import ApiError, HttpError
from .models import Order, OrderMeta, OrderStatus

TokenSource = Union[TokenProvider, str]


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
            raise HttpError(f"Сетевая ошибка: {exc}", url=url) from exc
        if resp.status_code >= 400:
            raise HttpError(
                f"ЕПГУ вернул ошибку: {resp.text}",
                status_code=resp.status_code,
                body=resp.text,
                url=url,
            )
        return resp

    @staticmethod
    def _json(resp: httpx.Response) -> Any:
        try:
            return resp.json()
        except json.JSONDecodeError as exc:
            raise ApiError(
                f"Не удалось разобрать JSON ответа: {resp.text}",
                status_code=resp.status_code,
                body=resp.text,
                url=str(resp.request.url),
            ) from exc

    # --- заявления ------------------------------------------------------

    def create_order(self, meta: Union[OrderMeta, Dict[str, str]]) -> int:
        """Создать заявление (черновик). Возвращает ``orderId``.

        POST ``/api/gusmev/order``
        """
        payload = meta.to_payload() if isinstance(meta, OrderMeta) else dict(meta)
        resp = self._request("POST", "/api/gusmev/order", json=payload)
        data = self._json(resp)
        order_id = data.get("orderId") if isinstance(data, dict) else None
        if order_id is None:
            raise ApiError(f"В ответе нет orderId: {data}", body=data)
        return int(order_id)

    def order_info(self, order_id: int, meta: Union[OrderMeta, Dict[str, str]]) -> Order:
        """Получить детали и статус заявления.

        POST ``/api/gusmev/order/{orderId}``
        """
        payload = meta.to_payload() if isinstance(meta, OrderMeta) else dict(meta)
        resp = self._request("POST", f"/api/gusmev/order/{order_id}", json=payload)
        return Order.from_response(self._json(resp))

    def cancel_order(self, order_id: int, meta: Union[OrderMeta, Dict[str, str]]) -> Dict[str, Any]:
        """Отменить заявление.

        POST ``/api/gusmev/order/{orderId}/cancel``
        """
        payload = meta.to_payload() if isinstance(meta, OrderMeta) else dict(meta)
        resp = self._request("POST", f"/api/gusmev/order/{order_id}/cancel", json=payload)
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
        files = {
            "meta": (None, json.dumps(meta), "application/json"),
            "file": (archive_name, archive, "application/zip"),
        }
        resp = self._request("POST", "/api/gusmev/push", files=files)
        return self._json(resp)

    def push_chunked(
        self,
        meta: Dict[str, Any],
        archive: bytes,
        *,
        order_id: int,
        chunk: int = 1,
        chunks: int = 1,
        archive_name: str = "piev_epgu.zip",
    ) -> Dict[str, Any]:
        """Отправить документы по частям (для больших комплектов).

        POST ``/api/gusmev/push/chunked``
        """
        files = {
            "meta": (None, json.dumps(meta), "application/json"),
            "file": (archive_name, archive, "application/zip"),
            "orderId": (None, str(order_id)),
            "chunk": (None, str(chunk)),
            "chunks": (None, str(chunks)),
        }
        resp = self._request("POST", "/api/gusmev/push/chunked", files=files)
        return self._json(resp)

    # --- статусы --------------------------------------------------------

    def orders_status(
        self,
        order_ids: List[int],
        *,
        page_num: int = 1,
        page_size: int = 50,
    ) -> List[OrderStatus]:
        """Статусы заявлений по их идентификаторам.

        GET ``/api/gusmev/order/getOrdersStatus/``
        """
        params = {
            "pageNum": page_num,
            "pageSize": page_size,
            "orderIds": ",".join(str(i) for i in order_ids),
        }
        resp = self._request("GET", "/api/gusmev/order/getOrdersStatus/", params=params)
        return self._parse_status_list(self._json(resp))

    def updated_after(
        self,
        updated_after: str,
        *,
        page_num: int = 1,
        page_size: int = 50,
    ) -> List[OrderStatus]:
        """Заявления, обновлённые после указанной даты/времени.

        GET ``/api/gusmev/order/getUpdatedAfter``
        """
        params = {"pageNum": page_num, "pageSize": page_size, "updatedAfter": updated_after}
        resp = self._request("GET", "/api/gusmev/order/getUpdatedAfter", params=params)
        return self._parse_status_list(self._json(resp))

    @staticmethod
    def _parse_status_list(data: Any) -> List[OrderStatus]:
        items: List[Dict[str, Any]] = []
        if isinstance(data, list):
            items = data
        elif isinstance(data, dict):
            for key in ("orders", "items", "content", "data"):
                if isinstance(data.get(key), list):
                    items = data[key]
                    break
        return [OrderStatus.from_dict(i) for i in items if isinstance(i, dict)]

    # --- справочники и файлы -------------------------------------------

    def dictionary(self, code: str) -> Dict[str, Any]:
        """Получить справочник НСИ по коду.

        POST ``/api/nsi/v1/dictionary/{code}``
        """
        resp = self._request("POST", f"/api/nsi/v1/dictionary/{code}")
        return self._json(resp)

    def download_file(
        self,
        object_id: Union[str, int],
        object_type: str,
        *,
        mnemonic: str,
        eservice_code: str,
    ) -> bytes:
        """Скачать файл результата заявления (ZIP). Возвращает байты.

        GET ``/api/gusmev/files/download/{objectId}/{objectType}``
        """
        params = {"mnemonic": mnemonic, "eserviceCode": eservice_code}
        resp = self._request(
            "GET",
            f"/api/gusmev/files/download/{object_id}/{object_type}",
            params=params,
        )
        return resp.content

    # --- управление ресурсами ------------------------------------------

    def close(self) -> None:
        if self._owns_client and self._client is not None:
            self._client.close()
            self._client = None

    def __enter__(self) -> "EpguClient":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()
