import json

import httpx
import pytest

from epgu import EpguClient, OrderMeta
from epgu.const import TEST
from epgu.errors import HttpError


def make_client(handler):
    http = httpx.Client(transport=httpx.MockTransport(handler))
    return EpguClient("TOKEN", env=TEST, client=http)


def test_create_order():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Bearer TOKEN"
        assert request.url.path == "/api/gusmev/order"
        body = json.loads(request.content)
        assert body == {
            "region": "45000000000",
            "serviceCode": "60010153",
            "targetCode": "-60010153",
        }
        return httpx.Response(200, json={"orderId": 987654})

    epgu = make_client(handler)
    meta = OrderMeta("45000000000", "60010153", "-60010153")
    assert epgu.create_order(meta) == 987654


def test_order_info_parses_nested():
    nested = {"orderId": 5, "orderStatusId": 3, "orderResponseFiles": []}

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/gusmev/order/5"
        return httpx.Response(200, json={"order": json.dumps(nested)})

    epgu = make_client(handler)
    order = epgu.order_info(5, {"region": "r", "serviceCode": "s", "targetCode": "t"})
    assert order.order_id == 5
    assert order.status_code == 3


def test_push_chunked_multipart():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/gusmev/push/chunked"
        content = request.content
        assert b"piev_epgu.zip" in content
        assert b'name="orderId"' in content
        return httpx.Response(200, json={"status": "ok"})

    epgu = make_client(handler)
    res = epgu.push_chunked({"a": 1}, b"ZIPDATA", order_id=5)
    assert res == {"status": "ok"}


def test_orders_status_list():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["orderIds"] == "1,2,3"
        return httpx.Response(200, json=[{"orderId": 1, "orderStatusId": 2}])

    epgu = make_client(handler)
    statuses = epgu.orders_status([1, 2, 3])
    assert statuses[0].order_id == 1
    assert statuses[0].status_code == 2


def test_http_error_raised():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, text="boom")

    epgu = make_client(handler)
    with pytest.raises(HttpError) as exc:
        epgu.dictionary("SOME_CODE")
    assert exc.value.status_code == 500


def test_download_file_returns_bytes():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/gusmev/files/download/10/abc"
        assert request.url.params["mnemonic"] == "piev_epgu.zip"
        return httpx.Response(200, content=b"ZIPBYTES")

    epgu = make_client(handler)
    data = epgu.download_file(10, "abc", mnemonic="piev_epgu.zip", eservice_code="60010153")
    assert data == b"ZIPBYTES"
