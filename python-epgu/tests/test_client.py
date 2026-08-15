import json

import httpx
import pytest

from epgu import EpguClient, OrderMeta
from epgu.const import TEST
from epgu.errors import ApiError, ConfigError, HttpError


def make_client(handler):
    http = httpx.Client(transport=httpx.MockTransport(handler))
    return EpguClient("TOKEN", env=TEST, client=http)


def test_create_order_sends_v114_payload_and_parses_id():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers["Authorization"] == "Bearer TOKEN"
        assert request.url.path == "/api/gusmev/order"
        assert json.loads(request.content) == {
            "region": "45000000000",
            "serviceCode": "60010153",
            "targetCode": "-60010153",
        }
        return httpx.Response(200, json={"orderId": "987654"})

    epgu = make_client(handler)
    meta = OrderMeta("45000000000", "60010153", "-60010153")
    assert epgu.create_order(meta) == 987654


@pytest.mark.parametrize("payload", [{}, {"orderId": 0}, {"orderId": "bad"}])
def test_create_order_rejects_invalid_id(payload):
    epgu = make_client(lambda request: httpx.Response(200, json=payload))
    with pytest.raises(ApiError):
        epgu.create_order({"region": "r", "serviceCode": "s", "targetCode": "t"})


def test_order_info_parses_documented_nested_id_without_meta_body():
    nested = {
        "id": 5,
        "orderStatusId": 3,
        "currentStatusHistoryId": 77,
        "orderResponseFiles": [],
    }

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/gusmev/order/5"
        assert request.content == b""
        return httpx.Response(200, json={"code": "OK", "order": json.dumps(nested)})

    order = make_client(handler).order_info(5)
    assert order.order_id == 5
    assert order.status_code == 3
    assert order.status_history_id == 77


def test_order_info_wraps_malformed_contract_as_api_error():
    epgu = make_client(lambda request: httpx.Response(200, json={"order": "{"}))
    with pytest.raises(ApiError, match="Некорректный ответ"):
        epgu.order_info(5)


def test_cancel_order_accepts_empty_200_response():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/gusmev/order/42/cancel"
        assert request.content == b""
        return httpx.Response(200, content=b"")

    assert make_client(handler).cancel_order(42) == {}


def test_push_validates_response_order_id_and_content_type():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/gusmev/push"
        assert b'filename="piev_epgu.zip"' in request.content
        assert b"application/octet-stream" in request.content
        return httpx.Response(200, json={"orderId": 123})

    result = make_client(handler).push({"serviceCode": "s"}, b"ZIP")
    assert result == {"orderId": 123}


def test_push_rejects_empty_archive_and_missing_response_id():
    epgu = make_client(lambda request: httpx.Response(200, json={"status": "ok"}))
    with pytest.raises(ValueError, match="archive"):
        epgu.push({}, b"")
    with pytest.raises(ApiError, match="orderId"):
        epgu.push({}, b"ZIP")


def test_push_enforces_formal_direct_archive_limit():
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request)
        return httpx.Response(200, json={"orderId": 1})

    epgu = make_client(handler)
    assert epgu.push({}, b"X" * 50_000_000)["orderId"] == 1
    with pytest.raises(ValueError, match="50 000 000"):
        epgu.push({}, b"X" * 50_000_001)
    assert len(calls) == 1


def test_push_chunked_automatically_splits_and_numbers_z001():
    requests = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request.content)
        return httpx.Response(200 if len(requests) == 3 else 206, json={"orderId": 5})

    result = make_client(handler).push_chunked(
        {"serviceCode": "s"},
        b"A" * 5_000_000 + b"B" * 5_000_000 + b"IJ",
        order_id=5,
        chunk_size=5_000_000,
    )

    assert result == {"orderId": 5}
    assert len(requests) == 3
    for index, content in enumerate(requests):
        assert f'filename="piev_epgu.z{index + 1:03d}"'.encode() in content
        assert f'name="chunk"\r\n\r\n{index}'.encode() in content
        assert b'name="chunks"\r\n\r\n3' in content
    assert b"A" * 100 in requests[0]
    assert b"B" * 100 in requests[1]
    assert b"IJ" in requests[2]


def test_push_chunked_requires_206_for_intermediate_parts():
    epgu = make_client(lambda request: httpx.Response(200, json={"orderId": 5}))
    with pytest.raises(HttpError, match="ожидался 206"):
        epgu.push_chunked({}, b"X" * 5_000_001, order_id=5)


def test_push_chunked_single_part_keeps_zip_and_omits_chunk_fields():
    def handler(request: httpx.Request) -> httpx.Response:
        assert b'filename="custom.zip"' in request.content
        assert b'name="chunk"' not in request.content
        assert b'name="chunks"' not in request.content
        return httpx.Response(200, json={"orderId": 7})

    result = make_client(handler).push_chunked({}, b"ZIP", order_id=7, archive_name="custom.zip")
    assert result["orderId"] == 7


@pytest.mark.parametrize(
    ("kwargs", "message"),
    [
        ({"chunk": 0}, "вместе"),
        ({"chunk": -1, "chunks": 2}, "диапазоне"),
        ({"chunk": 2, "chunks": 2}, "диапазоне"),
        ({"chunk": 0, "chunks": 0}, ">= 1"),
    ],
)
def test_push_chunked_validates_manual_chunk(kwargs, message):
    epgu = make_client(lambda request: httpx.Response(200, json={"orderId": 1}))
    with pytest.raises(ValueError, match=message):
        epgu.push_chunked({}, b"ZIP", order_id=1, **kwargs)


@pytest.mark.parametrize("payload", [{}, {"orderId": 6}, {"orderId": "bad"}])
def test_push_chunked_requires_same_response_order_id(payload):
    epgu = make_client(lambda request: httpx.Response(200, json=payload))
    with pytest.raises(ApiError, match="orderId"):
        epgu.push_chunked({}, b"ZIP", order_id=5)


def test_orders_status_parses_v114_page_and_nested_status():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/gusmev/order/getOrdersStatus"
        assert request.url.params["orderIds"] == "1,2,3"
        assert request.url.params["pageNum"] == "0"
        return httpx.Response(
            200,
            json={
                "count": 2,
                "totalCount": 7,
                "content": [
                    {
                        "orderId": 1,
                        "orderSearchStatus": "FOUND",
                        "status": {
                            "statusId": 24,
                            "statusName": "Ошибка отправки",
                            "updated": "2026-01-01T00:00:00.000",
                        },
                    },
                    {"orderId": 2, "orderSearchStatus": "NOT_FOUND", "status": None},
                ],
            },
        )

    page = make_client(handler).orders_status([1, 2, 3])
    assert page.count == 2
    assert page.total_count == 7
    assert page[0].status_code == 24
    assert page[0].search_status == "FOUND"
    assert page[1].status_code is None


def test_updated_after_sends_pagination_and_timestamp():
    def handler(request: httpx.Request) -> httpx.Response:
        assert dict(request.url.params) == {
            "pageNum": "2",
            "pageSize": "10",
            "updatedAfter": "2026-01-01T00:00:00.000+0300",
        }
        return httpx.Response(200, json={"count": 0, "totalCount": 0, "content": []})

    page = make_client(handler).updated_after(
        "2026-01-01T00:00:00.000+0300", page_num=2, page_size=10
    )
    assert len(page) == 0


def test_updated_after_defaults_to_first_zero_based_page():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.params["pageNum"] == "0"
        return httpx.Response(200, json={"count": 0, "totalCount": 0, "content": []})

    make_client(handler).updated_after("2026-01-01T00:00:00.000+0300")


@pytest.mark.parametrize(
    "call",
    [
        lambda client: client.orders_status([]),
        lambda client: client.orders_status([0]),
        lambda client: client.orders_status([1], page_num=-1),
        lambda client: client.updated_after("", page_num=0),
        lambda client: client.updated_after("date", page_size=0),
    ],
)
def test_status_methods_validate_inputs(call):
    with pytest.raises(ValueError):
        call(make_client(lambda request: httpx.Response(500)))


def test_dictionary_sends_v114_filter_and_returns_typed_result():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.raw_path.startswith(b"/api/nsi/v1/dictionary/CODE%2FWITH%20SPACE")
        assert json.loads(request.content) == {
            "treeFiltering": "SUBTREE",
            "parentRefItemValue": "ROOT",
            "pageNum": 0,
            "pageSize": 25,
        }
        return httpx.Response(
            200,
            json={
                "error": {"code": 0, "message": "operation completed"},
                "fieldErrors": [],
                "total": 1,
                "items": [{"value": "1", "title": "One", "isLeaf": True}],
            },
        )

    result = make_client(handler).dictionary(
        "CODE/WITH SPACE",
        tree_filtering="SUBTREE",
        parent_ref_item_value="ROOT",
        page_num=0,
        page_size=25,
    )
    assert result.total == 1
    assert result[0].value == "1"


def test_dictionary_raises_api_error_for_embedded_error_on_http_200():
    epgu = make_client(
        lambda request: httpx.Response(
            200,
            json={
                "error": {"code": 7, "message": "Entity not found"},
                "fieldErrors": [],
                "total": 0,
                "items": [],
            },
        )
    )
    with pytest.raises(ApiError) as exc:
        epgu.dictionary("MISSING")
    assert exc.value.code == "7"
    assert exc.value.status_code == 200


@pytest.mark.parametrize(
    "kwargs",
    [
        {"code": ""},
        {"code": "x", "tree_filtering": "ALL"},
        {"code": "x", "page_num": -1},
        {"code": "x", "page_size": 0},
    ],
)
def test_dictionary_validates_request(kwargs):
    code = kwargs.pop("code")
    with pytest.raises(ValueError):
        make_client(lambda request: httpx.Response(500)).dictionary(code, **kwargs)


def test_nested_json_http_error_is_api_error():
    epgu = make_client(
        lambda request: httpx.Response(
            400,
            json={"error": {"code": "bad_request", "message": "Wrong input"}},
        )
    )
    with pytest.raises(ApiError) as exc:
        epgu.dictionary("CODE")
    assert exc.value.code == "bad_request"
    assert exc.value.status_code == 400
    assert "Wrong input" not in str(exc.value)
    assert exc.value.body["error"]["message"] == "Wrong input"


def test_plain_http_error_and_204_are_not_success():
    with pytest.raises(HttpError) as exc:
        make_client(lambda request: httpx.Response(500, text="boom")).dictionary("CODE")
    assert exc.value.status_code == 500

    with pytest.raises(HttpError) as exc:
        make_client(lambda request: httpx.Response(204)).order_info(1)
    assert exc.value.status_code == 204


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(500, text="SENTINEL-RESPONSE-SECRET"),
        httpx.Response(
            400,
            json={
                "error": {
                    "code": "bad_request",
                    "message": "SENTINEL-RESPONSE-SECRET",
                }
            },
        ),
    ],
)
def test_http_error_messages_do_not_expose_upstream_body(response):
    with pytest.raises(HttpError) as caught:
        make_client(lambda request: response).dictionary("CODE")
    assert "SENTINEL-RESPONSE-SECRET" not in str(caught.value)


def test_download_file_uses_status_history_and_terrabyte_segments():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.raw_path.startswith(
            b"/api/gusmev/files/download/15000910007/%D1%82%D0%B8%D0%BF%203"
        )
        assert request.url.params["mnemonic"] == "req file.xml"
        assert request.url.params["eserviceCode"] == "10000000109"
        return httpx.Response(200, content=b"XML")

    data = make_client(handler).download_file(
        "terrabyte://00/3500308079/req%20file.xml/%D1%82%D0%B8%D0%BF%203",
        status_history_id=15000910007,
        eservice_code="10000000109",
    )
    assert data == b"XML"


def test_download_file_legacy_contract_and_invalid_current_link():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path == "/api/gusmev/files/download/10/2"
        return httpx.Response(200, content=b"ZIP")

    epgu = make_client(handler)
    assert epgu.download_file(10, "2", mnemonic="a.zip", eservice_code="s") == b"ZIP"
    with pytest.raises(ConfigError):
        epgu.download_file("terrabyte://00/123//2", status_history_id=10, eservice_code="s")


def test_order_info_and_cancel_ignore_legacy_meta_and_send_no_body():
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append((request.url.path, request.content))
        if request.url.path.endswith("/cancel"):
            return httpx.Response(200, json={"status": "cancelled"})
        return httpx.Response(200, json={"order": {"id": 9}})

    epgu = make_client(handler)
    meta = {"region": "r", "serviceCode": "s", "targetCode": "t"}
    assert epgu.order_info(9, meta).order_id == 9
    assert epgu.cancel_order(9, meta) == {"status": "cancelled"}
    assert calls == [
        ("/api/gusmev/order/9", b""),
        ("/api/gusmev/order/9/cancel", b""),
    ]


def test_client_wraps_transport_and_success_json_errors():
    def fail(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("offline", request=request)

    with pytest.raises(HttpError, match="Сетевая"):
        make_client(fail).order_info(1)

    epgu = make_client(lambda request: httpx.Response(200, text="not-json"))
    with pytest.raises(ApiError, match="JSON"):
        epgu.order_info(1)


@pytest.mark.parametrize(
    ("handler", "operation"),
    [
        (
            lambda request: httpx.Response(200, text="SENTINEL-RESPONSE-SECRET"),
            lambda client: client.order_info(1),
        ),
        (
            lambda request: httpx.Response(200, json={"unexpected": "SENTINEL-RESPONSE-SECRET"}),
            lambda client: client.create_order(
                {"region": "36", "serviceCode": "s", "targetCode": "t"}
            ),
        ),
        (
            lambda request: httpx.Response(200, json={"unexpected": "SENTINEL-RESPONSE-SECRET"}),
            lambda client: client.push({}, b"ZIP"),
        ),
    ],
)
def test_malformed_success_messages_do_not_expose_response_body(handler, operation):
    with pytest.raises(ApiError) as caught:
        operation(make_client(handler))
    assert "SENTINEL-RESPONSE-SECRET" not in str(caught.value)


def test_client_rejects_invalid_meta_upload_and_download_arguments():
    epgu = make_client(lambda request: httpx.Response(500))
    with pytest.raises(ConfigError, match="метаданных"):
        epgu.create_order(None)
    with pytest.raises(ValueError, match="archive_name"):
        epgu.push({}, b"ZIP", archive_name="")
    with pytest.raises(ValueError, match="order_id"):
        epgu.push_chunked({}, b"ZIP", order_id=0)
    with pytest.raises(ValueError, match="archive"):
        epgu.push_chunked({}, b"", order_id=1)
    with pytest.raises(ValueError, match="chunk_size"):
        epgu.push_chunked({}, b"ZIP", order_id=1, chunk_size=0)
    with pytest.raises(ValueError, match="archive_name"):
        epgu.push_chunked({}, b"ZIP", order_id=1, archive_name="")
    with pytest.raises(ConfigError, match="ссылкой"):
        epgu.download_file(1)
    with pytest.raises(ConfigError, match="status_history_id"):
        epgu.download_file("terrabyte://00/1/a.xml/2", eservice_code="s")
    with pytest.raises(ConfigError, match="eservice_code"):
        epgu.download_file("terrabyte://00/1/a.xml/2", status_history_id=1)
    with pytest.raises(ConfigError, match="mnemonic"):
        epgu.download_file(1, "2", eservice_code="s")
    with pytest.raises(ConfigError, match="eservice_code"):
        epgu.download_file(1, "2", mnemonic="a.xml")


def test_owned_http_client_context_manager_closes_resource():
    epgu = EpguClient("TOKEN", env=TEST)
    http = epgu._http()
    with epgu as same:
        assert same is epgu
    assert http.is_closed
    assert epgu._client is None
