import json

import pytest

from epgu.models import (
    DictionaryResult,
    Order,
    OrderFile,
    OrderMeta,
    OrdersPage,
    OrderStatus,
)


def test_order_meta_payload_and_validation():
    meta = OrderMeta(region="45000000000", service_code="60010153", target_code="-60010153")
    assert meta.to_payload() == {
        "region": "45000000000",
        "serviceCode": "60010153",
        "targetCode": "-60010153",
    }
    assert OrderMeta(region="36", service_code="service", target_code="target").region == "36"
    with pytest.raises(ValueError, match="service_code"):
        OrderMeta(region="45000000000", service_code="", target_code="t")
    for invalid_region in ("", "1", "123456789012", "Moscow"):
        with pytest.raises(ValueError, match="OKATO"):
            OrderMeta(region=invalid_region, service_code="service", target_code="target")


def test_order_from_v114_nested_json_preserves_details_and_both_file_groups():
    nested = {
        "id": 3500308079,
        "orderStatusId": 2,
        "orderStatusName": "Заявление получено ведомством",
        "currentStatusHistoryId": 15000910007,
        "updated": "2023-12-13T14:23:11.434+0300",
        "closed": False,
        "currentStatusHistory": {
            "id": 15000910007,
            "statusId": 2,
            "title": "Заявление получено ведомством",
            "cancelAllowed": True,
            "finalStatus": False,
        },
        "orderAttachmentFiles": [
            {
                "id": "file-id",
                "fileName": "req.xml",
                "fileSize": 4875,
                "link": "terrabyte://00/3500308079/req.xml/2",
                "mimeType": "application/xml",
                "hasDigitalSignature": False,
                "type": "REQUEST",
            }
        ],
        "orderResponseFiles": [
            {
                "fileName": "result.xml",
                "link": "terrabyte://00/3500308079/result.xml/3",
            }
        ],
    }
    data = {"code": "OK", "message": None, "messageId": "guid", "order": json.dumps(nested)}

    order = Order.from_response(data)

    assert order.order_id == 3500308079
    assert order.status_code == 2
    assert order.status_name == "Заявление получено ведомством"
    assert order.status_history_id == 15000910007
    assert order.cancel_allowed is True
    assert order.final_status is False
    assert order.message_id == "guid"
    assert len(order.files) == 2
    assert order.attachment_files[0].file_size == 4875
    assert order.attachment_files[0].file_type == "REQUEST"
    assert order.file("result.xml").mnemonic == "result.xml"
    assert order.file("result.xml").object_type == "3"
    assert order.file("missing.xml") is None


def test_order_supports_legacy_id_and_nested_current_status_fallback():
    order = Order.from_response(
        {
            "order": {
                "orderId": "123",
                "currentStatusHistory": {"id": "55", "statusId": "17", "title": "Sent"},
            }
        }
    )
    assert order.order_id == 123
    assert order.status_code == 17
    assert order.status_history_id == 55
    assert order.status_name == "Sent"


@pytest.mark.parametrize(
    "payload",
    [
        {"order": "{"},
        {"order": "[]"},
        {"order": []},
        {"order": {}},
        [],
    ],
)
def test_order_rejects_malformed_or_missing_id(payload):
    with pytest.raises(ValueError):
        Order.from_response(payload)


def test_order_file_decodes_terrabyte_segments_and_rejects_empty_mnemonic():
    file = OrderFile(
        file_name="req file.xml",
        link="terrabyte://00/123/req%20file.xml/%D1%82%D0%B8%D0%BF%203",
    )
    assert file.mnemonic == "req file.xml"
    assert file.object_type == "тип 3"
    invalid = OrderFile(file_name="x", link="terrabyte://00/123//2")
    assert invalid.mnemonic == ""


def test_order_status_parses_nested_and_legacy_shapes():
    nested = OrderStatus.from_dict(
        {
            "orderId": "7",
            "orderSearchStatus": "FOUND",
            "status": {"statusId": "24", "statusName": "Ошибка", "updated": "date"},
        }
    )
    assert nested.order_id == 7
    assert nested.status_code == 24
    assert nested.status_name == "Ошибка"
    assert nested.updated == "date"
    assert nested.search_status == "FOUND"

    legacy = OrderStatus.from_dict({"orderId": 8, "orderStatusId": 2, "statusName": "OK"})
    assert legacy.status_code == 2
    assert legacy.status_name == "OK"


def test_orders_page_preserves_count_total_and_sequence_protocol():
    page = OrdersPage.from_response(
        {
            "count": 1,
            "totalCount": 4,
            "content": [{"orderId": 1, "status": {"statusId": 2}}],
        }
    )
    assert len(page) == 1
    assert page.count == 1
    assert page.total_count == 4
    assert page.content is page.items
    assert [item.order_id for item in page] == [1]
    assert page[:] == page.items

    legacy = OrdersPage.from_response([{"orderId": 2, "statusId": 3}])
    assert legacy.count == legacy.total_count == 1
    with pytest.raises(ValueError):
        OrdersPage.from_response("invalid")


def test_dictionary_result_parses_contract_and_sequence_protocol():
    result = DictionaryResult.from_response(
        {
            "error": {"code": 0, "message": "operation completed"},
            "fieldErrors": [],
            "total": "10",
            "items": [
                {
                    "value": "01",
                    "title": "Item",
                    "parentValue": "root",
                    "isLeaf": True,
                    "children": [{"value": "child"}],
                    "attributes": [{"name": "BIC"}],
                    "attributeValues": {"BIC": "123"},
                }
            ],
        }
    )
    assert result.total == 10
    assert result.error_code == 0
    assert len(result) == 1
    assert result[0].parent_value == "root"
    assert result[0].attribute_values == {"BIC": "123"}
    assert result[:] == result.items

    with pytest.raises(ValueError):
        DictionaryResult.from_response([])
    with pytest.raises(ValueError):
        DictionaryResult.from_response({"items": {}})
