import json

from epgu.models import Order, OrderMeta, OrderStatus


def test_order_meta_payload():
    meta = OrderMeta(region="45000000000", service_code="60010153", target_code="-60010153")
    assert meta.to_payload() == {
        "region": "45000000000",
        "serviceCode": "60010153",
        "targetCode": "-60010153",
    }


def test_order_from_response_with_nested_json_string():
    nested = {
        "orderId": 123,
        "orderStatusId": 17,
        "currentStatusHistoryId": 555,
        "orderResponseFiles": [
            {"fileName": "piev_epgu.zip", "link": "/api/x/files/abc123"},
        ],
    }
    data = {"order": json.dumps(nested)}
    order = Order.from_response(data)

    assert order.order_id == 123
    assert order.status_code == 17
    assert order.status_history_id == 555
    assert order.file("piev_epgu.zip").object_type == "abc123"
    assert order.file("missing.zip") is None


def test_order_status_from_dict():
    st = OrderStatus.from_dict({"orderId": "7", "orderStatusId": "2"})
    assert st.order_id == 7
    assert st.status_code == 2
