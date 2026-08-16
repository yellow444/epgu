from datetime import datetime, timedelta, timezone

import pytest

from epgu import Order, OrderArchive, OrderMeta
from epgu.errors import ApiError
from epgu.services import submit_application, submit_goskey
from epgu.services.goskey import (
    GoskeyAttribute,
    IndividualRecipient,
    IndividualSignRequest,
    SigningVariant,
    TransportMode,
)


class FakeClient:
    def __init__(self):
        self.calls = []
        self.orders = []

    def create_order(self, meta):
        self.calls.append(("create", meta))
        return 101

    def push_chunked(self, meta, archive, *, order_id):
        self.calls.append(("chunked", meta, archive, order_id))
        return {"orderId": order_id}

    def push(self, meta, archive):
        self.calls.append(("push", meta, archive))
        return {"orderId": 202}

    def order_info(self, order_id, meta=None):
        self.calls.append(("info", order_id, meta))
        return self.orders.pop(0)


def make_archive():
    return OrderArchive().add_file("req.xml", b"<req/>")


def make_goskey_request(now):
    return IndividualSignRequest(
        variant=SigningVariant.UNEP,
        recipient=IndividualRecipient(snils="000-729-729 38"),
        sign_expiration=now + timedelta(hours=1),
        description="Документы на подпись",
        attributes=(
            GoskeyAttribute("orgName", "ООО Ромашка"),
            GoskeyAttribute("orgINN", "6950199530"),
        ),
    )


def test_submit_chunked_reserves_order_then_uploads():
    client = FakeClient()
    meta = OrderMeta("45000000000", "60010153", "-60010153")

    result = submit_application(client, meta, make_archive())

    assert result.order_id == 101
    assert result.push_response == {"orderId": 101}
    assert [call[0] for call in client.calls] == ["create", "chunked"]
    assert client.calls[1][1] == meta.to_payload()


def test_submit_single_push_does_not_create_redundant_draft():
    client = FakeClient()
    result = submit_application(client, {"serviceCode": "s"}, make_archive(), chunked=False)

    assert result.order_id == 202
    assert [call[0] for call in client.calls] == ["push"]


def test_submit_single_push_requires_response_order_id():
    client = FakeClient()
    client.push = lambda meta, archive: {}
    with pytest.raises(ValueError, match="orderId"):
        submit_application(client, {}, make_archive(), chunked=False)


def test_submit_can_poll_until_nonzero_status(monkeypatch):
    client = FakeClient()
    client.orders = [Order(order_id=101, status_code=0), Order(order_id=101, status_code=2)]
    monkeypatch.setattr("epgu.services.submit.time.sleep", lambda seconds: None)

    result = submit_application(
        client,
        {},
        make_archive(),
        wait=True,
        poll_interval=0.01,
        timeout=1,
    )

    assert result.order.status_code == 2
    assert [call[0] for call in client.calls].count("info") == 2
    assert all(call[2] is None for call in client.calls if call[0] == "info")


@pytest.mark.parametrize(
    "kwargs",
    [
        {"wait": True, "poll_interval": 0},
        {"wait": True, "timeout": -1},
    ],
)
def test_submit_validates_polling_options_before_network(kwargs):
    client = FakeClient()
    with pytest.raises(ValueError):
        submit_application(client, {}, make_archive(), **kwargs)
    assert client.calls == []


def test_submit_goskey_builds_meta_and_uses_direct_push(monkeypatch):
    now = datetime(2026, 8, 12, 12, tzinfo=timezone(timedelta(hours=3)))
    client = FakeClient()
    monkeypatch.setattr(
        "epgu.services.submit.build_signed_archive",
        lambda request, documents, signer: b"signed-zip",
    )

    result = submit_goskey(
        client,
        "36",
        make_goskey_request(now),
        {"document.pdf": b"payload"},
        object(),
        now=now,
    )

    assert result.order_id == 202
    assert result.transport is TransportMode.PUSH
    assert result.archive_size == len(b"signed-zip")
    assert client.calls == [
        (
            "push",
            {
                "region": "36",
                "serviceCode": "10000000374",
                "targetCode": "-10000000374",
            },
            b"signed-zip",
        )
    ]


def test_submit_goskey_uses_existing_order_for_chunked(monkeypatch):
    now = datetime(2026, 8, 12, 12, tzinfo=timezone(timedelta(hours=3)))
    client = FakeClient()
    monkeypatch.setattr(
        "epgu.services.submit.build_signed_archive",
        lambda request, documents, signer: b"signed-zip",
    )

    result = submit_goskey(
        client,
        "36",
        make_goskey_request(now),
        {"document.pdf": b"payload"},
        object(),
        order_id=101,
        now=now,
    )

    assert result.order_id == 101
    assert result.transport is TransportMode.ORDER_CHUNKED
    assert [call[0] for call in client.calls] == ["chunked"]


def test_submit_goskey_reserves_order_when_archive_requires_chunking(monkeypatch):
    now = datetime(2026, 8, 12, 12, tzinfo=timezone(timedelta(hours=3)))
    client = FakeClient()
    monkeypatch.setattr(
        "epgu.services.submit.build_signed_archive",
        lambda request, documents, signer: b"signed-zip",
    )
    monkeypatch.setattr("epgu.services.goskey.MAX_DIRECT_ARCHIVE_BYTES", 1)

    result = submit_goskey(
        client,
        "36",
        make_goskey_request(now),
        {"document.pdf": b"payload"},
        object(),
        now=now,
    )

    assert result.order_id == 101
    assert result.transport is TransportMode.ORDER_CHUNKED
    assert [call[0] for call in client.calls] == ["create", "chunked"]


def test_submit_goskey_rejects_mismatched_chunked_order_id(monkeypatch):
    now = datetime(2026, 8, 12, 12, tzinfo=timezone(timedelta(hours=3)))
    client = FakeClient()
    client.push_chunked = lambda meta, archive, *, order_id: {"orderId": order_id + 1}
    monkeypatch.setattr(
        "epgu.services.submit.build_signed_archive",
        lambda request, documents, signer: b"signed-zip",
    )

    with pytest.raises(ApiError, match="вместо ожидаемого"):
        submit_goskey(
            client,
            "36",
            make_goskey_request(now),
            {"document.pdf": b"payload"},
            object(),
            order_id=101,
            now=now,
        )
