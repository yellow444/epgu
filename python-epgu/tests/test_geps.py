"""Госпочта (ГЭПС): четыре сервиса и ограничения из спецификации."""

import json
from datetime import datetime, timedelta, timezone

import httpx
import pytest

from epgu import EpguClient, geps
from epgu.const import TEST
from epgu.errors import ApiError, ConfigError, ValidationError

MSK = timezone(timedelta(hours=3))
NOW = datetime(2026, 8, 16, 12, 0, tzinfo=MSK)
THREAD = "6c7a5efd-2a8c-11f0-8080-808080808080"
MESSAGE = "91160bbb-f997-11ef-8080-808080808080"
ATTACHMENT = "61d94a0a-66ce-11ef-8080-808080808080"
TASK = "11971e70-a8ec-11f0-84e4-c322de0b8c44"


def make_client(handler):
    http = httpx.Client(transport=httpx.MockTransport(handler))
    return EpguClient("TOKEN", env=TEST, client=http)


def day_before(end=NOW):
    return geps.SearchRange(start=end - timedelta(days=1), end=end)


# --- заказ списка ------------------------------------------------------


def test_search_sends_documented_payload_and_returns_task():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.method == "POST"
        assert request.url.path == "/api/gusmev/proxy/geps-api-ext/api/messages/v1/search"
        assert request.headers["Authorization"] == "Bearer TOKEN"
        body = json.loads(request.content)
        assert set(body) == {"startDateTime", "endDateTime", "statusFilter"}
        assert body["statusFilter"] == "ANY"
        assert body["startDateTime"].endswith("+03:00")
        return httpx.Response(200, json={"searchTaskUuid": TASK})

    assert make_client(handler).geps_search(day_before(), now=NOW) == TASK


def test_search_requires_task_uuid_in_response():
    client = make_client(lambda request: httpx.Response(200, json={}))
    with pytest.raises(ApiError):
        client.geps_search(day_before(), now=NOW)


def test_range_longer_than_a_day_is_refused_before_the_request():
    """Отказ на нашей стороне: заказов всего пять в сутки."""
    with pytest.raises(ValidationError):
        geps.SearchRange(start=NOW - timedelta(days=2), end=NOW)


def test_range_must_be_ordered_and_timezone_aware():
    with pytest.raises(ValidationError):
        geps.SearchRange(start=NOW, end=NOW - timedelta(hours=1))
    with pytest.raises(ValidationError):
        geps.SearchRange(start=NOW.replace(tzinfo=None), end=NOW)


def test_depth_and_future_are_checked_against_now():
    old = geps.SearchRange(start=NOW - timedelta(days=40), end=NOW - timedelta(days=39))
    with pytest.raises(ValidationError):
        old.validate_against(NOW)

    future = geps.SearchRange(start=NOW, end=NOW + timedelta(hours=1))
    with pytest.raises(ValidationError):
        future.validate_against(NOW)


def test_suggested_range_is_a_valid_day():
    window = geps.suggested_range(NOW)
    window.validate_against(NOW)
    assert window.end - window.start == geps.MAX_RANGE
    assert window.status is geps.StatusFilter.ANY


def test_search_never_leaves_the_range_unchecked():
    """Проверка обязана сработать и тогда, когда now не передали."""
    calls = []
    client = make_client(
        lambda request: calls.append(request) or httpx.Response(200, json={"searchTaskUuid": TASK})
    )
    stale = geps.SearchRange(start=NOW - timedelta(days=40), end=NOW - timedelta(days=39))
    with pytest.raises(ValidationError):
        client.geps_search(stale)
    assert calls == []


# --- получение готового списка -----------------------------------------


def test_result_reports_not_ready_without_failing():
    client = make_client(
        lambda request: httpx.Response(200, json={"searchTaskStatus": "PROCESSING"})
    )
    page = client.geps_search_result(TASK)

    assert page.status is geps.SearchTaskStatus.PROCESSING
    assert page.ready is False
    assert page.messages == ()


def test_result_parses_documented_list():
    payload = {
        "searchTaskStatus": "COMPLETED",
        "offset": 0,
        "limit": 100,
        "total": 2,
        "messageList": [
            {
                "threadUuid": THREAD,
                "messageUuid": MESSAGE,
                "feedTitle": "ФССП",
                "feedSubtitle": "Извещение",
                "isRead": False,
                "createDate": "2026-08-15T10:20:00.000+03:00",
            },
            {
                "threadUuid": THREAD,
                "messageUuid": ATTACHMENT,
                "feedTitle": "МВД",
                "feedSubtitle": "Штраф оплачен",
                "isRead": True,
                "createDate": "не дата",
            },
        ],
    }

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/search/" + TASK)
        assert dict(request.url.params) == {"offset": "10", "limit": "100"}
        return httpx.Response(200, json=payload)

    page = make_client(handler).geps_search_result(TASK, offset=10, limit=100)

    assert page.ready is True
    assert page.total == 2
    assert page.messages[0].feed_title == "ФССП"
    assert page.messages[0].is_read is False
    assert page.messages[0].create_date.hour == 10
    # Непонятная дата не должна ронять весь список.
    assert page.messages[1].create_date is None


def test_result_rejects_unknown_task_status():
    client = make_client(
        lambda request: httpx.Response(200, json={"searchTaskStatus": "СЮРПРИЗ"})
    )
    with pytest.raises(ValidationError):
        client.geps_search_result(TASK)


@pytest.mark.parametrize("limit", [0, geps.MAX_PAGE_SIZE + 1])
def test_page_size_limits_are_enforced(limit):
    client = make_client(lambda request: httpx.Response(200, json={}))
    with pytest.raises(ValidationError):
        client.geps_search_result(TASK, limit=limit)


def test_task_uuid_is_validated_before_the_request():
    calls = []
    client = make_client(
        lambda request: calls.append(request) or httpx.Response(200, json={})
    )
    with pytest.raises(ValidationError):
        client.geps_search_result("../../secret")
    assert calls == []


# --- карточка уведомления ----------------------------------------------


def test_message_parses_card_with_attachments_and_statuses():
    payload = {
        "threadUuid": THREAD,
        "messageUuid": MESSAGE,
        "text": "<div class=\"mail-body-content\">Извещение</div>",
        "isRead": True,
        "createDate": "2026-08-15T10:20:00.000+03:00",
        "params": {
            "feed_title": "ФССП",
            "feed_subtitle": "Извещение о возбуждении",
            "uin": "1234567890",
        },
        "attachmentList": [
            {
                "messageUuid": MESSAGE,
                "attachmentUuid": ATTACHMENT,
                "fileName": "postanovlenie.pdf",
                "fileSize": 12345,
                "mimeType": "application/pdf",
                "signed": True,
                "statusMnemonic": "READY",
                "statusDescription": "Файл доступен",
            },
            {
                "messageUuid": MESSAGE,
                "attachmentUuid": ATTACHMENT,
                "fileName": "staroe.pdf",
                "mimeType": "application/pdf",
                "signed": False,
                "statusMnemonic": "DELETED",
                "statusDescription": "Файл удалён",
            },
        ],
        "statusList": [
            {
                "mnemonic": "READ",
                "description": "Прочитано",
                "originatorUserName": "Иванов И.И.",
                "createDate": "2026-08-15T11:00:00.000+03:00",
            }
        ],
    }

    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/message/{0}/{1}".format(THREAD, MESSAGE))
        return httpx.Response(200, json=payload)

    card = make_client(handler).geps_message(THREAD, MESSAGE)

    assert card.sender == "ФССП"
    assert card.subject == "Извещение о возбуждении"
    assert card.params["uin"] == "1234567890"
    assert card.attachments[0].downloadable is True
    assert card.attachments[0].signed is True
    assert card.attachments[0].file_size == 12345
    # Удалённое вложение качать нечего, и это видно без похода за файлом.
    assert card.attachments[1].downloadable is False
    assert card.attachments[1].file_size is None
    assert card.statuses[0].originator == "Иванов И.И."


def test_message_uuids_are_validated():
    calls = []
    client = make_client(
        lambda request: calls.append(request) or httpx.Response(200, json={})
    )
    with pytest.raises(ValidationError):
        client.geps_message(THREAD, "не-uuid")
    assert calls == []


# --- вложения ------------------------------------------------------------


def test_attachment_downloads_file_and_takes_name_from_headers():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith(
            "/attachment/{0}/{1}/file".format(MESSAGE, ATTACHMENT)
        )
        return httpx.Response(
            200,
            content=b"%PDF-1.4 ...",
            headers={
                "content-type": "application/pdf",
                "content-disposition": 'attachment; filename="postanovlenie.pdf"',
            },
        )

    downloaded = make_client(handler).geps_attachment(MESSAGE, ATTACHMENT)

    assert downloaded.content.startswith(b"%PDF")
    assert downloaded.file_name == "postanovlenie.pdf"
    assert downloaded.mime_type == "application/pdf"
    assert len(downloaded) == 12


def test_attachment_signature_uses_sig_path():
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.url.path.endswith("/sig")
        return httpx.Response(
            200,
            content=b"SIGNATURE",
            headers={"content-type": "application/pkcs7-signature"},
        )

    signature = make_client(handler).geps_attachment(
        MESSAGE, ATTACHMENT, file_type=geps.FileType.SIGNATURE
    )
    assert signature.content == b"SIGNATURE"


@pytest.mark.parametrize(
    "disposition, expected",
    [
        ('attachment; filename="../../etc/passwd"', "passwd"),
        ("attachment; filename=C:\\\\windows\\\\system32\\\\evil.dll", "evil.dll"),
        ("attachment; filename*=UTF-8''%D0%B0%D0%BA%D1%82.pdf", "акт.pdf"),
        ("attachment; filename=\"\"", "attachment"),
        ("", "attachment"),
    ],
)
def test_attachment_name_is_cleaned_up(disposition, expected):
    """Имя файла приходит снаружи, а файл потом ложится на диск."""
    headers = {"content-type": "application/pdf"}
    if disposition:
        headers["content-disposition"] = disposition
    client = make_client(
        lambda request: httpx.Response(200, content=b"x", headers=headers)
    )
    assert client.geps_attachment(MESSAGE, ATTACHMENT).file_name == expected


def test_unknown_file_type_is_refused():
    with pytest.raises(ConfigError):
        geps.attachment_path(MESSAGE, ATTACHMENT, "everything")


# --- ошибки сервиса ------------------------------------------------------


def test_service_error_is_raised_with_its_code():
    client = make_client(
        lambda request: httpx.Response(
            422,
            json={
                "code": "search-messages.range.exceeded",
                "message": "range longer than one day",
            },
        )
    )
    with pytest.raises(ApiError) as failure:
        client.geps_search(day_before(), now=NOW)
    assert failure.value.code == "search-messages.range.exceeded"


def test_daily_limits_match_the_specification():
    assert geps.daily_limit("search") == 5
    assert geps.daily_limit("result") == 15
    with pytest.raises(ConfigError):
        geps.daily_limit("attachment")
