"""Четыре метода Госпочты в бэкенде: транспорт, лимиты и разбор ответов."""

from __future__ import annotations

import importlib
import time
from datetime import datetime, timedelta, timezone

import httpx
import pytest
from fastapi.testclient import TestClient

import app as app_module

MSK = timezone(timedelta(hours=3))
THREAD = "6c7a5efd-2a8c-11f0-8080-808080808080"
MESSAGE = "91160bbb-f997-11ef-8080-808080808080"
ATTACHMENT = "61d94a0a-66ce-11ef-8080-808080808080"
TASK = "11971e70-a8ec-11f0-84e4-c322de0b8c44"


class Upstream:
    """Заглушка ЕПГУ: помнит вызовы и отдаёт заранее заданные ответы."""

    def __init__(self, *, post=None, get=None):
        self.calls = []
        self._post = post or (lambda url, **kwargs: httpx.Response(200, json={"searchTaskUuid": TASK}))
        self._get = get or (lambda url, **kwargs: httpx.Response(200, json={"searchTaskStatus": "PROCESSING"}))

    async def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self._respond(self._post(url, **kwargs), "POST", url)

    async def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return self._respond(self._get(url, **kwargs), "GET", url)

    def stream(self, method, url, **kwargs):
        owner = self
        owner.calls.append((url, kwargs))
        response = owner._respond(owner._get(url, **kwargs), method, url)

        class StreamContext:
            async def __aenter__(self):
                return response

            async def __aexit__(self, *exc):
                return False

        return StreamContext()

    @staticmethod
    def _respond(response, method, url):
        response.request = httpx.Request(method, url)
        return response


def _override(upstream):
    async def dependency():
        yield upstream

    app_module.app.dependency_overrides[app_module.get_async_client] = dependency


@pytest.fixture(autouse=True)
def clean_overrides():
    yield
    app_module.app.dependency_overrides.clear()


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("GEPS_QUOTA_FILE", str(tmp_path / "geps-quota.json"))

    import geps_quota

    importlib.reload(geps_quota)
    monkeypatch.setattr(app_module, "geps_quota", geps_quota)
    # Старт приложения перечитывает хранилище сертификатов и гасит сессию.
    monkeypatch.setattr(app_module, "load_certificates", lambda: [])
    with TestClient(app_module.app) as value:
        monkeypatch.setattr(app_module, "ACCESS_TKN_ESIA", "test-bearer")
        monkeypatch.setattr(app_module, "ACCESS_TKN_EXP", int(time.time()) + 3600)
        value.quota = geps_quota
        yield value


def yesterday():
    end = datetime.now(MSK).replace(microsecond=0) - timedelta(hours=2)
    return {
        "startDateTime": (end - timedelta(days=1)).isoformat(),
        "endDateTime": end.isoformat(),
        "statusFilter": "ANY",
    }


# --- заказ списка ------------------------------------------------------


def test_search_orders_the_list_and_reports_remaining_attempts(client):
    upstream = Upstream()
    _override(upstream)

    response = client.post("/geps/search", json=yesterday())

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["searchTaskUuid"] == TASK
    assert body["attemptsLeft"] == 4
    assert body["quota"]["limits"]["search"]["limit"] == 5

    url, kwargs = upstream.calls[0]
    assert url.endswith("/api/gusmev/proxy/geps-api-ext/api/messages/v1/search")
    assert kwargs["headers"]["Authorization"] == "Bearer test-bearer"
    assert set(kwargs["json"]) == {"startDateTime", "endDateTime", "statusFilter"}


def test_search_refuses_without_access_token(client, monkeypatch):
    monkeypatch.setattr(app_module, "ACCESS_TKN_ESIA", "")
    upstream = Upstream()
    _override(upstream)

    assert client.post("/geps/search", json=yesterday()).status_code == 401
    assert upstream.calls == []


def test_search_checks_the_range_before_spending_an_attempt(client):
    """Период больше суток отклоняется у нас: заказов всего пять."""
    upstream = Upstream()
    _override(upstream)
    window = yesterday()
    window["startDateTime"] = (
        datetime.fromisoformat(window["endDateTime"]) - timedelta(days=3)
    ).isoformat()

    response = client.post("/geps/search", json=window)

    assert response.status_code == 422
    assert "суток" in response.json()["detail"].lower()
    assert upstream.calls == []
    assert client.quota.used("search") == 0


def test_search_refuses_when_the_daily_quota_is_gone(client):
    upstream = Upstream()
    _override(upstream)

    for _ in range(5):
        assert client.post("/geps/search", json=yesterday()).status_code == 200

    response = client.post("/geps/search", json=yesterday())
    assert response.status_code == 429
    assert "лимит" in response.json()["detail"].lower()
    # Шестого обращения к ЕПГУ не было.
    assert len(upstream.calls) == 5


def test_attempt_is_spent_even_when_the_upstream_fails(client):
    """Сервер расходует попытку в любом случае, значит и мы должны."""

    def failing(url, **kwargs):
        return httpx.Response(500, json={"code": "internal", "message": "boom"})

    _override(Upstream(post=failing))
    assert client.post("/geps/search", json=yesterday()).status_code == 500
    assert client.quota.used("search") == 1


def test_missing_task_uuid_is_reported_as_upstream_error(client):
    _override(Upstream(post=lambda url, **kwargs: httpx.Response(200, json={})))
    response = client.post("/geps/search", json=yesterday())
    assert response.status_code == 502
    assert "searchTaskUuid" in response.json()["detail"]


# --- получение списка --------------------------------------------------


def test_result_returns_not_ready_without_pretending_it_is_empty(client):
    _override(Upstream(get=lambda url, **kwargs: httpx.Response(200, json={"searchTaskStatus": "SEARCH"})))

    body = client.get(f"/geps/search/{TASK}").json()

    assert body["status"] == "SEARCH"
    assert body["ready"] is False
    assert body["messages"] == []


def test_result_maps_the_list_to_our_field_names(client):
    payload = {
        "searchTaskStatus": "COMPLETED",
        "offset": 0,
        "limit": 100,
        "total": 1,
        "messageList": [
            {
                "threadUuid": THREAD,
                "messageUuid": MESSAGE,
                "feedTitle": "ФССП",
                "feedSubtitle": "Извещение",
                "isRead": False,
                "createDate": "2026-08-15T10:20:00.000+03:00",
            }
        ],
    }
    upstream = Upstream(get=lambda url, **kwargs: httpx.Response(200, json=payload))
    _override(upstream)

    body = client.get(f"/geps/search/{TASK}", params={"offset": 0, "limit": 100}).json()

    assert body["ready"] is True
    assert body["total"] == 1
    assert body["messages"][0]["sender"] == "ФССП"
    assert body["messages"][0]["subject"] == "Извещение"
    assert body["messages"][0]["isRead"] is False
    assert body["attemptsLeft"] == 14

    _, kwargs = upstream.calls[0]
    assert kwargs["params"] == {"offset": 0, "limit": 100}


def test_result_rejects_a_task_id_that_is_not_a_uuid(client):
    upstream = Upstream()
    _override(upstream)

    response = client.get("/geps/search/not-a-uuid")

    assert response.status_code == 422
    assert upstream.calls == []
    # Отказ до обращения к ЕПГУ, значит и попытка не потрачена.
    assert client.quota.used("result") == 0


def test_traversal_in_the_task_id_never_reaches_the_upstream(client):
    upstream = Upstream()
    _override(upstream)

    assert client.get("/geps/search/..%2F..%2Fsecret").status_code == 404
    assert upstream.calls == []


def test_result_quota_is_separate_from_search(client):
    _override(Upstream())
    client.post("/geps/search", json=yesterday())
    client.get(f"/geps/search/{TASK}")

    quota = client.get("/geps/quota").json()
    assert quota["limits"]["search"]["used"] == 1
    assert quota["limits"]["result"]["used"] == 1
    assert quota["limits"]["result"]["remaining"] == 14


# --- карточка ----------------------------------------------------------


def test_message_returns_card_with_attachments_and_statuses(client):
    payload = {
        "threadUuid": THREAD,
        "messageUuid": MESSAGE,
        "text": "<div>Извещение</div>",
        "isRead": True,
        "createDate": "2026-08-15T10:20:00.000+03:00",
        "params": {"feed_title": "ФССП", "feed_subtitle": "Извещение", "uin": 42},
        "attachmentList": [
            {
                "messageUuid": MESSAGE,
                "attachmentUuid": ATTACHMENT,
                "fileName": "postanovlenie.pdf",
                "fileSize": 100,
                "mimeType": "application/pdf",
                "signed": True,
                "statusMnemonic": "READY",
                "statusDescription": "Доступен",
            },
            {
                "messageUuid": MESSAGE,
                "attachmentUuid": ATTACHMENT,
                "fileName": "udalen.pdf",
                "mimeType": "application/pdf",
                "signed": False,
                "statusMnemonic": "DELETED",
                "statusDescription": "Удалён",
            },
        ],
        "statusList": [
            {"mnemonic": "READ", "description": "Прочитано", "createDate": "2026-08-15T11:00:00+03:00"}
        ],
    }
    upstream = Upstream(get=lambda url, **kwargs: httpx.Response(200, json=payload))
    _override(upstream)

    body = client.get(f"/geps/message/{THREAD}/{MESSAGE}").json()

    assert body["sender"] == "ФССП"
    assert body["html"] == "<div>Извещение</div>"
    assert body["params"]["uin"] == "42"
    assert body["attachments"][0]["downloadable"] is True
    assert body["attachments"][1]["downloadable"] is False
    assert body["statuses"][0]["mnemonic"] == "READ"
    # Карточки лимитом не ограничены, счётчики не трогаем.
    assert client.quota.used("result") == 0


def test_message_rejects_bad_identifiers(client):
    upstream = Upstream()
    _override(upstream)

    assert client.get(f"/geps/message/{THREAD}/nope").status_code == 422
    assert upstream.calls == []


def test_missing_role_is_explained(client):
    _override(Upstream(get=lambda url, **kwargs: httpx.Response(403, json={"code": "forbidden"})))

    response = client.get(f"/geps/message/{THREAD}/{MESSAGE}")

    assert response.status_code == 403
    assert "Руководитель организации" in response.json()["detail"]


def test_expired_result_is_explained(client):
    _override(Upstream(get=lambda url, **kwargs: httpx.Response(404, json={"code": "not-found"})))

    response = client.get(f"/geps/search/{TASK}")

    assert response.status_code == 404
    assert "семи дней" in response.json()["detail"]


# --- вложения ----------------------------------------------------------


def attachment_response(url, **kwargs):
    return httpx.Response(
        200,
        content=b"%PDF-1.4 body",
        headers={
            "content-type": "application/pdf",
            "content-disposition": 'attachment; filename="../../etc/passwd"',
        },
    )


def test_attachment_is_streamed_and_the_name_is_cleaned(client):
    upstream = Upstream(get=attachment_response)
    _override(upstream)

    response = client.get(f"/geps/attachment/{MESSAGE}/{ATTACHMENT}/file")

    assert response.status_code == 200
    assert response.content == b"%PDF-1.4 body"
    assert response.headers["content-type"].startswith("application/pdf")
    # Путь из чужого заголовка не должен доехать до диска.
    assert "passwd" in response.headers["content-disposition"]
    assert ".." not in response.headers["content-disposition"]

    url, _ = upstream.calls[0]
    assert url.endswith(f"/attachment/{MESSAGE}/{ATTACHMENT}/file")


def test_attachment_signature_uses_its_own_path(client):
    upstream = Upstream(
        get=lambda url, **kwargs: httpx.Response(
            200, content=b"SIG", headers={"content-type": "application/pkcs7-signature"}
        )
    )
    _override(upstream)

    response = client.get(f"/geps/attachment/{MESSAGE}/{ATTACHMENT}/sig")

    assert response.status_code == 200
    assert response.content == b"SIG"
    assert upstream.calls[0][0].endswith("/sig")


def test_attachment_rejects_unknown_file_type(client):
    upstream = Upstream()
    _override(upstream)

    assert client.get(f"/geps/attachment/{MESSAGE}/{ATTACHMENT}/everything").status_code == 422
    assert upstream.calls == []


def test_oversized_attachment_is_refused(client, monkeypatch):
    monkeypatch.setattr(app_module, "MAX_DOWNLOAD_BYTES", 4)
    _override(Upstream(get=attachment_response))

    assert client.get(f"/geps/attachment/{MESSAGE}/{ATTACHMENT}/file").status_code == 413
