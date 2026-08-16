"""Exact multipart/ZIP contract tests for service-profile submission."""

from __future__ import annotations

import io
import json
import random
import zipfile

import httpx
import pytest
from fastapi.testclient import TestClient

import app as app_module


class RecordingClient:
    """Small async httpx stand-in that preserves outgoing multipart fields."""

    def __init__(self, *, response_order_id: int | None = 42, json_body=None):
        self.calls = []
        self.response_order_id = response_order_id
        self.json_body = json_body

    async def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        files = kwargs.get("files", {})
        current = int(files.get("chunk", (None, "0"))[1])
        total = int(files.get("chunks", (None, "1"))[1])
        status = 200 if current == total - 1 else 206
        body = (
            self.json_body
            if self.json_body is not None
            else ({} if self.response_order_id is None else {"orderId": self.response_order_id})
        )
        return httpx.Response(
            status,
            json=body,
            request=httpx.Request("POST", url),
        )

    async def get(self, url, **kwargs):
        self.calls.append((url, kwargs))
        return httpx.Response(
            200,
            content=b"payload",
            headers={"content-type": "application/pdf"},
            request=httpx.Request("GET", url),
        )

    def stream(self, method, url, **kwargs):
        owner = self

        class StreamContext:
            async def __aenter__(self):
                assert method == "GET"
                return await owner.get(url, **kwargs)

            async def __aexit__(self, *_exc):
                return False

        return StreamContext()


class OrderLifecycleClient:
    """Upstream stand-in for the body-less v1.14 detail/cancel methods."""

    def __init__(self, *, service_code="actual-service", malformed_order=None):
        self.calls = []
        self.service_code = service_code
        self.malformed_order = malformed_order

    async def post(self, url, **kwargs):
        self.calls.append((url, kwargs))
        if url.endswith("/cancel"):
            body = {"status": "cancelled"}
        elif self.malformed_order is not None:
            body = {"order": self.malformed_order}
        else:
            order = {
                "eserviceId": self.service_code,
                "currentStatusHistoryId": 91,
                "orderResponseFiles": [
                    {
                        "link": "https://files.example/result-type",
                        "fileName": "answer.pdf",
                    }
                ],
            }
            body = {"order": json.dumps(order)}
        return httpx.Response(
            200,
            json=body,
            request=httpx.Request("POST", url),
        )


@pytest.fixture()
def executable_generic_profile(monkeypatch):
    """Enable the generic FSSP fixture only inside transport unit tests.

    The shipped catalogue keeps 60010153 reference-only until its applicant
    form can reject demonstration data, while these tests still exercise the
    generic ZIP/chunk implementation itself.
    """
    profile = app_module.services_dict["60010153"]
    monkeypatch.setitem(profile, "status", "verified")
    monkeypatch.setitem(profile, "available", True)
    return profile


@pytest.fixture()
def profile_files(executable_generic_profile):
    root = app_module.XML_ROOT
    return [
        ("files_upload", ("req.xml", (root / "req.xml").read_bytes(), "application/xml")),
        (
            "files_upload",
            ("piev_epgu.xml", (root / "piev_epgu.xml").read_bytes(), "application/xml"),
        ),
    ]


@pytest.fixture()
def meta(executable_generic_profile):
    return {
        "region": "45000000000",
        "serviceCode": "60010153",
        "targetCode": "-60010153",
        "submissionContext": "12345678-1234-5678-1234-567812345678",
        "uiOnly": "must-not-leak",
    }


def _override_client(recording):
    async def dependency():
        yield recording

    app_module.app.dependency_overrides[app_module.get_async_client] = dependency


def _clear_overrides():
    app_module.app.dependency_overrides.clear()


def test_chunked_builds_one_zip_then_sends_zero_based_z001_parts(
    monkeypatch, profile_files, meta
):
    profile = app_module.services_dict["60010153"]
    monkeypatch.setitem(profile["submission"], "chunkSize", 300)
    deterministic_bytes = random.Random(7).randbytes(900)
    uploads = profile_files + [
        ("files_upload", ("evidence.bin", deterministic_bytes, "application/octet-stream"))
    ]
    recording = RecordingClient()
    _override_client(recording)
    try:
        with TestClient(app_module.app) as client:
            response = client.post(
                "/push/chunked",
                data={"meta": json.dumps(meta), "orderId": "42"},
                files=uploads,
            )
    finally:
        _clear_overrides()

    assert response.status_code == 200, response.text
    assert response.json() == {"orderId": 42}
    assert len(recording.calls) > 1

    parts = []
    for index, (url, kwargs) in enumerate(recording.calls):
        assert url.endswith("/api/gusmev/push/chunked")
        assert 0 < kwargs["timeout"] <= app_module.CHUNK_UPLOAD_DEADLINE_SECONDS
        outgoing = kwargs["files"]
        assert outgoing["file"][0] == f"42-archive.z{index + 1:03d}"
        assert int(outgoing["chunk"][1]) == index
        assert int(outgoing["chunks"][1]) == len(recording.calls)
        assert json.loads(outgoing["meta"][1]) == {
            "region": "45000000000",
            "serviceCode": "60010153",
            "targetCode": "-60010153",
        }
        parts.append(outgoing["file"][1])

    with zipfile.ZipFile(io.BytesIO(b"".join(parts))) as archive:
        assert set(archive.namelist()) == {"req.xml", "piev_epgu.xml", "evidence.bin"}
        assert archive.read("evidence.bin") == deterministic_bytes


def test_chunked_single_part_keeps_zip_and_omits_counters(profile_files, meta):
    recording = RecordingClient()
    _override_client(recording)
    try:
        with TestClient(app_module.app) as client:
            response = client.post(
                "/push/chunked",
                data={"meta": json.dumps(meta), "orderId": "42", "chunk": "0", "chunks": "1"},
                files=profile_files,
            )
    finally:
        _clear_overrides()

    assert response.status_code == 200, response.text
    outgoing = recording.calls[0][1]["files"]
    assert outgoing["file"][0] == "42-archive.zip"
    assert "chunk" not in outgoing
    assert "chunks" not in outgoing


def test_push_validates_response_order_id(monkeypatch, profile_files, meta):
    profile = app_module.services_dict["60010153"]
    monkeypatch.setitem(profile["submission"], "mode", "push")
    recording = RecordingClient(response_order_id=None)
    _override_client(recording)
    try:
        with TestClient(app_module.app) as client:
            response = client.post(
                "/push",
                data={"meta": json.dumps(meta)},
                files=profile_files,
            )
    finally:
        _clear_overrides()

    assert response.status_code == 502
    assert "orderId" in response.json()["detail"]
    outgoing = recording.calls[0][1]["files"]
    assert outgoing["file"][0] == "-archive.zip"
    assert outgoing["file"][2] == "application/octet-stream"


def test_order_validates_response_order_id(meta):
    recording = RecordingClient(response_order_id=None)
    _override_client(recording)
    try:
        with TestClient(app_module.app) as client:
            response = client.post("/order", json=meta)
    finally:
        _clear_overrides()

    assert response.status_code == 502
    assert "orderId" in response.json()["detail"]


def test_order_accepts_official_two_digit_region(meta):
    recording = RecordingClient(response_order_id=42)
    _override_client(recording)
    try:
        with TestClient(app_module.app) as client:
            response = client.post("/order", json={**meta, "region": "36"})
    finally:
        _clear_overrides()

    assert response.status_code == 200, response.text
    assert recording.calls[0][1]["json"]["region"] == "36"


@pytest.mark.parametrize(
    "legacy_body",
    [
        None,
        {"region": "36", "serviceCode": "unknown-service", "targetCode": "unknown-target"},
    ],
)
def test_order_details_sends_no_body_and_uses_actual_response_service(legacy_body):
    recording = OrderLifecycleClient(service_code="actual-service")
    _override_client(recording)
    request_kwargs = {} if legacy_body is None else {"json": legacy_body}
    try:
        with TestClient(app_module.app) as client:
            response = client.post("/order/42", **request_kwargs)
    finally:
        _clear_overrides()

    assert response.status_code == 200, response.text
    assert response.json()["fileDetails"][0]["eserviceCode"] == "actual-service"
    url, upstream_kwargs = recording.calls[0]
    assert url.endswith("/api/gusmev/order/42")
    assert "json" not in upstream_kwargs
    assert "content" not in upstream_kwargs
    assert "Content-Type" not in upstream_kwargs["headers"]


@pytest.mark.parametrize(
    "legacy_body",
    [
        None,
        {"region": "36", "serviceCode": "unknown-service", "targetCode": "unknown-target"},
    ],
)
def test_cancel_sends_no_body_and_does_not_validate_legacy_service(legacy_body):
    recording = OrderLifecycleClient()
    _override_client(recording)
    request_kwargs = {} if legacy_body is None else {"json": legacy_body}
    try:
        with TestClient(app_module.app) as client:
            response = client.post("/order/42/cancel", **request_kwargs)
    finally:
        _clear_overrides()

    assert response.status_code == 200, response.text
    url, upstream_kwargs = recording.calls[0]
    assert url.endswith("/api/gusmev/order/42/cancel")
    assert "json" not in upstream_kwargs
    assert "content" not in upstream_kwargs
    assert "Content-Type" not in upstream_kwargs["headers"]


def test_order_details_fail_closed_without_response_service_code():
    recording = OrderLifecycleClient(service_code="")
    _override_client(recording)
    try:
        with TestClient(app_module.app) as client:
            response = client.post("/order/42")
    finally:
        _clear_overrides()

    assert response.status_code == 502
    assert "код услуги" in response.json()["detail"]


def test_malformed_order_details_do_not_reflect_upstream_payload():
    sentinel = "SENSITIVE-UPSTREAM-ORDER"
    recording = OrderLifecycleClient(malformed_order=sentinel)
    _override_client(recording)
    try:
        with TestClient(app_module.app) as client:
            response = client.post("/order/42")
    finally:
        _clear_overrides()

    assert response.status_code == 502
    assert sentinel not in response.text


@pytest.mark.parametrize(
    ("path", "extra_data"),
    [
        ("/push", {}),
        ("/push/chunked", {"orderId": "42"}),
    ],
)
def test_goskey_generator_cannot_use_generic_submission_routes(path, extra_data):
    recording = RecordingClient()
    _override_client(recording)
    goskey_meta = {
        "region": "45000000000",
        "serviceCode": "10000000374",
        "targetCode": "-10000000374",
    }
    try:
        with TestClient(app_module.app) as client:
            response = client.post(
                path,
                data={"meta": json.dumps(goskey_meta), **extra_data},
                files={"files_upload": ("req.xml", b"<request/>", "application/xml")},
            )
    finally:
        _clear_overrides()

    assert response.status_code == 409
    assert "/goskey/submit" in response.json()["detail"]
    assert recording.calls == []


def test_upload_limit_returns_413_without_upstream_call(monkeypatch, profile_files, meta):
    monkeypatch.setattr(app_module, "MAX_UPLOAD_FILE_BYTES", 16)
    monkeypatch.setattr(app_module, "MAX_UPLOAD_TOTAL_BYTES", 32)
    recording = RecordingClient()
    _override_client(recording)
    uploads = profile_files + [
        ("files_upload", ("oversized.bin", b"x" * 17, "application/octet-stream"))
    ]
    try:
        with TestClient(app_module.app) as client:
            response = client.post(
                "/push/chunked",
                data={"meta": json.dumps(meta), "orderId": "42"},
                files=uploads,
            )
    finally:
        _clear_overrides()

    assert response.status_code == 413
    assert recording.calls == []


@pytest.mark.asyncio
async def test_chunk_deadline_maps_transport_timeout_to_504():
    class TimingOutClient:
        async def post(self, *_args, **_kwargs):
            request = httpx.Request("POST", "https://upstream.example/chunk")
            raise httpx.ReadTimeout("late", request=request)

    with pytest.raises(app_module.HTTPException) as caught:
        await app_module._post_chunk_with_deadline(
            TimingOutClient(),
            "https://upstream.example/chunk",
            started_at=app_module.time.monotonic(),
            files={},
            headers={},
        )

    assert caught.value.status_code == 504


def test_upstream_error_mapper_does_not_reflect_url_or_body(caplog):
    request = httpx.Request("POST", "https://upstream.example/path?token=SECRET-TOKEN")
    response = httpx.Response(502, text="PII-RESPONSE-BODY", request=request)
    error = httpx.HTTPStatusError("SECRET-ERROR", request=request, response=response)

    mapped = app_module._upstream_http_failure("contract test", error)

    rendered = str(mapped.detail) + caplog.text
    assert mapped.status_code == 502
    assert "SECRET-TOKEN" not in rendered
    assert "PII-RESPONSE-BODY" not in rendered
    assert "SECRET-ERROR" not in rendered


def test_archive_requires_detached_signature_for_signed_document():
    descriptor = {
        "mediaType": "application/octet-stream",
        "signature": "detached-cades",
    }
    with pytest.raises(app_module.HTTPException, match="подпись"):
        app_module._build_archive([("req.xml", b"payload", descriptor)])

    archive = app_module._build_archive(
        [
            ("req.xml", b"payload", descriptor),
            ("req.xml.sig", b"signature", None),
        ]
    )
    with zipfile.ZipFile(io.BytesIO(archive)) as zipped:
        assert zipped.namelist() == ["req.xml", "req.xml.sig"]


@pytest.mark.parametrize(
    "changes",
    [
        {"region": ""},
        {"region": "Moscow"},
        {"region": "1"},
        {"region": "123456789012"},
        {"targetCode": "wrong"},
        {"serviceCode": "unknown"},
    ],
)
def test_meta_rejected_before_external_side_effect(profile_files, meta, changes):
    invalid = {**meta, **changes}
    recording = RecordingClient()
    _override_client(recording)
    try:
        with TestClient(app_module.app) as client:
            response = client.post(
                "/push/chunked",
                data={"meta": json.dumps(invalid), "orderId": "42"},
                files=profile_files,
            )
    finally:
        _clear_overrides()

    assert response.status_code == 400
    assert recording.calls == []


def test_download_quotes_path_uses_params_and_sanitizes_filename():
    recording = RecordingClient()
    _override_client(recording)
    try:
        with TestClient(app_module.app) as client:
            response = client.post(
                "/download_file/42/type%20segment",
                params={
                    "mnemonic": "folder/report & итог.pdf",
                    "eserviceCode": "service&other=bad",
                },
            )
    finally:
        _clear_overrides()

    assert response.status_code == 200, response.text
    url, kwargs = recording.calls[0]
    assert url.endswith("/files/download/42/type%20segment")
    assert kwargs["params"] == {
        "mnemonic": "folder/report & итог.pdf",
        "eserviceCode": "service&other=bad",
    }
    disposition = response.headers["content-disposition"]
    assert "folder" not in disposition
    assert "%D0%B8%D1%82%D0%BE%D0%B3.pdf" in disposition
    assert response.headers["content-type"].startswith("application/pdf")


def test_download_is_spooled_and_rejects_unknown_length_over_limit(monkeypatch):
    monkeypatch.setattr(app_module, "MAX_DOWNLOAD_BYTES", 4)
    recording = RecordingClient()
    _override_client(recording)
    try:
        with TestClient(app_module.app) as client:
            response = client.post(
                "/download_file/42/result",
                params={"mnemonic": "result.bin", "eserviceCode": "service"},
            )
    finally:
        _clear_overrides()

    assert response.status_code == 413


def test_dictionary_quotes_code_path_segment():
    recording = RecordingClient(json_body={"items": []})
    _override_client(recording)
    try:
        with TestClient(app_module.app) as client:
            response = client.post("/dictionary/code%20with%20space")
    finally:
        _clear_overrides()

    assert response.status_code == 200, response.text
    url, _ = recording.calls[0]
    assert url.endswith("/dictionary/code%20with%20space")


def test_dictionary_application_error_is_sanitized(caplog):
    sentinel = "SENSITIVE-UPSTREAM-DICTIONARY"
    recording = RecordingClient(
        json_body={"error": {"code": "E-42", "message": sentinel}}
    )
    _override_client(recording)
    caplog.clear()
    try:
        with TestClient(app_module.app) as client:
            response = client.post("/dictionary/example")
    finally:
        _clear_overrides()

    assert response.status_code == 502
    assert response.json() == {"detail": "Справочник ЕПГУ вернул ошибку"}
    assert sentinel not in response.text + caplog.text
