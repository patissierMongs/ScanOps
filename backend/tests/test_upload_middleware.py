"""ASGI upload body limit rejects declared and chunked oversized requests early."""
from __future__ import annotations

import asyncio

from scanops import uploads


def _scope(headers=(), path="/api/scans/import"):
    return {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": "POST",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode(),
        "query_string": b"",
        "headers": list(headers),
        "client": ("127.0.0.1", 1),
        "server": ("test", 80),
    }


def test_declared_oversized_body_is_rejected_without_reading(monkeypatch):
    monkeypatch.setattr(uploads.get_settings(), "upload_max_bytes", 10)
    monkeypatch.setattr(uploads, "MULTIPART_OVERHEAD_BYTES", 0)
    receive_called = False
    sent = []

    async def app(scope, receive, send):
        raise AssertionError("downstream app must not run")

    async def receive():
        nonlocal receive_called
        receive_called = True
        return {"type": "http.request", "body": b"", "more_body": False}

    async def send(message):
        sent.append(message)

    asyncio.run(uploads.UploadBodyLimitMiddleware(app)(
        _scope([(b"content-length", b"11")]), receive, send,
    ))

    assert receive_called is False
    assert sent[0]["status"] == 413


def test_chunked_oversized_body_stops_before_downstream_finishes(monkeypatch):
    monkeypatch.setattr(uploads.get_settings(), "upload_max_bytes", 10)
    monkeypatch.setattr(uploads, "MULTIPART_OVERHEAD_BYTES", 0)
    messages = iter([
        {"type": "http.request", "body": b"123456", "more_body": True},
        {"type": "http.request", "body": b"789012", "more_body": False},
    ])
    downstream_finished = False
    sent = []

    async def app(scope, receive, send):
        nonlocal downstream_finished
        while (message := await receive()).get("more_body", False):
            pass
        downstream_finished = True

    async def receive():
        return next(messages)

    async def send(message):
        sent.append(message)

    asyncio.run(uploads.UploadBodyLimitMiddleware(app)(_scope(), receive, send))

    assert downstream_finished is False
    assert sent[0]["status"] == 413


def test_bundle_rejects_oversized_part_before_rest_of_request_is_read(monkeypatch):
    monkeypatch.setattr(uploads.get_settings(), "upload_max_bytes", 10)
    monkeypatch.setattr(uploads.get_settings(), "upload_bundle_max_bytes", 1000)
    monkeypatch.setattr(uploads, "MULTIPART_OVERHEAD_BYTES", 0)
    # A semicolon inside a quoted boundary is valid and must not disable streaming limits.
    boundary = b"scan;ops-boundary"
    first_chunk = (
        b"--" + boundary
        + b'\r\nContent-Disposition: form-data; name="files"; filename="large.xml"'
        + b"\r\nContent-Type: application/xml\r\n\r\n"
        + b"x" * 64
    )
    second_chunk = b"\r\n--" + boundary + b"--\r\n"
    messages = iter([
        {"type": "http.request", "body": first_chunk, "more_body": True},
        {"type": "http.request", "body": second_chunk, "more_body": False},
    ])
    receive_count = 0
    downstream_finished = False
    sent = []

    async def app(scope, receive, send):
        nonlocal downstream_finished
        while (message := await receive()).get("more_body", False):
            pass
        downstream_finished = True

    async def receive():
        nonlocal receive_count
        receive_count += 1
        return next(messages)

    async def send(message):
        sent.append(message)

    headers = [(b"content-type", b'multipart/form-data; boundary="scan;ops-boundary"')]
    asyncio.run(uploads.UploadBodyLimitMiddleware(app)(
        _scope(headers, path="/api/scans/import-bundle"), receive, send,
    ))

    assert receive_count == 1
    assert downstream_finished is False
    assert sent[0]["status"] == 413


def test_bundle_accepts_part_and_total_at_exact_boundaries(monkeypatch):
    monkeypatch.setattr(uploads.get_settings(), "upload_max_bytes", 10)
    monkeypatch.setattr(uploads.get_settings(), "upload_bundle_max_bytes", 10)
    monkeypatch.setattr(uploads, "MULTIPART_OVERHEAD_BYTES", 1024)
    boundary = b"scanops-exact"
    body = (
        b"--" + boundary
        + b'\r\nContent-Disposition: form-data; name="files"; filename="exact.xml"'
        + b"\r\nContent-Type: application/xml\r\n\r\n"
        + b"x" * 10
        + b"\r\n--" + boundary + b"--\r\n"
    )
    messages = iter([{"type": "http.request", "body": body, "more_body": False}])
    downstream_finished = False

    async def app(scope, receive, send):
        nonlocal downstream_finished
        await receive()
        downstream_finished = True

    async def receive():
        return next(messages)

    async def send(message):
        raise AssertionError(f"unexpected response: {message}")

    headers = [(b"content-type", b"multipart/form-data; boundary=scanops-exact")]
    asyncio.run(uploads.UploadBodyLimitMiddleware(app)(
        _scope(headers, path="/api/scans/import-bundle"), receive, send,
    ))

    assert downstream_finished is True


def test_bundle_rejects_aggregate_parts_before_request_finishes(monkeypatch):
    monkeypatch.setattr(uploads.get_settings(), "upload_max_bytes", 10)
    monkeypatch.setattr(uploads.get_settings(), "upload_bundle_max_bytes", 12)
    monkeypatch.setattr(uploads, "MULTIPART_OVERHEAD_BYTES", 1024)
    boundary = b"scanops-total"
    first_chunk = (
        b"--" + boundary
        + b'\r\nContent-Disposition: form-data; name="files"; filename="one.xml"'
        + b"\r\n\r\n" + b"a" * 8
        + b"\r\n--" + boundary
        + b'\r\nContent-Disposition: form-data; name="files"; filename="two.xml"'
        + b"\r\n\r\n" + b"b" * 8
        + b"\r\n--" + boundary + b"--\r\n"
    )
    messages = iter([
        {"type": "http.request", "body": first_chunk, "more_body": True},
        {"type": "http.request", "body": b"epilogue", "more_body": False},
    ])
    receive_count = 0
    downstream_finished = False
    sent = []

    async def app(scope, receive, send):
        nonlocal downstream_finished
        while (message := await receive()).get("more_body", False):
            pass
        downstream_finished = True

    async def receive():
        nonlocal receive_count
        receive_count += 1
        return next(messages)

    async def send(message):
        sent.append(message)

    headers = [(b"content-type", b"multipart/form-data; boundary=scanops-total")]
    asyncio.run(uploads.UploadBodyLimitMiddleware(app)(
        _scope(headers, path="/api/scans/import-bundle"), receive, send,
    ))

    assert receive_count == 1
    assert downstream_finished is False
    assert sent[0]["status"] == 413
