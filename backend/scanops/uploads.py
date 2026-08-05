"""Bounded upload transport and reads shared by XML and asset imports."""
from __future__ import annotations

from fastapi import HTTPException, UploadFile
from python_multipart import MultipartParser
from python_multipart.multipart import parse_options_header
from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from .config import get_settings


CHUNK_SIZE = 1024 * 1024
# Multipart boundaries and headers are not part of the file payload limits. Keep that transport
# overhead bounded too, without rejecting a file exactly at the documented limit.
MULTIPART_OVERHEAD_BYTES = 1024 * 1024


class _UploadBodyTooLarge(Exception):
    def __init__(self, detail: str = "업로드 요청 본문이 허용 크기를 초과했습니다."):
        super().__init__(detail)
        self.detail = detail


def _multipart_boundary(headers: dict[bytes, bytes]) -> bytes | None:
    media_type, options = parse_options_header(headers.get(b"content-type", b""))
    if media_type.lower() != b"multipart/form-data":
        return None
    boundary = options.get(b"boundary", b"")
    if boundary and b"\r" not in boundary and b"\n" not in boundary:
        return boundary
    return None


class _MultipartPartLimiter:
    """Count part payloads with python-multipart before Starlette can spool them."""

    def __init__(self, boundary: bytes, max_part_bytes: int, max_total_bytes: int):
        self._max_part_bytes = max_part_bytes
        self._max_total_bytes = max_total_bytes
        self._part_bytes = 0
        self._total_bytes = 0
        self._parser = MultipartParser(boundary, callbacks={
            "on_part_begin": self._part_begin,
            "on_part_data": self._part_data,
        })

    def _part_begin(self) -> None:
        self._part_bytes = 0

    def _part_data(self, data: bytes, start: int, end: int) -> None:
        size = end - start
        self._part_bytes += size
        self._total_bytes += size
        if self._part_bytes > self._max_part_bytes:
            raise _UploadBodyTooLarge(
                f"업로드 파일이 허용 크기({self._max_part_bytes} bytes)를 초과했습니다."
            )
        if self._total_bytes > self._max_total_bytes:
            raise _UploadBodyTooLarge(
                f"업로드 묶음이 허용 크기({self._max_total_bytes} bytes)를 초과했습니다."
            )

    def feed(self, data: bytes) -> None:
        self._parser.write(data)


def _request_limit(path: str) -> int | None:
    settings = get_settings()
    if path == "/api/scans/import-bundle":
        return settings.upload_bundle_max_bytes + MULTIPART_OVERHEAD_BYTES
    if path in {"/api/scans/import", "/api/assets/import"}:
        return settings.upload_max_bytes + MULTIPART_OVERHEAD_BYTES
    return None


class UploadBodyLimitMiddleware:
    """Reject oversized upload bodies before Starlette finishes multipart spooling.

    Route-level ``read_limited`` remains the exact per-file/aggregate contract. This outer bound
    also covers chunked requests with no Content-Length and protects temporary disk usage.
    """

    def __init__(self, app: ASGIApp):
        self.app = app

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or (limit := _request_limit(scope.get("path", ""))) is None:
            await self.app(scope, receive, send)
            return

        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        boundary = _multipart_boundary(headers)
        settings = get_settings()
        max_total_bytes = (
            settings.upload_bundle_max_bytes
            if scope.get("path") == "/api/scans/import-bundle"
            else settings.upload_max_bytes
        )
        part_limiter = (
            _MultipartPartLimiter(boundary, settings.upload_max_bytes, max_total_bytes)
            if boundary is not None else None
        )
        try:
            declared = int(headers.get(b"content-length", b""))
        except ValueError:
            declared = None
        if declared is not None and declared > limit:
            await self._reject(scope, receive, send)
            return

        received = 0
        response_started = False
        too_large = False
        replacement_sent = False
        reject_detail = "업로드 요청 본문이 허용 크기를 초과했습니다."

        async def limited_receive():
            nonlocal received, too_large, reject_detail
            message = await receive()
            if message["type"] == "http.request":
                body = message.get("body", b"")
                received += len(body)
                if received > limit:
                    too_large = True
                    raise _UploadBodyTooLarge
                if part_limiter is not None:
                    try:
                        part_limiter.feed(body)
                    except _UploadBodyTooLarge as exc:
                        too_large = True
                        reject_detail = exc.detail
                        raise
            return message

        async def tracked_send(message):
            nonlocal response_started, replacement_sent
            # FastAPI converts receive-side multipart exceptions to a generic 400. Preserve the
            # transport contract by replacing that parser response with the intended 413.
            if too_large:
                if not replacement_sent:
                    replacement_sent = True
                    response_started = True
                    await self._reject(scope, receive, send, reject_detail)
                return
            if message["type"] == "http.response.start":
                response_started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracked_send)
        except _UploadBodyTooLarge:
            if replacement_sent:
                return
            if response_started:  # Defensive: multipart parsing occurs before endpoint responses.
                raise
            await self._reject(scope, receive, send, reject_detail)

    @staticmethod
    async def _reject(
        scope: Scope, receive: Receive, send: Send,
        detail: str = "업로드 요청 본문이 허용 크기를 초과했습니다.",
    ) -> None:
        response = JSONResponse(
            {"detail": detail}, status_code=413,
        )
        await response(scope, receive, send)


async def read_limited(file: UploadFile, max_bytes: int) -> bytes:
    declared_size = getattr(file, "size", None)
    if declared_size is not None and declared_size > max_bytes:
        raise HTTPException(
            status_code=413,
            detail=f"업로드 파일이 허용 크기({max_bytes} bytes)를 초과했습니다.",
        )
    chunks: list[bytes] = []
    total = 0
    while True:
        chunk = await file.read(CHUNK_SIZE)
        if not chunk:
            break
        total += len(chunk)
        if total > max_bytes:
            raise HTTPException(
                status_code=413,
                detail=f"업로드 파일이 허용 크기({max_bytes} bytes)를 초과했습니다.",
            )
        chunks.append(chunk)
    return b"".join(chunks)
