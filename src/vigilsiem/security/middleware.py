"""Pure-ASGI middleware: request-size cap and security response headers."""

from __future__ import annotations

import json
from collections.abc import MutableMapping
from typing import Any

from starlette.types import ASGIApp, Message, Receive, Scope, Send

Headers = list[tuple[bytes, bytes]]

CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
    "font-src 'self'; connect-src 'self'; form-action 'self'; base-uri 'none'; "
    "frame-ancestors 'none'"
)


def _json_headers(body: bytes) -> Headers:
    return [
        (b"content-type", b"application/json"),
        (b"content-length", str(len(body)).encode("ascii")),
    ]


class _BodyTooLargeError(Exception):
    pass


class BodySizeLimitMiddleware:
    """Reject bodies over ``max_bytes`` with 413, both by header and while streaming."""

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        declared = dict(scope["headers"]).get(b"content-length")
        if declared is not None:
            try:
                too_big = int(declared) > self.max_bytes
            except ValueError:
                too_big = True  # malformed length -> refuse
            if too_big:
                await self._reject(send)
                return

        received = 0
        started = False

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise _BodyTooLargeError
            return message

        async def tracking_send(message: Message) -> None:
            nonlocal started
            if message["type"] == "http.response.start":
                started = True
            await send(message)

        try:
            await self.app(scope, limited_receive, tracking_send)
        except _BodyTooLargeError:
            if not started:
                await self._reject(send)

    @staticmethod
    async def _reject(send: Send) -> None:
        body = json.dumps(
            {"error": {"code": "payload_too_large", "message": "Request body too large."}}
        ).encode()
        await send({"type": "http.response.start", "status": 413, "headers": _json_headers(body)})
        await send({"type": "http.response.body", "body": body})


class SecurityHeadersMiddleware:
    """Inject hardening headers on every HTTP response."""

    def __init__(self, app: ASGIApp, *, hsts: bool = True) -> None:
        self.app = app
        self._static: Headers = [
            (b"x-content-type-options", b"nosniff"),
            (b"x-frame-options", b"DENY"),
            (b"referrer-policy", b"no-referrer"),
            (b"content-security-policy", CSP.encode("ascii")),
            (b"permissions-policy", b"camera=(), microphone=(), geolocation=(), payment=()"),
            (b"cross-origin-opener-policy", b"same-origin"),
            (b"cross-origin-resource-policy", b"same-origin"),
            (b"cache-control", b"no-store"),
        ]
        if hsts:
            self._static.append(
                (b"strict-transport-security", b"max-age=63072000; includeSubDomains")
            )

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        async def send_with_headers(message: MutableMapping[str, Any]) -> None:
            if message["type"] == "http.response.start":
                managed = {name for name, _ in self._static}
                # Drop our managed headers and "server" (never advertise the stack).
                skip = managed | {b"server"}
                headers = [(k, v) for k, v in message.get("headers", []) if k.lower() not in skip]
                headers.extend(self._static)
                message["headers"] = headers
            await send(message)  # type: ignore[arg-type]

        await self.app(scope, receive, send_with_headers)
