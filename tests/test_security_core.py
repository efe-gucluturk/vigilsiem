from __future__ import annotations

import json
import secrets
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError
from sqlalchemy import select, text
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from vigilsiem.core.config import Settings
from vigilsiem.core.db import Database
from vigilsiem.core.logging import JsonFormatter
from vigilsiem.models.orm import ApiKey
from vigilsiem.models.schemas import IngestBatch, SecurityEvent
from vigilsiem.security import apikeys, passwords, tokens
from vigilsiem.security.middleware import BodySizeLimitMiddleware, SecurityHeadersMiddleware
from vigilsiem.security.ratelimit import SlidingWindowLimiter
from vigilsiem.security.ssrf import UnsafeWebhookURLError, validate_webhook_url

SECRET = secrets.token_urlsafe(48)


# --- config ----------------------------------------------------------------
def test_config_fails_closed_without_secret(monkeypatch):
    monkeypatch.delenv("VIGIL_JWT_SECRET", raising=False)
    with pytest.raises(ValidationError):
        Settings(_env_file=None)


@pytest.mark.parametrize("bad", ["short", "changeme" + "x" * 40, "a" * 40])
def test_config_rejects_weak_secret(bad):
    with pytest.raises(ValidationError):
        Settings(_env_file=None, jwt_secret=bad)


# --- api keys --------------------------------------------------------------
def test_api_key_roundtrip_and_tamper():
    k = apikeys.generate_key()
    assert apikeys.extract_prefix(k.plaintext) == k.prefix
    assert apikeys.verify_key(k.plaintext, k.key_hash)
    assert not apikeys.verify_key(k.plaintext + "x", k.key_hash)
    assert not apikeys.verify_key(None, k.key_hash)
    assert not apikeys.verify_key(k.plaintext, None)
    assert k.plaintext not in k.key_hash


@pytest.mark.parametrize("bad", [None, "", "vsk_", "vsk_zzzz.abc", "x" * 500, "vsk_é.x"])
def test_extract_prefix_rejects_malformed(bad):
    assert apikeys.extract_prefix(bad) is None


# --- passwords -------------------------------------------------------------
def test_password_hash_verify():
    h = passwords.hash_password("correct horse battery")
    assert passwords.verify_password("correct horse battery", h)
    assert not passwords.verify_password("wrong", h)
    assert not passwords.verify_password("anything", None)
    assert not passwords.verify_password("anything", "garbage$hash")


# --- tokens / csrf ---------------------------------------------------------
def _mk(**kw):
    return tokens.create_access_token(
        "admin", secret=SECRET, ttl_minutes=5, issuer="i", audience="a", **kw
    )


def test_jwt_roundtrip_and_csrf_binding():
    tok, claims = _mk()
    got = tokens.decode_access_token(tok, secret=SECRET, issuer="i", audience="a")
    assert got.subject == "admin" and got.session_id == claims.session_id
    csrf = tokens.issue_csrf_token(got.session_id, secret=SECRET)
    assert tokens.verify_csrf_token(csrf, got.session_id, secret=SECRET)
    assert not tokens.verify_csrf_token(csrf, "other-session", secret=SECRET)
    assert not tokens.verify_csrf_token(None, got.session_id, secret=SECRET)


def test_jwt_rejections():
    tok, _ = _mk()
    for kw in ({"secret": secrets.token_urlsafe(48)}, {"issuer": "x"}, {"audience": "x"}):
        args = {"secret": SECRET, "issuer": "i", "audience": "a", **kw}
        with pytest.raises(tokens.InvalidTokenError):
            tokens.decode_access_token(tok, **args)
    expired, _ = _mk(now=datetime.now(UTC) - timedelta(hours=1))
    with pytest.raises(tokens.InvalidTokenError):
        tokens.decode_access_token(expired, secret=SECRET, issuer="i", audience="a")


def test_jwt_alg_none_rejected():
    import base64

    def b64(d):
        return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b"=").decode()

    forged = (
        b64({"alg": "none", "typ": "JWT"})
        + "."
        + b64({"sub": "admin", "iss": "i", "aud": "a", "exp": 9999999999})
        + "."
    )
    with pytest.raises(tokens.InvalidTokenError):
        tokens.decode_access_token(forged, secret=SECRET, issuer="i", audience="a")


# --- rate limiter ----------------------------------------------------------
def test_sliding_window():
    now = [1000.0]
    rl = SlidingWindowLimiter(3, 60, clock=lambda: now[0])
    assert all(rl.check("k").allowed for _ in range(3))
    d = rl.check("k")
    assert not d.allowed and 1 <= d.retry_after <= 60
    assert rl.check("other").allowed  # keys are isolated
    now[0] += 61
    assert rl.check("k").allowed


def test_limiter_bounded_memory():
    rl = SlidingWindowLimiter(1, 60, max_keys=100)
    for i in range(1000):
        rl.check(f"ip-{i}")
    assert len(rl._hits) <= 100


# --- SSRF ------------------------------------------------------------------
async def _resolver_for(*ips):
    async def r(_h, _p):
        return list(ips)

    return r


@pytest.mark.parametrize(
    "url",
    [
        "http://hooks.slack.com/x",
        "https://127.0.0.1/x",
        "https://10.1.2.3/x",
        "https://172.16.0.1/x",
        "https://192.168.1.1/x",
        "https://169.254.169.254/latest/meta-data",
        "https://[::1]/x",
        "https://[::ffff:127.0.0.1]/x",
        "https://[::ffff:169.254.169.254]/x",
        "https://0.0.0.0/x",
        "https://user:pw@hooks.slack.com/x",
        "https://hooks.slack.com:8443/x",
        "ftp://hooks.slack.com/x",
        "https://",
        "https://exa mple.com",
        "https://hooks.slack.com/" + "a" * 3000,
    ],
)
async def test_ssrf_blocks_literals_and_shapes(url):
    with pytest.raises(UnsafeWebhookURLError):
        await validate_webhook_url(url, resolver=await _resolver_for("93.184.216.34"))


@pytest.mark.parametrize(
    "ips",
    [["127.0.0.1"], ["10.0.0.5"], ["169.254.169.254"], ["::1"], ["93.184.216.34", "10.0.0.1"]],
)
async def test_ssrf_blocks_dns_to_private(ips):
    with pytest.raises(UnsafeWebhookURLError):
        await validate_webhook_url("https://evil.example/hook", resolver=await _resolver_for(*ips))


async def test_ssrf_allows_public_and_pins_ip():
    t = await validate_webhook_url(
        "https://hooks.slack.com/services/T/B/X", resolver=await _resolver_for("93.184.216.34")
    )
    assert t.ip == "93.184.216.34" and t.hostname == "hooks.slack.com" and t.port == 443


# --- schemas ---------------------------------------------------------------
def test_schemas_forbid_extra_and_bound_sizes():
    with pytest.raises(ValidationError):
        IngestBatch(source_type="ssh", host="h1", lines=["x"], admin=True)  # type: ignore[call-arg]
    with pytest.raises(ValidationError):
        IngestBatch(source_type="ssh", host="h1; DROP TABLE", lines=["x"])
    with pytest.raises(ValidationError):
        IngestBatch(source_type="ssh", host="h1", lines=["x" * 9000])
    with pytest.raises(ValidationError):
        IngestBatch(source_type="bogus", host="h1", lines=["x"])  # type: ignore[arg-type]
    with pytest.raises(ValidationError):
        SecurityEvent(
            timestamp=datetime.now(UTC),
            source_ip="not-an-ip",  # type: ignore[arg-type]
            event_category="web",  # type: ignore[arg-type]
            action="a",
            status="s",
            raw_log="r",
        )


# --- middleware ------------------------------------------------------------
def _app(max_bytes=1024):
    async def echo(request):
        return PlainTextResponse(str(len(await request.body())))

    app = Starlette(routes=[Route("/", echo, methods=["POST", "GET"])])
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=max_bytes)
    return TestClient(app, base_url="https://testserver")


def test_body_limit_and_headers():
    c = _app(1024)
    ok = c.post("/", content=b"a" * 1024)
    assert ok.status_code == 200
    big = c.post("/", content=b"a" * 1025)
    assert big.status_code == 413 and big.json()["error"]["code"] == "payload_too_large"
    # streamed (chunked, no Content-Length) body is also capped
    chunked = c.post("/", content=(b"a" * 512 for _ in range(10)))
    assert chunked.status_code == 413
    h = ok.headers
    assert h["x-content-type-options"] == "nosniff"
    assert h["x-frame-options"] == "DENY"
    assert h["referrer-policy"] == "no-referrer"
    assert "frame-ancestors 'none'" in h["content-security-policy"]
    assert "script-src 'self'" in h["content-security-policy"]


# --- db --------------------------------------------------------------------
async def test_db_wal_and_parameterized_lookup(tmp_path):
    db = Database(f"sqlite+aiosqlite:///{tmp_path / 't.db'}")
    await db.create_all()
    k = apikeys.generate_key()
    async with db.session() as s:
        assert (await s.execute(text("PRAGMA journal_mode"))).scalar() == "wal"
        s.add(ApiKey(name="a", key_prefix=k.prefix, key_hash=k.key_hash))
    evil = "' OR '1'='1"
    async with db.session() as s:
        assert await s.scalar(select(ApiKey).where(ApiKey.key_prefix == evil)) is None
        assert await s.scalar(select(ApiKey).where(ApiKey.key_prefix == k.prefix)) is not None
    await db.dispose()


# --- logging ---------------------------------------------------------------
def test_log_redaction():
    import logging

    rec = logging.LogRecord("x", logging.INFO, "f", 1, "hello", (), None)
    rec.api_key = "vsk_secret"
    rec.password = "hunter2"
    rec.path = "/ok"
    out = json.loads(JsonFormatter().format(rec))
    assert out["api_key"] == "[REDACTED]" and out["password"] == "[REDACTED]"
    assert out["path"] == "/ok"
