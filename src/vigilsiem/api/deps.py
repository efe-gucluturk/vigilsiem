"""Authentication / authorization / CSRF dependencies.

Two disjoint auth planes:
  * agents  -> ``X-API-Key`` (ingest only)
  * analysts -> signed JWT in an HttpOnly cookie (+ CSRF header on writes)
A credential from one plane is never accepted by the other.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Annotated
from urllib.parse import urlsplit

from fastapi import Depends, Request
from sqlalchemy import select

from vigilsiem.api.context import AppContext, get_ctx
from vigilsiem.core.errors import AppError
from vigilsiem.models.orm import AdminUser, ApiKey
from vigilsiem.security import tokens
from vigilsiem.security.apikeys import extract_prefix, verify_key

UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
Ctx = Annotated[AppContext, Depends(get_ctx)]


def client_ip(request: Request, ctx: AppContext) -> str:
    """Peer address; X-Forwarded-For is honored ONLY for a declared trusted-proxy depth."""
    hops = ctx.settings.trusted_proxy_count
    if hops:
        forwarded = [p.strip() for p in request.headers.get("x-forwarded-for", "").split(",")]
        forwarded = [p for p in forwarded if p]
        if len(forwarded) >= hops:
            return forwarded[-hops][:45]
    return request.client.host if request.client else "unknown"


def rate_limited(retry_after: int) -> AppError:
    return AppError(
        429, "rate_limited", "Too many requests.", headers={"Retry-After": str(retry_after)}
    )


# --- agent plane -----------------------------------------------------------------------


@dataclass
class AgentIdentity:
    key_id: int
    name: str
    prefix: str


async def require_api_key(request: Request, ctx: Ctx) -> AgentIdentity:
    ip = client_ip(request, ctx)
    if ctx.key_fail_limiter.is_limited(ip):
        raise rate_limited(60)

    candidate = request.headers.get("x-api-key")
    prefix = extract_prefix(candidate)
    row = None
    if prefix:
        async with ctx.db.session() as session:
            row = await session.scalar(select(ApiKey).where(ApiKey.key_prefix == prefix))
    stored = row.key_hash if row is not None and not row.revoked else None
    if not verify_key(candidate, stored) or row is None:  # always runs a constant-time compare
        ctx.key_fail_limiter.check(ip)
        raise AppError(
            401, "unauthorized", "Invalid or missing API key.", {"WWW-Authenticate": "ApiKey"}
        )

    decision = ctx.ingest_limiter.check(row.key_prefix)
    if not decision.allowed:
        raise rate_limited(decision.retry_after)
    return AgentIdentity(key_id=row.id, name=row.name, prefix=row.key_prefix)


# --- analyst plane -----------------------------------------------------------------------


@dataclass
class AdminSession:
    username: str
    session_id: str
    csrf_token: str
    expires_at: datetime


async def resolve_admin(request: Request, ctx: AppContext) -> AdminSession | None:
    token = request.cookies.get(ctx.settings.cookie_name)
    if not token or len(token) > 2048:
        return None
    s = ctx.settings
    try:
        claims = tokens.decode_access_token(
            token,
            secret=s.jwt_secret.get_secret_value(),
            issuer=s.jwt_issuer,
            audience=s.jwt_audience,
        )
    except tokens.InvalidTokenError:
        return None
    if ctx.is_revoked(claims.session_id):
        return None
    async with ctx.db.session() as session:  # deleting the user revokes outstanding tokens
        exists = await session.scalar(
            select(AdminUser.id).where(AdminUser.username == claims.subject)
        )
    if exists is None:
        return None
    decision = ctx.admin_limiter.check(claims.subject)
    if not decision.allowed:
        raise rate_limited(decision.retry_after)
    return AdminSession(
        username=claims.subject,
        session_id=claims.session_id,
        csrf_token=tokens.issue_csrf_token(
            claims.session_id, secret=s.jwt_secret.get_secret_value()
        ),
        expires_at=claims.expires_at,
    )


async def require_admin(request: Request, ctx: Ctx) -> AdminSession:
    session = await resolve_admin(request, ctx)
    if session is None:
        raise AppError(401, "unauthorized", "Authentication required.")
    return session


Admin = Annotated[AdminSession, Depends(require_admin)]


def _same_origin(request: Request, *, require_https: bool) -> bool:
    origin = request.headers.get("origin")
    if origin is None:
        return True  # non-browser clients; CSRF token below is still mandatory
    parts = urlsplit(origin)
    if parts.scheme not in {"http", "https"} or (require_https and parts.scheme != "https"):
        return False  # "null", file:, and plain-http origins for an https-only deployment
    return parts.netloc == request.headers.get("host", "")


async def require_csrf(request: Request, admin: Admin, ctx: Ctx) -> AdminSession:
    """State-changing routes: valid CSRF header bound to this session + same-origin."""
    if request.method in UNSAFE_METHODS and (
        not _same_origin(request, require_https=ctx.settings.cookie_secure)
        or not tokens.verify_csrf_token(
            request.headers.get("x-csrf-token"),
            admin.session_id,
            secret=ctx.settings.jwt_secret.get_secret_value(),
        )
    ):
        raise AppError(403, "csrf_failed", "CSRF validation failed.")
    return admin


AdminWrite = Annotated[AdminSession, Depends(require_csrf)]


def utcnow() -> datetime:
    return datetime.now(UTC)
