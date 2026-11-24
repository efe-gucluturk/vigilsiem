"""Admin authentication: login / logout (JWT in HttpOnly SameSite=Strict cookie)."""

from __future__ import annotations

from fastapi import APIRouter, Request, Response
from sqlalchemy import select

from vigilsiem.api.context import AppContext
from vigilsiem.api.deps import AdminWrite, Ctx, client_ip, rate_limited
from vigilsiem.core.errors import AppError
from vigilsiem.core.logging import get_logger
from vigilsiem.models.orm import AdminUser
from vigilsiem.models.schemas import LoginRequest
from vigilsiem.security import tokens
from vigilsiem.security.passwords import verify_password

router = APIRouter(prefix="/api/v1/auth", tags=["auth"])
log = get_logger("auth")


async def authenticate(
    ctx: AppContext, request: Request, username: str, password: str
) -> tuple[str, str]:
    """Return (jwt, csrf_token) or raise AppError. Throttled per client IP."""
    ip = client_ip(request, ctx)
    decision = ctx.login_limiter.check(ip)
    if not decision.allowed:
        log.warning("login_throttled", extra={"client_ip": ip})
        raise rate_limited(decision.retry_after)

    async with ctx.db.session() as session:
        row = await session.scalar(select(AdminUser).where(AdminUser.username == username))
    # Always run a scrypt verification (dummy when the user is unknown): no user oracle.
    if not verify_password(password, row.password_hash if row else None) or row is None:
        log.warning("login_failed", extra={"client_ip": ip})
        raise AppError(401, "invalid_credentials", "Invalid credentials.")

    s = ctx.settings
    secret = s.jwt_secret.get_secret_value()
    token, claims = tokens.create_access_token(
        row.username,
        secret=secret,
        ttl_minutes=s.jwt_ttl_minutes,
        issuer=s.jwt_issuer,
        audience=s.jwt_audience,
    )
    log.info("login_ok", extra={"user": row.username, "client_ip": ip})
    return token, tokens.issue_csrf_token(claims.session_id, secret=secret)


def set_session_cookie(response: Response, ctx: AppContext, token: str) -> None:
    response.set_cookie(
        ctx.settings.cookie_name,
        token,
        max_age=ctx.settings.jwt_ttl_minutes * 60,
        httponly=True,
        secure=ctx.settings.cookie_secure,
        samesite="strict",
        path="/",
    )


def clear_session_cookie(response: Response, ctx: AppContext) -> None:
    response.delete_cookie(
        ctx.settings.cookie_name,
        path="/",
        httponly=True,
        secure=ctx.settings.cookie_secure,
        samesite="strict",
    )


@router.post("/login")
async def login(
    body: LoginRequest, request: Request, response: Response, ctx: Ctx
) -> dict[str, str]:
    token, csrf = await authenticate(ctx, request, body.username, body.password.get_secret_value())
    set_session_cookie(response, ctx, token)
    return {"csrf_token": csrf}


@router.post("/logout", status_code=204)
async def logout(response: Response, ctx: Ctx, admin: AdminWrite) -> None:
    ctx.revoke_session(admin.session_id, admin.expires_at)
    clear_session_cookie(response, ctx)
