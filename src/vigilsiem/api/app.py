"""Application factory.

Run with:  uvicorn --factory vigilsiem.api.app:create_app
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from sqlalchemy import select

from vigilsiem.api import admin, auth, ingest
from vigilsiem.api.context import AppContext
from vigilsiem.core.config import Settings, get_settings
from vigilsiem.core.db import Database
from vigilsiem.core.errors import register_error_handlers
from vigilsiem.core.ingestion import restore_rule_hits
from vigilsiem.core.logging import configure_logging, get_logger
from vigilsiem.core.notifier import WebhookNotifier
from vigilsiem.engine.correlation import RuleEngine
from vigilsiem.engine.pipeline import DetectionPipeline
from vigilsiem.models.orm import AdminUser
from vigilsiem.security.middleware import BodySizeLimitMiddleware, SecurityHeadersMiddleware
from vigilsiem.security.ratelimit import SlidingWindowLimiter
from vigilsiem.web import routes as web_routes

STATIC_DIR = Path(web_routes.__file__).parent / "static"
log = get_logger("app")


async def _bootstrap_admin(ctx: AppContext) -> None:
    s = ctx.settings
    if s.admin_password_hash is None:
        log.warning("no_admin_configured", extra={"hint": "set VIGIL_ADMIN_PASSWORD_HASH"})
        return
    pw_hash = s.admin_password_hash.get_secret_value()
    if not pw_hash.startswith("scrypt$"):
        raise RuntimeError("VIGIL_ADMIN_PASSWORD_HASH is not a valid VigilSIEM hash")
    async with ctx.db.session() as session:
        row = await session.scalar(select(AdminUser).where(AdminUser.username == s.admin_username))
        if row is None:
            session.add(AdminUser(username=s.admin_username, password_hash=pw_hash))
        elif row.password_hash != pw_hash:
            row.password_hash = pw_hash


def build_context(settings: Settings, notifier: WebhookNotifier | None = None) -> AppContext:
    rules = RuleEngine.from_directory(settings.rules_dir)
    return AppContext(
        settings=settings,
        db=Database(settings.database_url),
        rules=rules,
        pipeline=DetectionPipeline(rules),
        notifier=notifier or WebhookNotifier(timeout=settings.webhook_timeout_seconds),
        ingest_limiter=SlidingWindowLimiter(settings.ingest_rate_per_min, 60),
        login_limiter=SlidingWindowLimiter(settings.login_rate_per_min, 60),
        admin_limiter=SlidingWindowLimiter(settings.admin_rate_per_min, 60),
    )


def create_app(
    settings: Settings | None = None, *, notifier: WebhookNotifier | None = None
) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level)
    ctx = build_context(settings, notifier)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        await ctx.db.create_all()
        await _bootstrap_admin(ctx)
        async with ctx.db.session() as session:
            await restore_rule_hits(session, ctx.pipeline)
        log.info("startup", extra={"rules": len(ctx.rules.describe())})
        yield
        await ctx.db.dispose()

    docs = "/docs" if settings.enable_docs else None
    app = FastAPI(
        title="VigilSIEM",
        version="0.1.0",
        lifespan=lifespan,
        docs_url=docs,
        redoc_url=None,
        openapi_url="/openapi.json" if settings.enable_docs else None,
    )
    app.state.ctx = ctx
    register_error_handlers(app)

    # Last added = outermost: security headers wrap everything, including 413 rejections.
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_body_bytes)
    app.add_middleware(SecurityHeadersMiddleware, hsts=settings.cookie_secure)

    @app.get("/healthz", include_in_schema=False)
    async def healthz() -> dict[str, str]:
        return {"status": "ok"}

    app.include_router(ingest.router)
    app.include_router(auth.router)
    app.include_router(admin.router)
    app.include_router(web_routes.router)
    app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")
    return app
