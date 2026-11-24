"""Server-rendered SOC dashboard (Jinja2 + HTMX + Alpine). All output is auto-escaped."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any

from fastapi import APIRouter, Form, Request, Response
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from pydantic import ValidationError
from sqlalchemy import delete, select

from vigilsiem.api.admin import create_webhook, webhook_out
from vigilsiem.api.auth import authenticate, clear_session_cookie, set_session_cookie
from vigilsiem.api.deps import Admin, AdminWrite, Ctx, resolve_admin
from vigilsiem.core.errors import AppError
from vigilsiem.core.queries import alert_events, compute_stats, list_alerts
from vigilsiem.engine.rules import RuleLoadError
from vigilsiem.models.enums import AlertStatus, Severity
from vigilsiem.models.orm import Alert, WebhookConfig
from vigilsiem.models.schemas import LoginRequest, WebhookCreate

BASE = Path(__file__).parent
templates = Jinja2Templates(directory=str(BASE / "templates"))
router = APIRouter(include_in_schema=False)


def _fmt_ts(value: datetime | None) -> str:
    if value is None:
        return ""
    value = value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)
    return value.strftime("%Y-%m-%d %H:%M:%S UTC")


templates.env.filters["ts"] = _fmt_ts


def _render(request: Request, name: str, **context: Any) -> HTMLResponse:
    status = context.pop("status_code", 200)
    headers = context.pop("headers", None)
    return templates.TemplateResponse(request, name, context, status_code=status, headers=headers)


def _enum_or_none[E: (Severity, AlertStatus)](kind: type[E], raw: str) -> E | None:
    if not raw:
        return None
    try:
        return kind(raw)
    except ValueError as exc:
        raise AppError(422, "validation_error", "Invalid filter value.") from exc


# --- login / pages -------------------------------------------------------------------------


@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, ctx: Ctx) -> Response:
    if await resolve_admin(request, ctx):
        return RedirectResponse("/", status_code=303)
    return _render(request, "login.html", admin=None, error=None)


@router.post("/login", response_class=HTMLResponse)
async def login_submit(
    request: Request,
    ctx: Ctx,
    username: Annotated[str, Form(max_length=64)] = "",
    password: Annotated[str, Form(max_length=128)] = "",
) -> Response:
    # SameSite=Strict on the session cookie + per-IP throttling cover login CSRF/brute force.
    try:
        creds = LoginRequest(username=username, password=password)  # type: ignore[arg-type]
        token, _ = await authenticate(ctx, request, creds.username, password)
    except (ValidationError, AppError) as exc:
        status = exc.status_code if isinstance(exc, AppError) else 401
        message = (
            "Too many attempts. Try again shortly." if status == 429 else "Invalid credentials."
        )
        headers = exc.headers if isinstance(exc, AppError) else None
        return _render(
            request, "login.html", admin=None, error=message, status_code=status, headers=headers
        )
    response = RedirectResponse("/", status_code=303)
    set_session_cookie(response, ctx, token)
    return response


async def _page(request: Request, ctx: Ctx, name: str, **extra: Any) -> Response:
    admin = await resolve_admin(request, ctx)
    if admin is None:
        return RedirectResponse("/login", status_code=303)
    return _render(request, name, admin=admin, **extra)


@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, ctx: Ctx) -> Response:
    return await _page(request, ctx, "dashboard.html", page="dashboard")


@router.get("/rules", response_class=HTMLResponse)
async def rules_page(request: Request, ctx: Ctx) -> Response:
    return await _page(
        request, ctx, "rules.html", page="rules", rules=ctx.rules.describe(), notice=None
    )


@router.get("/webhooks", response_class=HTMLResponse)
async def webhooks_page(request: Request, ctx: Ctx) -> Response:
    admin = await resolve_admin(request, ctx)
    if admin is None:
        return RedirectResponse("/login", status_code=303)
    return _render(
        request,
        "webhooks.html",
        admin=admin,
        page="webhooks",
        hooks=await _hooks(ctx),
        error=None,
        severities=[Severity.HIGH, Severity.CRITICAL],
    )


# --- HTMX fragments ----------------------------------------------------------------------------


@router.get("/ui/metrics", response_class=HTMLResponse)
async def ui_metrics(request: Request, ctx: Ctx, _: Admin) -> Response:
    async with ctx.db.session() as session:
        stats = await compute_stats(session)
    return _render(request, "partials/metrics.html", stats=stats, severities=list(Severity)[::-1])


@router.get("/ui/alerts", response_class=HTMLResponse)
async def ui_alerts(
    request: Request, ctx: Ctx, _: Admin, severity: str = "", status: str = ""
) -> Response:
    sev, st = _enum_or_none(Severity, severity[:16]), _enum_or_none(AlertStatus, status[:16])
    async with ctx.db.session() as session:
        alerts = await list_alerts(session, severity=sev, status=st, limit=50)
    return _render(request, "partials/alerts.html", alerts=alerts)


async def _detail(request: Request, ctx: Ctx, alert_id: int, *, open_panel: bool) -> Response:
    async with ctx.db.session() as session:
        alert = await session.get(Alert, alert_id)
        if alert is None:
            raise AppError(404, "not_found", "Alert not found.")
        events = await alert_events(session, alert)
    rule = next((r for r in ctx.rules.describe() if r["id"] == alert.rule_id), None)
    return _render(
        request,
        "partials/alert_detail.html",
        alert=alert,
        events=events,
        rule=rule,
        statuses=list(AlertStatus),
        headers={"HX-Trigger": "open-detail"} if open_panel else None,
    )


@router.get("/ui/alerts/{alert_id}", response_class=HTMLResponse)
async def ui_alert_detail(request: Request, alert_id: int, ctx: Ctx, _: Admin) -> Response:
    return await _detail(request, ctx, alert_id, open_panel=True)


@router.post("/ui/alerts/{alert_id}/status", response_class=HTMLResponse)
async def ui_alert_status(
    request: Request, alert_id: int, status: Annotated[AlertStatus, Form()], ctx: Ctx, _: AdminWrite
) -> Response:
    async with ctx.db.session() as session:
        alert = await session.get(Alert, alert_id)
        if alert is None:
            raise AppError(404, "not_found", "Alert not found.")
        alert.status = status
    return await _detail(request, ctx, alert_id, open_panel=False)


@router.post("/ui/logout")
async def ui_logout(ctx: Ctx, admin: AdminWrite) -> Response:
    ctx.revoke_session(admin.session_id, admin.expires_at)
    response = Response(status_code=204, headers={"HX-Redirect": "/login"})
    clear_session_cookie(response, ctx)
    return response


@router.post("/ui/rules/reload", response_class=HTMLResponse)
async def ui_rules_reload(request: Request, ctx: Ctx, _: AdminWrite) -> Response:
    try:
        count = ctx.rules.reload_from_directory(ctx.settings.rules_dir)
        notice = f"Reloaded {count} rules."
    except RuleLoadError as exc:
        notice = f"Reload failed (previous rules still active): {exc}"[:300]
    return _render(request, "partials/rules_table.html", rules=ctx.rules.describe(), notice=notice)


async def _hooks(ctx: Ctx) -> list[Any]:
    async with ctx.db.session() as session:
        rows = (await session.scalars(select(WebhookConfig).order_by(WebhookConfig.id))).all()
        return [webhook_out(r) for r in rows]


@router.post("/ui/webhooks", response_class=HTMLResponse)
async def ui_webhook_add(
    request: Request,
    ctx: Ctx,
    _: AdminWrite,
    name: Annotated[str, Form(max_length=64)] = "",
    url: Annotated[str, Form(max_length=2048)] = "",
    min_severity: Annotated[str, Form(max_length=16)] = "high",
) -> Response:
    error = None
    try:
        await create_webhook(
            ctx,
            WebhookCreate(name=name, url=url, min_severity=min_severity),  # type: ignore[arg-type]
        )
    except ValidationError:
        error = "Invalid name, URL or severity."
    except AppError as exc:
        error = exc.message  # 200 so htmx swaps the message in
    return _render(request, "partials/webhooks_table.html", hooks=await _hooks(ctx), error=error)


@router.delete("/ui/webhooks/{webhook_id}", response_class=HTMLResponse)
async def ui_webhook_delete(request: Request, webhook_id: int, ctx: Ctx, _: AdminWrite) -> Response:
    async with ctx.db.session() as session:
        await session.execute(delete(WebhookConfig).where(WebhookConfig.id == webhook_id))
    return _render(request, "partials/webhooks_table.html", hooks=await _hooks(ctx), error=None)
