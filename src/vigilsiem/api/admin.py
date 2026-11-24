"""Management API (admin plane): alerts, stats, rules, webhooks."""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Path, Query
from pydantic import BaseModel
from sqlalchemy import delete, select

from vigilsiem.api.deps import Admin, AdminWrite, Ctx
from vigilsiem.core.errors import AppError
from vigilsiem.core.notifier import mask_url
from vigilsiem.core.queries import alert_events, compute_stats, list_alerts
from vigilsiem.engine.rules import RuleLoadError
from vigilsiem.models.enums import AlertStatus, Severity
from vigilsiem.models.orm import Alert, WebhookConfig
from vigilsiem.models.schemas import (
    AlertDetail,
    AlertOut,
    AlertTriage,
    EventOut,
    StatsOut,
    WebhookCreate,
    WebhookOut,
)
from vigilsiem.security.ssrf import UnsafeWebhookURLError

router = APIRouter(prefix="/api/v1", tags=["admin"])

PathId = Annotated[int, Path(ge=1, le=2**62)]


class RuleOut(BaseModel):
    id: str
    name: str
    description: str
    severity: Severity
    type: str
    enabled: bool
    mitre_tactic: str
    mitre_technique_id: str
    mitre_technique: str
    hits: int
    source: str


@router.get("/alerts", response_model=list[AlertOut])
async def get_alerts(
    ctx: Ctx,
    _: Admin,
    severity: Severity | None = None,
    status: AlertStatus | None = None,
    limit: Annotated[int, Query(ge=1, le=200)] = 50,
    offset: Annotated[int, Query(ge=0, le=1_000_000)] = 0,
) -> list[Alert]:
    async with ctx.db.session() as session:
        return await list_alerts(
            session, severity=severity, status=status, limit=limit, offset=offset
        )


@router.get("/alerts/{alert_id}", response_model=AlertDetail)
async def get_alert(alert_id: PathId, ctx: Ctx, _: Admin) -> AlertDetail:
    async with ctx.db.session() as session:
        alert = await session.get(Alert, alert_id)
        if alert is None:
            raise AppError(404, "not_found", "Alert not found.")
        events = await alert_events(session, alert)
        detail = AlertDetail.model_validate(alert)
        detail.events = [EventOut.model_validate(e) for e in events]
    source = next((r["source"] for r in ctx.rules.describe() if r["id"] == alert.rule_id), None)
    detail.rule_source = source or None
    return detail


@router.patch("/alerts/{alert_id}", response_model=AlertOut)
async def triage_alert(alert_id: PathId, body: AlertTriage, ctx: Ctx, _: AdminWrite) -> Alert:
    async with ctx.db.session() as session:
        alert = await session.get(Alert, alert_id)
        if alert is None:
            raise AppError(404, "not_found", "Alert not found.")
        alert.status = body.status
        await session.flush()
        await session.refresh(alert)
        return alert


@router.get("/stats", response_model=StatsOut)
async def stats(ctx: Ctx, _: Admin) -> StatsOut:
    async with ctx.db.session() as session:
        return await compute_stats(session)


@router.get("/rules", response_model=list[RuleOut])
async def rules(ctx: Ctx, _: Admin) -> list[dict]:
    return ctx.rules.describe()


@router.post("/rules/reload")
async def reload_rules(ctx: Ctx, _: AdminWrite) -> dict[str, int]:
    try:
        count = ctx.rules.reload_from_directory(ctx.settings.rules_dir)
    except RuleLoadError as exc:
        # Admin-only endpoint; the loader's message names the file and schema problem.
        raise AppError(400, "rules_invalid", str(exc)[:300]) from exc
    return {"loaded": count}


# --- webhooks ------------------------------------------------------------------------------


def webhook_out(row: WebhookConfig) -> WebhookOut:
    return WebhookOut(
        id=row.id,
        name=row.name,
        url_masked=mask_url(row.url),
        min_severity=row.min_severity,
        enabled=row.enabled,
    )


async def create_webhook(ctx: Ctx, body: WebhookCreate) -> WebhookOut:
    try:
        await ctx.notifier.validate(body.url)  # SSRF gate at configuration time
    except UnsafeWebhookURLError as exc:
        raise AppError(422, "unsafe_webhook_url", f"Webhook URL rejected: {exc}.") from exc
    async with ctx.db.session() as session:
        if await session.scalar(select(WebhookConfig.id).where(WebhookConfig.name == body.name)):
            raise AppError(409, "conflict", "A webhook with that name already exists.")
        row = WebhookConfig(
            name=body.name, url=body.url, min_severity=body.min_severity, enabled=body.enabled
        )
        session.add(row)
        await session.flush()
        return webhook_out(row)


@router.get("/webhooks", response_model=list[WebhookOut])
async def get_webhooks(ctx: Ctx, _: Admin) -> list[WebhookOut]:
    async with ctx.db.session() as session:
        rows = (await session.scalars(select(WebhookConfig).order_by(WebhookConfig.id))).all()
        return [webhook_out(r) for r in rows]


@router.post("/webhooks", response_model=WebhookOut, status_code=201)
async def add_webhook(body: WebhookCreate, ctx: Ctx, _: AdminWrite) -> WebhookOut:
    return await create_webhook(ctx, body)


@router.delete("/webhooks/{webhook_id}", status_code=204)
async def remove_webhook(webhook_id: PathId, ctx: Ctx, _: AdminWrite) -> None:
    async with ctx.db.session() as session:
        result = await session.execute(delete(WebhookConfig).where(WebhookConfig.id == webhook_id))
        if result.rowcount == 0:
            raise AppError(404, "not_found", "Webhook not found.")
