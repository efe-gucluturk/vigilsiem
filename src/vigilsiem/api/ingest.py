"""POST /api/v1/ingest: agent log batches (API-key auth only)."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Annotated

from fastapi import APIRouter, BackgroundTasks, Depends, Request
from pydantic import ValidationError
from sqlalchemy import select, update

from vigilsiem.api.context import AppContext
from vigilsiem.api.deps import AgentIdentity, Ctx, require_api_key
from vigilsiem.core.errors import AppError
from vigilsiem.core.ingestion import ingest_batch
from vigilsiem.core.logging import get_logger
from vigilsiem.engine.detection import Detection
from vigilsiem.models.enums import Severity
from vigilsiem.models.orm import ApiKey, WebhookConfig
from vigilsiem.models.schemas import IngestBatch, IngestResult

router = APIRouter(prefix="/api/v1", tags=["ingest"])
log = get_logger("ingest")

Job = tuple[str, Detection, int | None]


async def _notify(ctx: AppContext, jobs: list[Job]) -> None:
    for url, detection, alert_id in jobs:
        await ctx.notifier.send(url, detection, alert_id)


@router.post("/ingest", response_model=IngestResult)
async def ingest(
    request: Request,
    background: BackgroundTasks,
    ctx: Ctx,
    agent: Annotated[AgentIdentity, Depends(require_api_key)],
) -> IngestResult:
    # Authentication already happened; only now is the body parsed and validated.
    if "application/json" not in request.headers.get("content-type", ""):
        raise AppError(415, "unsupported_media_type", "Content-Type must be application/json.")
    try:
        batch = IngestBatch.model_validate_json(await request.body())
    except ValidationError as exc:
        raise AppError(422, "validation_error", "Request validation failed.") from exc
    if len(batch.lines) > ctx.settings.max_batch_lines:
        raise AppError(413, "batch_too_large", "Too many lines in one batch.")

    jobs: list[Job] = []
    async with ctx.db.session() as session:
        outcome = await ingest_batch(session, ctx.pipeline, batch)
        await session.execute(
            update(ApiKey).where(ApiKey.id == agent.key_id).values(last_used_at=datetime.now(UTC))
        )
        if outcome.new_alerts:
            hooks = (
                await session.scalars(select(WebhookConfig).where(WebhookConfig.enabled.is_(True)))
            ).all()
            for alert, detection in outcome.new_alerts:
                if detection.severity.rank < Severity.HIGH.rank:
                    continue
                jobs.extend(
                    (h.url, detection, alert.id)
                    for h in hooks
                    if detection.severity.rank >= h.min_severity.rank
                )
        alerts_created = len(outcome.new_alerts)

    if jobs:
        background.add_task(_notify, ctx, jobs[: ctx.settings.max_webhook_notifications_per_batch])
    log.info(
        "ingest",
        extra={"agent": agent.name, "accepted": outcome.accepted, "rejected": outcome.rejected},
    )
    return IngestResult(
        accepted=outcome.accepted, rejected=outcome.rejected, alerts_created=alerts_created
    )
