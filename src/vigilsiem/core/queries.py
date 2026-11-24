"""Read-side queries shared by the JSON API and the dashboard. ORM expressions only."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

from sqlalchemy import desc, func, select
from sqlalchemy.ext.asyncio import AsyncSession

from vigilsiem.models.enums import AlertStatus, Severity
from vigilsiem.models.orm import Alert, Event
from vigilsiem.models.schemas import StatsOut

ACTIVE = (AlertStatus.OPEN, AlertStatus.INVESTIGATING)
MAX_PAGE = 200


async def list_alerts(
    session: AsyncSession,
    *,
    severity: Severity | None = None,
    status: AlertStatus | None = None,
    limit: int = 50,
    offset: int = 0,
) -> list[Alert]:
    stmt = select(Alert).order_by(desc(Alert.created_at), desc(Alert.id))
    if severity is not None:
        stmt = stmt.where(Alert.severity == severity)
    if status is not None:
        stmt = stmt.where(Alert.status == status)
    stmt = stmt.limit(max(1, min(limit, MAX_PAGE))).offset(max(0, offset))
    return list((await session.scalars(stmt)).all())


async def alert_events(session: AsyncSession, alert: Alert) -> list[Event]:
    if not alert.event_ids:
        return []
    ids = [int(i) for i in alert.event_ids[:50]]
    stmt = select(Event).where(Event.id.in_(ids)).order_by(Event.timestamp, Event.id)
    return list((await session.scalars(stmt)).all())


async def compute_stats(session: AsyncSession) -> StatsOut:
    now = datetime.now(UTC)
    recent = await session.scalar(
        select(func.count())
        .select_from(Event)
        .where(Event.ingested_at >= now - timedelta(seconds=60))
    )
    total_events = await session.scalar(select(func.count()).select_from(Event))
    total_alerts = await session.scalar(select(func.count()).select_from(Alert))

    by_sev = {s.value: 0 for s in Severity}
    rows = await session.execute(
        select(Alert.severity, func.count())
        .where(Alert.status.in_(ACTIVE))
        .group_by(Alert.severity)
    )
    for sev, n in rows.all():
        by_sev[sev.value] = n

    counted = func.count().label("n")
    ips = await session.execute(
        select(Alert.source_ip, counted)
        .where(Alert.source_ip.is_not(None), Alert.status != AlertStatus.FALSE_POSITIVE)
        .group_by(Alert.source_ip)
        .order_by(desc("n"), Alert.source_ip)
        .limit(5)
    )
    techniques = await session.execute(
        select(Alert.mitre_technique, Alert.mitre_technique_name, counted)
        .where(Alert.status != AlertStatus.FALSE_POSITIVE)
        .group_by(Alert.mitre_technique, Alert.mitre_technique_name)
        .order_by(desc("n"), Alert.mitre_technique)
        .limit(5)
    )
    return StatsOut(
        events_per_sec=round((recent or 0) / 60, 2),
        total_events=total_events or 0,
        total_alerts=total_alerts or 0,
        active_by_severity=by_sev,
        top_ips=[(str(ip), n) for ip, n in ips.all()],
        top_techniques=[(f"{tid} {name}".strip(), n) for tid, name, n in techniques.all()],
    )
