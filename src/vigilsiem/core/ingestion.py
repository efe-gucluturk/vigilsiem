"""Ingest orchestration: parse -> persist events -> detect -> persist alerts."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from vigilsiem.engine.detection import Detection
from vigilsiem.engine.pipeline import DetectionPipeline
from vigilsiem.models.orm import Alert, Event, RuleHit
from vigilsiem.models.schemas import IngestBatch
from vigilsiem.parsers.normalizer import normalize_batch


@dataclass
class IngestOutcome:
    accepted: int
    rejected: int
    new_alerts: list[tuple[Alert, Detection]]


async def ingest_batch(
    session: AsyncSession, pipeline: DetectionPipeline, batch: IngestBatch
) -> IngestOutcome:
    result = normalize_batch(batch.source_type, batch.host, batch.lines)

    rows = [
        Event(
            timestamp=e.timestamp,
            source_ip=str(e.source_ip) if e.source_ip else None,
            destination_ip=str(e.destination_ip) if e.destination_ip else None,
            username=e.username,
            category=e.event_category,
            action=e.action,
            status=e.status,
            raw_log=e.raw_log,
            meta=dict(e.metadata),
        )
        for e in result.events
    ]
    session.add_all(rows)
    await session.flush()
    row_id = {id(e): r.id for e, r in zip(result.events, rows, strict=True)}

    # Synchronous section (no awaits): the shared rule-engine state is mutated atomically.
    before = dict(pipeline.rules.hits)
    detections = pipeline.process(result.events)
    changed = {k: v for k, v in pipeline.rules.hits.items() if v != before.get(k, 0)}

    alerts: list[tuple[Alert, Detection]] = []
    for d in detections:
        alert = Alert(
            rule_id=d.rule_id,
            rule_name=d.rule_name,
            severity=d.severity,
            mitre_tactic=d.mitre_tactic,
            mitre_technique=d.mitre_technique_id,
            mitre_technique_name=d.mitre_technique,
            source_ip=d.source_ip,
            username=d.username,
            summary=d.summary,
            event_ids=[row_id[id(e)] for e in d.events if id(e) in row_id],
        )
        session.add(alert)
        alerts.append((alert, d))

    now = datetime.now(UTC)
    for rule_id, hits in changed.items():
        row = await session.get(RuleHit, rule_id)
        if row is None:
            session.add(RuleHit(rule_id=rule_id, hits=hits, last_hit_at=now))
        else:
            row.hits, row.last_hit_at = hits, now
    await session.flush()
    return IngestOutcome(len(rows), result.rejected, alerts)


async def restore_rule_hits(session: AsyncSession, pipeline: DetectionPipeline) -> None:
    for row in (await session.scalars(select(RuleHit))).all():
        pipeline.rules.hits[row.rule_id] = row.hits
