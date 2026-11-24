"""Strict Pydantic v2 request/response models. Unknown fields are always rejected."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated

from pydantic import BaseModel, ConfigDict, Field, IPvAnyAddress, SecretStr, field_validator

from vigilsiem.models.enums import AlertStatus, EventCategory, Severity, SourceType

MAX_RAW_LINE = 8192
MAX_METADATA_ITEMS = 32
_HOST_PATTERN = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"

MetaValue = str | int | float | bool | None


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True, frozen=True)


class SecurityEvent(StrictModel):
    """Unified Security Event Schema produced by every parser."""

    timestamp: datetime
    source_ip: IPvAnyAddress | None = None
    destination_ip: IPvAnyAddress | None = None
    username: Annotated[str, Field(max_length=128)] | None = None
    event_category: EventCategory
    action: Annotated[str, Field(min_length=1, max_length=64)]
    status: Annotated[str, Field(min_length=1, max_length=32)]
    raw_log: Annotated[str, Field(max_length=MAX_RAW_LINE)]
    metadata: dict[Annotated[str, Field(max_length=64)], MetaValue] = Field(default_factory=dict)

    @field_validator("metadata")
    @classmethod
    def _bound_metadata(cls, value: dict[str, MetaValue]) -> dict[str, MetaValue]:
        if len(value) > MAX_METADATA_ITEMS:
            raise ValueError("too many metadata items")
        for v in value.values():
            if isinstance(v, str) and len(v) > 1024:
                raise ValueError("metadata value too long")
        return value


class IngestBatch(StrictModel):
    """Batch of raw log lines from an agent. Lines are parsed server-side."""

    source_type: SourceType
    host: Annotated[str, Field(pattern=_HOST_PATTERN)]
    lines: Annotated[
        list[Annotated[str, Field(min_length=1, max_length=MAX_RAW_LINE)]],
        Field(min_length=1, max_length=5000),
    ]


class IngestResult(StrictModel):
    accepted: int
    rejected: int
    alerts_created: int


class LoginRequest(StrictModel):
    username: Annotated[str, Field(min_length=3, max_length=64)]
    password: Annotated[SecretStr, Field(min_length=1, max_length=128)]


class AlertTriage(StrictModel):
    status: AlertStatus


class WebhookCreate(StrictModel):
    name: Annotated[str, Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9 ._-]+$")]
    url: Annotated[str, Field(min_length=12, max_length=2048)]
    min_severity: Severity = Severity.HIGH
    enabled: bool = True

    @field_validator("min_severity")
    @classmethod
    def _high_or_critical_only(cls, value: Severity) -> Severity:
        if value.rank < Severity.HIGH.rank:
            raise ValueError("webhooks are limited to high/critical alerts")
        return value


# --- Response models (explicit allow-list of fields; never return ORM rows directly) ---------


class ResponseModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class EventOut(ResponseModel):
    id: int
    timestamp: datetime
    source_ip: str | None
    destination_ip: str | None
    username: str | None
    category: EventCategory
    action: str
    status: str
    raw_log: str
    meta: dict[str, MetaValue]


class AlertOut(ResponseModel):
    id: int
    rule_id: str
    rule_name: str
    severity: Severity
    status: AlertStatus
    mitre_tactic: str
    mitre_technique: str
    mitre_technique_name: str
    source_ip: str | None
    username: str | None
    summary: str
    created_at: datetime
    updated_at: datetime


class AlertDetail(AlertOut):
    events: list[EventOut] = []
    rule_source: str | None = None


class WebhookOut(ResponseModel):
    id: int
    name: str
    url_masked: str  # the full URL is a bearer secret: it is never returned
    min_severity: Severity
    enabled: bool


class StatsOut(ResponseModel):
    events_per_sec: float
    total_events: int
    total_alerts: int
    active_by_severity: dict[str, int]
    top_ips: list[tuple[str, int]]
    top_techniques: list[tuple[str, int]]
