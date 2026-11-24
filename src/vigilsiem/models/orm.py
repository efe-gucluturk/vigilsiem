"""SQLAlchemy 2.0 ORM tables. All queries use bound parameters via the ORM/Core API."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import JSON, Boolean, DateTime, Enum, Index, Integer, String, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column

from vigilsiem.models.enums import AlertStatus, EventCategory, Severity


def utcnow() -> datetime:
    return datetime.now(UTC)


class Base(DeclarativeBase):
    pass


class ApiKey(Base):
    """Agent ingestion key. Only the SHA-256 hash is stored; plaintext is shown once."""

    __tablename__ = "api_keys"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    key_prefix: Mapped[str] = mapped_column(String(16), unique=True, index=True)
    key_hash: Mapped[str] = mapped_column(String(64))
    revoked: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    last_used_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


class AdminUser(Base):
    __tablename__ = "admin_users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True)
    password_hash: Mapped[str] = mapped_column(String(256))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class Event(Base):
    __tablename__ = "events"
    __table_args__ = (
        Index("ix_events_ts", "timestamp"),
        Index("ix_events_src", "source_ip"),
    )

    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    ingested_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    source_ip: Mapped[str | None] = mapped_column(String(45))
    destination_ip: Mapped[str | None] = mapped_column(String(45))
    username: Mapped[str | None] = mapped_column(String(128))
    category: Mapped[EventCategory] = mapped_column(Enum(EventCategory, native_enum=False))
    action: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(32))
    raw_log: Mapped[str] = mapped_column(Text)
    meta: Mapped[dict[str, Any]] = mapped_column("metadata", JSON, default=dict)


class Alert(Base):
    __tablename__ = "alerts"
    __table_args__ = (Index("ix_alerts_status_sev", "status", "severity"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    rule_id: Mapped[str] = mapped_column(String(64), index=True)
    rule_name: Mapped[str] = mapped_column(String(128))
    severity: Mapped[Severity] = mapped_column(Enum(Severity, native_enum=False))
    status: Mapped[AlertStatus] = mapped_column(
        Enum(AlertStatus, native_enum=False), default=AlertStatus.OPEN
    )
    mitre_tactic: Mapped[str] = mapped_column(String(64))
    mitre_technique: Mapped[str] = mapped_column(String(16))  # technique ID, e.g. T1110
    mitre_technique_name: Mapped[str] = mapped_column(String(96), default="")
    source_ip: Mapped[str | None] = mapped_column(String(45), index=True)
    username: Mapped[str | None] = mapped_column(String(128))
    summary: Mapped[str] = mapped_column(String(512))
    event_ids: Mapped[list[int]] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utcnow, onupdate=utcnow
    )


class WebhookConfig(Base):
    __tablename__ = "webhook_configs"

    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(64), unique=True)
    url: Mapped[str] = mapped_column(String(2048))
    min_severity: Mapped[Severity] = mapped_column(
        Enum(Severity, native_enum=False), default=Severity.HIGH
    )
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utcnow)


class RuleHit(Base):
    """Per-rule hit counter shown in the dashboard rules viewer."""

    __tablename__ = "rule_hits"

    rule_id: Mapped[str] = mapped_column(String(64), primary_key=True)
    hits: Mapped[int] = mapped_column(Integer, default=0)
    last_hit_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))


__all__ = [
    "AdminUser",
    "Alert",
    "ApiKey",
    "Base",
    "Event",
    "RuleHit",
    "WebhookConfig",
]
