"""Shared parser plumbing.

ReDoS policy for parsers: every regex is precompiled, anchored at ``^``, uses only
bounded character classes / quantifiers on delimited tokens, and never nests
quantifiers. Input is length-capped (``MAX_RAW_LINE``) before any regex runs, so
worst-case matching time is linear in a small constant.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from ipaddress import ip_address
from typing import Any

from pydantic import ValidationError

from vigilsiem.models.enums import EventCategory, SourceType
from vigilsiem.models.schemas import MAX_RAW_LINE, SecurityEvent

MAX_META_VALUE = 1024
MONTHS = {
    m: i
    for i, m in enumerate(
        ("Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), 1
    )
}

# Strip control characters (incl. CR/LF, so a forged multi-line entry cannot spoof
# extra log records when rendered). Tab is preserved.
_CONTROL = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")


class ParseError(ValueError):
    """A line could not be parsed into a SecurityEvent. Message is safe to log."""


@dataclass(frozen=True)
class ParseContext:
    host: str
    source_type: SourceType
    now: datetime


def clean_line(line: str) -> str:
    if len(line) > MAX_RAW_LINE:
        raise ParseError("line too long")
    cleaned = _CONTROL.sub(" ", line).strip()
    if not cleaned:
        raise ParseError("empty line")
    return cleaned


def safe_ip(text: str | None) -> str | None:
    if not text:
        return None
    try:
        return str(ip_address(text.split("%", 1)[0]))
    except ValueError:
        return None


def to_utc(ts: datetime) -> datetime:
    return ts.replace(tzinfo=UTC) if ts.tzinfo is None else ts.astimezone(UTC)


def syslog_timestamp(mon: str, day: str, hms: tuple[str, str, str], now: datetime) -> datetime:
    """Syslog stamps carry no year: assume the current one, roll back if it lands in the future."""
    month = MONTHS.get(mon)
    if month is None:
        raise ParseError("bad month")
    try:
        ts = datetime(now.year, month, int(day), int(hms[0]), int(hms[1]), int(hms[2]), tzinfo=UTC)
    except ValueError as exc:
        raise ParseError("bad syslog timestamp") from exc
    if ts > now + timedelta(days=1):
        ts = ts.replace(year=ts.year - 1)
    return ts


def cap(value: Any, limit: int = MAX_META_VALUE) -> Any:
    return value[:limit] if isinstance(value, str) else value


def make_event(
    ctx: ParseContext,
    *,
    timestamp: datetime,
    category: EventCategory,
    action: str,
    status: str,
    raw: str,
    source_ip: str | None = None,
    destination_ip: str | None = None,
    username: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> SecurityEvent:
    meta: dict[str, Any] = {"host": ctx.host, "source_type": ctx.source_type.value}
    for key, value in (metadata or {}).items():
        if value is not None and len(meta) < 32:
            meta[str(key)[:64]] = cap(value)
    try:
        return SecurityEvent(
            timestamp=to_utc(timestamp),
            source_ip=source_ip,
            destination_ip=destination_ip,
            username=(username or None) and username[:128],
            event_category=category,
            action=action,
            status=status,
            raw_log=raw,
            metadata=meta,
        )
    except ValidationError as exc:
        raise ParseError("event failed schema validation") from exc
