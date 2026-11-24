"""Generic JSON application security-event parser (one JSON object per line)."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from typing import Any

from vigilsiem.models.enums import EventCategory
from vigilsiem.models.schemas import SecurityEvent
from vigilsiem.parsers.base import ParseContext, ParseError, clean_line, make_event, safe_ip, to_utc

_TS_KEYS = ("timestamp", "time", "@timestamp", "ts")
_SRC_KEYS = ("source_ip", "src_ip", "client_ip", "remote_addr")
_DST_KEYS = ("destination_ip", "dest_ip", "dst_ip")
_USER_KEYS = ("username", "user", "account")
_CAT_KEYS = ("event_category", "category")
_ACTION_KEYS = ("action", "event", "event_type")
_STATUS_KEYS = ("status", "outcome", "result")
_CONSUMED = set(
    _TS_KEYS + _SRC_KEYS + _DST_KEYS + _USER_KEYS + _CAT_KEYS + _ACTION_KEYS + _STATUS_KEYS
)
_OK = {"ok", "success", "succeeded", "allowed", "accepted", "pass"}
_BAD = {"fail", "failed", "failure", "error", "denied", "blocked", "rejected", "deny"}
_MIN_EPOCH, _MAX_EPOCH = 0, 4_102_444_800  # 1970 .. 2100


def _first(obj: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for key in keys:
        if key in obj and obj[key] is not None:
            return obj[key]
    return None


def _timestamp(value: Any, now: datetime) -> datetime:
    if value is None:
        return now
    if isinstance(value, bool):
        raise ParseError("bad timestamp")
    if isinstance(value, int | float):
        seconds = value / 1000 if value > 1e11 else value
        if not _MIN_EPOCH <= seconds <= _MAX_EPOCH:
            raise ParseError("timestamp out of range")
        return datetime.fromtimestamp(seconds, tz=UTC)
    if isinstance(value, str) and len(value) <= 64:
        try:
            return to_utc(datetime.fromisoformat(value))
        except ValueError as exc:
            raise ParseError("bad timestamp") from exc
    raise ParseError("bad timestamp")


def _text(value: Any, limit: int) -> str | None:
    return str(value)[:limit] if isinstance(value, str | int | float) and value != "" else None


def parse(line: str, ctx: ParseContext) -> SecurityEvent:
    raw = clean_line(line)
    try:
        obj = json.loads(raw)
    except (ValueError, RecursionError) as exc:
        raise ParseError("invalid JSON") from exc
    if not isinstance(obj, dict):
        raise ParseError("JSON event must be an object")

    category_raw = (_text(_first(obj, _CAT_KEYS), 32) or "").lower()
    try:
        category = EventCategory(category_raw)
    except ValueError:
        category = EventCategory.APPLICATION

    status_raw = (_text(_first(obj, _STATUS_KEYS), 32) or "unknown").lower()
    status = "success" if status_raw in _OK else "failure" if status_raw in _BAD else status_raw

    extras = {
        str(k)[:64]: v
        for k, v in obj.items()
        if k not in _CONSUMED and isinstance(v, str | int | float | bool)
    }
    return make_event(
        ctx,
        timestamp=_timestamp(_first(obj, _TS_KEYS), ctx.now),
        category=category,
        action=(_text(_first(obj, _ACTION_KEYS), 64) or "event"),
        status=status,
        raw=raw,
        source_ip=safe_ip(_text(_first(obj, _SRC_KEYS), 45)),
        destination_ip=safe_ip(_text(_first(obj, _DST_KEYS), 45)),
        username=_text(_first(obj, _USER_KEYS), 128),
        metadata=extras,
    )
