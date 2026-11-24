"""Batch normalization: raw lines -> unified SecurityEvents, with per-line isolation."""

from __future__ import annotations

from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime

from vigilsiem.models.enums import SourceType
from vigilsiem.models.schemas import SecurityEvent
from vigilsiem.parsers import json_app, nginx, ssh
from vigilsiem.parsers.base import ParseContext, ParseError

Parser = Callable[[str, ParseContext], SecurityEvent]

PARSERS: dict[SourceType, Parser] = {
    SourceType.SSH: ssh.parse,
    SourceType.NGINX: nginx.parse,
    SourceType.JSON: json_app.parse,
}
_MAX_REPORTED_ERRORS = 10


@dataclass
class NormalizeResult:
    events: list[SecurityEvent] = field(default_factory=list)
    rejected: int = 0
    # (line index, reason) only: raw content is never echoed back.
    errors: list[tuple[int, str]] = field(default_factory=list)


def normalize_batch(
    source_type: SourceType,
    host: str,
    lines: Sequence[str],
    *,
    now: datetime | None = None,
) -> NormalizeResult:
    parser = PARSERS[source_type]
    ctx = ParseContext(host=host, source_type=source_type, now=now or datetime.now(UTC))
    result = NormalizeResult()
    for index, line in enumerate(lines):
        try:
            result.events.append(parser(line, ctx))
        except ParseError as exc:
            result.rejected += 1
            if len(result.errors) < _MAX_REPORTED_ERRORS:
                result.errors.append((index, str(exc)))
    return result
