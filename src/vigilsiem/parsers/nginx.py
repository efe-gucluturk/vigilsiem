"""Nginx/Apache "combined" access-log parser."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta, timezone
from urllib.parse import urlsplit

from vigilsiem.models.enums import EventCategory
from vigilsiem.models.schemas import SecurityEvent
from vigilsiem.parsers.base import MONTHS, ParseContext, ParseError, clean_line, make_event, safe_ip

_LINE = re.compile(
    r"^(?P<ip>[0-9A-Fa-f:.]{2,45}) \S{1,64} (?P<user>\S{1,64}) "
    r"\[(?P<d>\d{2})/(?P<mon>[A-Za-z]{3})/(?P<y>\d{4}):(?P<h>\d{2}):(?P<mi>\d{2}):(?P<s>\d{2}) "
    r"(?P<tz>[+-]\d{4})\] "
    r'"(?P<req>[^"]{0,4096})" (?P<status>\d{3}) (?P<bytes>\d{1,12}|-)'
    r'(?: "(?P<ref>[^"]{0,1024})" "(?P<ua>[^"]{0,1024})")?'
)
_METHOD = re.compile(r"^[A-Z]{3,10}$")
_URI_CAP = 1024


def _timestamp(m: re.Match[str]) -> datetime:
    month = MONTHS.get(m["mon"].title())
    if month is None:
        raise ParseError("bad month")
    sign = -1 if m["tz"][0] == "-" else 1
    offset = timedelta(hours=int(m["tz"][1:3]), minutes=int(m["tz"][3:5])) * sign
    try:
        local = datetime(
            int(m["y"]),
            month,
            int(m["d"]),
            int(m["h"]),
            int(m["mi"]),
            int(m["s"]),
            tzinfo=timezone(offset),
        )
    except ValueError as exc:
        raise ParseError("bad access-log timestamp") from exc
    return local.astimezone(UTC)


def parse(line: str, ctx: ParseContext) -> SecurityEvent:
    raw = clean_line(line)
    m = _LINE.match(raw)
    if not m:
        raise ParseError("not a combined access-log line")

    method, uri, proto = "UNKNOWN", m["req"][:_URI_CAP], None
    first, _, rest = m["req"].partition(" ")
    if _METHOD.match(first) and rest:
        # The URI is everything between the method and a trailing "HTTP/x" token, so raw
        # spaces in a (malformed) request target cannot truncate the inspected payload.
        target, _, last = rest.rpartition(" ")
        if target and last.startswith("HTTP/"):
            method, uri, proto = first, target[:_URI_CAP], last[:16]
        else:
            method, uri = first, rest[:_URI_CAP]

    path = query = None
    try:
        split = urlsplit(uri)
        path, query = split.path[:_URI_CAP], split.query[:_URI_CAP] or None
    except ValueError:
        pass  # malformed URI (e.g. bad IPv6 bracket): keep raw uri only

    code = int(m["status"])
    user = None if m["user"] == "-" else m["user"]
    return make_event(
        ctx,
        timestamp=_timestamp(m),
        category=EventCategory.WEB,
        action="http_request",
        status="success" if code < 400 else "failure",
        raw=raw,
        source_ip=safe_ip(m["ip"]),
        username=user,
        metadata={
            "method": method,
            "uri": uri,
            "path": path,
            "query": query,
            "protocol": proto,
            "status_code": code,
            "bytes": None if m["bytes"] == "-" else int(m["bytes"]),
            "referrer": None if m["ref"] in (None, "-") else m["ref"],
            "user_agent": None if m["ua"] in (None, "-") else m["ua"],
        },
    )
