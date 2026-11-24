"""Field addressing for rules: top-level event fields or ``metadata.<key>``."""

from __future__ import annotations

from vigilsiem.models.schemas import SecurityEvent

TOP_LEVEL = (
    "source_ip",
    "destination_ip",
    "username",
    "event_category",
    "action",
    "status",
    "raw_log",
)
FIELD_PATTERN = r"^(?:" + "|".join(TOP_LEVEL) + r"|metadata\.[A-Za-z0-9_]{1,64})$"
_META = "metadata."


def get_field(event: SecurityEvent, path: str) -> str | int | float | bool | None:
    if path.startswith(_META):
        return event.metadata.get(path[len(_META) :])
    if path not in TOP_LEVEL:
        return None
    value = getattr(event, path)
    if value is None:
        return None
    if path == "event_category":
        return value.value
    return value if isinstance(value, str) else str(value)
