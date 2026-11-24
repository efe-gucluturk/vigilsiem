"""Detection: the common output of rules and the anomaly scorer."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Literal

from vigilsiem.models.enums import Severity
from vigilsiem.models.schemas import SecurityEvent

MAX_EVIDENCE = 20
MAX_SUMMARY = 512


@dataclass(frozen=True, slots=True)
class Detection:
    rule_id: str
    rule_name: str
    severity: Severity
    mitre_tactic: str
    mitre_technique_id: str
    mitre_technique: str
    source_ip: str | None
    username: str | None
    summary: str
    timestamp: datetime
    events: tuple[SecurityEvent, ...]
    kind: Literal["rule", "anomaly"] = "rule"

    def __post_init__(self) -> None:
        if len(self.summary) > MAX_SUMMARY:
            object.__setattr__(self, "summary", self.summary[: MAX_SUMMARY - 1] + "…")
        if len(self.events) > MAX_EVIDENCE:
            object.__setattr__(self, "events", self.events[-MAX_EVIDENCE:])
