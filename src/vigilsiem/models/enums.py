from __future__ import annotations

from enum import StrEnum


class Severity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_RANK[self]


_SEVERITY_RANK = {
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class AlertStatus(StrEnum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"


class EventCategory(StrEnum):
    AUTHENTICATION = "authentication"
    PRIVILEGE = "privilege"
    WEB = "web"
    APPLICATION = "application"
    SYSTEM = "system"


class SourceType(StrEnum):
    SSH = "ssh"
    NGINX = "nginx"
    JSON = "json"
