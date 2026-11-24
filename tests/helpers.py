from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from vigilsiem.models.enums import SourceType
from vigilsiem.models.schemas import SecurityEvent
from vigilsiem.parsers.normalizer import normalize_batch

RULES_DIR = Path(__file__).resolve().parents[1] / "rules"
NOW = datetime(2026, 11, 24, 12, 0, 0, tzinfo=UTC)


def syslog_ts(ts: datetime) -> str:
    return f"{ts:%b} {ts.day:2d} {ts:%H:%M:%S}"


def ssh_failed(ts: datetime, ip: str = "203.0.113.9", user: str = "root") -> str:
    return f"{syslog_ts(ts)} web01 sshd[100]: Failed password for {user} from {ip} port 4444 ssh2"


def ssh_ok(ts: datetime, ip: str = "198.51.100.7", user: str = "alice") -> str:
    return (
        f"{syslog_ts(ts)} web01 sshd[101]: Accepted publickey for {user} from {ip} port 5555 ssh2"
    )


def nginx_line(
    ts: datetime,
    uri: str = "/",
    ip: str = "198.51.100.20",
    code: int = 200,
    ua: str = "Mozilla/5.0",
) -> str:
    return f'{ip} - - [{ts:%d/%b/%Y:%H:%M:%S} +0000] "GET {uri} HTTP/1.1" {code} 512 "-" "{ua}"'


def events(source: SourceType, lines: list[str], now: datetime = NOW) -> list[SecurityEvent]:
    result = normalize_batch(source, "web01", lines, now=now)
    assert result.rejected == 0, result.errors
    return result.events


def at(seconds: float) -> datetime:
    return NOW + timedelta(seconds=seconds)
