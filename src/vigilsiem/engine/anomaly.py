"""Behavioral anomaly scorer: rolling per-subject baselines.

Two detectors, both O(1) per event with LRU-bounded memory:
  * off-hours login  - per-user 24-bucket hour histogram; a successful login whose hour
    (and its neighbours) holds < ``hour_neighbor_share`` of that user's history is flagged
    once at least ``min_login_samples`` logins have been learned.
  * volume spike     - per-source-IP events/minute; the in-progress minute exceeding
    ``spike_factor`` x the rolling average of the previous ``history_buckets`` minutes
    (and ``spike_min_events`` in absolute terms) is flagged once per minute.

Hours are evaluated in UTC. The baseline is updated AFTER scoring so an anomalous event
does not excuse itself.
"""

from __future__ import annotations

from collections import OrderedDict, deque
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from vigilsiem.engine.detection import Detection
from vigilsiem.models.enums import EventCategory, Severity
from vigilsiem.models.schemas import SecurityEvent

OFF_HOURS_ID = "VSA-0001"
SPIKE_ID = "VSA-0002"


@dataclass(frozen=True)
class AnomalyConfig:
    min_login_samples: int = 20
    hour_neighbor_share: float = 0.05
    flag_cooldown: timedelta = timedelta(hours=1)
    spike_factor: float = 3.0
    spike_min_events: int = 20
    history_buckets: int = 30
    min_history: int = 5
    max_subjects: int = 10_000


@dataclass
class _LoginProfile:
    hours: list[int] = field(default_factory=lambda: [0] * 24)
    total: int = 0
    last_flag: datetime | None = None


@dataclass
class _VolumeProfile:
    history: deque[int]
    bucket: int | None = None
    count: int = 0
    flagged_bucket: int | None = None


def _bounded_get[T](
    store: OrderedDict[str, T], key: str, factory: Callable[[], T], limit: int
) -> T:
    value = store.get(key)
    if value is None:
        value = store[key] = factory()
        while len(store) > limit:
            store.popitem(last=False)
    store.move_to_end(key)
    return value


class AnomalyScorer:
    def __init__(self, config: AnomalyConfig | None = None) -> None:
        self.cfg = config or AnomalyConfig()
        self._logins: OrderedDict[str, _LoginProfile] = OrderedDict()
        self._volume: OrderedDict[str, _VolumeProfile] = OrderedDict()

    def score(self, event: SecurityEvent) -> list[Detection]:
        return [d for d in (self._off_hours(event), self._volume_spike(event)) if d is not None]

    # -- off-hours login --------------------------------------------------------
    def _off_hours(self, event: SecurityEvent) -> Detection | None:
        if (
            event.event_category is not EventCategory.AUTHENTICATION
            or event.status != "success"
            or not event.username
        ):
            return None
        profile = _bounded_get(self._logins, event.username, _LoginProfile, self.cfg.max_subjects)
        ts = event.timestamp
        hour = ts.hour
        detection = None
        if profile.total >= self.cfg.min_login_samples:
            near = sum(profile.hours[(hour + d) % 24] for d in (-1, 0, 1))
            share = near / profile.total
            recently = profile.last_flag and ts - profile.last_flag < self.cfg.flag_cooldown
            if share < self.cfg.hour_neighbor_share and not recently:
                profile.last_flag = ts
                detection = Detection(
                    rule_id=OFF_HOURS_ID,
                    rule_name="Login outside normal activity hours",
                    severity=Severity.MEDIUM,
                    mitre_tactic="Initial Access",
                    mitre_technique_id="T1078",
                    mitre_technique="Valid Accounts",
                    source_ip=str(event.source_ip) if event.source_ip else None,
                    username=event.username,
                    summary=(
                        f"Anomaly {1 - share:.2f}: {event.username} logged in at "
                        f"{hour:02d}:00 UTC; "
                        f"only {share:.1%} of {profile.total} prior logins were near this hour"
                    ),
                    timestamp=ts,
                    events=(event,),
                    kind="anomaly",
                )
        profile.hours[hour] += 1
        profile.total += 1
        return detection

    # -- volume spike -----------------------------------------------------------
    def _volume_spike(self, event: SecurityEvent) -> Detection | None:
        if event.source_ip is None:
            return None
        ip = str(event.source_ip)
        prof = _bounded_get(
            self._volume,
            ip,
            lambda: _VolumeProfile(history=deque(maxlen=self.cfg.history_buckets)),
            self.cfg.max_subjects,
        )
        minute = int(event.timestamp.timestamp() // 60)
        if prof.bucket is None:
            prof.bucket = minute
        elif minute < prof.bucket:
            return None  # late event: ignore for volume purposes
        elif minute > prof.bucket:
            prof.history.append(prof.count)
            gap = min(minute - prof.bucket - 1, self.cfg.history_buckets)
            prof.history.extend([0] * gap)
            prof.bucket, prof.count = minute, 0
        prof.count += 1

        if len(prof.history) < self.cfg.min_history or prof.flagged_bucket == minute:
            return None
        avg = sum(prof.history) / len(prof.history)
        if prof.count >= self.cfg.spike_min_events and prof.count > self.cfg.spike_factor * avg:
            prof.flagged_bucket = minute
            ratio = prof.count / avg if avg else float("inf")
            return Detection(
                rule_id=SPIKE_ID,
                rule_name="Log volume spike",
                severity=Severity.MEDIUM if ratio < 10 else Severity.HIGH,
                mitre_tactic="Reconnaissance",
                mitre_technique_id="T1595",
                mitre_technique="Active Scanning",
                source_ip=ip,
                username=event.username,
                summary=(
                    f"Anomaly: {ip} produced {prof.count} events this minute vs rolling "
                    f"average {avg:.1f} ({self.cfg.spike_factor:g}x threshold)"
                ),
                timestamp=event.timestamp,
                events=(event,),
                kind="anomaly",
            )
        return None
