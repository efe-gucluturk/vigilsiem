"""Rule engine: stateless signatures + stateful time-window correlation.

State is keyed per (rule, group value), LRU-bounded, and driven by EVENT timestamps
(so replays/backfills behave deterministically). After a stateful rule fires it enters a
cool-down of one window for that key, so a sustained attack yields one alert per window
rather than an alert flood.
"""

from __future__ import annotations

from collections import Counter, OrderedDict, deque
from collections.abc import Callable, Iterable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any

from vigilsiem.engine.detection import Detection
from vigilsiem.engine.fields import get_field
from vigilsiem.engine.matchers import build_all
from vigilsiem.engine.rules import LoadedRule, RuleSpec, load_rules
from vigilsiem.models.schemas import SecurityEvent

MAX_KEYS_PER_RULE = 10_000
_NO_HIT = (False, None)

Outcome = tuple[bool, Detection | None]


@dataclass
class _Slot:
    events: deque[tuple[datetime, SecurityEvent, Any]] = field(default_factory=deque)
    latest: datetime | None = None
    cooldown_until: datetime | None = None
    stage: int = 0
    chain: list[SecurityEvent] = field(default_factory=list)


class _Rule:
    def __init__(self, spec: RuleSpec) -> None:
        self.spec = spec
        self.window = timedelta(seconds=spec.window_seconds)
        self._slots: OrderedDict[str, _Slot] = OrderedDict()

    def _slot(self, key: str) -> _Slot:
        slot = self._slots.get(key)
        if slot is None:
            slot = self._slots[key] = _Slot()
            while len(self._slots) > MAX_KEYS_PER_RULE:
                self._slots.popitem(last=False)
        self._slots.move_to_end(key)
        return slot

    def _key(self, event: SecurityEvent) -> str | None:
        value = get_field(event, self.spec.group_by) if self.spec.group_by else None
        return None if value is None else str(value)

    def _push(self, slot: _Slot, event: SecurityEvent, value: Any) -> bool:
        ts = event.timestamp
        ref = max(ts, slot.latest) if slot.latest else ts
        slot.latest = ref
        cutoff = ref - self.window
        if ts < cutoff:
            return False  # too old to matter
        slot.events = deque(x for x in slot.events if x[0] >= cutoff)
        slot.events.append((ts, event, value))
        return True

    def _fire(
        self, slot: _Slot, event: SecurityEvent, evidence: list[SecurityEvent], text: str
    ) -> Detection:
        slot.cooldown_until = event.timestamp + self.window
        s = self.spec
        src = next((str(e.source_ip) for e in reversed(evidence) if e.source_ip), None)
        user = next((e.username for e in reversed(evidence) if e.username), None)
        return Detection(
            rule_id=s.id,
            rule_name=s.name,
            severity=s.severity,
            mitre_tactic=s.mitre.tactic,
            mitre_technique_id=s.mitre.technique_id,
            mitre_technique=s.mitre.technique,
            source_ip=src,
            username=user,
            summary=f"{s.name}: {text}",
            timestamp=event.timestamp,
            events=tuple(evidence),
        )

    def _cooling(self, slot: _Slot, ts: datetime) -> bool:
        return slot.cooldown_until is not None and ts < slot.cooldown_until

    def process(self, event: SecurityEvent) -> Outcome:  # pragma: no cover - abstract
        raise NotImplementedError


class _Signature(_Rule):
    def __init__(self, spec: RuleSpec) -> None:
        super().__init__(spec)
        self._match = build_all(spec.match)

    def process(self, event: SecurityEvent) -> Outcome:
        if not self._match(event):
            return _NO_HIT
        key = self._key(event) or (str(event.source_ip) if event.source_ip else None)
        key = key or event.username or "*"
        slot = self._slot(key)
        if (
            self.spec.dedupe_seconds
            and slot.cooldown_until
            and event.timestamp < slot.cooldown_until
        ):
            return True, None  # a hit, but de-duplicated
        det = self._fire(slot, event, [event], f"signature matched from {key}")
        slot.cooldown_until = event.timestamp + timedelta(seconds=self.spec.dedupe_seconds)
        return True, det


class _Counting(_Rule):
    def __init__(self, spec: RuleSpec) -> None:
        super().__init__(spec)
        self._match = build_all(spec.match)

    def _value(self, event: SecurityEvent) -> Any:
        return event.timestamp

    def _count(self, slot: _Slot) -> int:
        return len(slot.events)

    def _describe(self, key: str, n: int) -> str:
        return f"{n} matching events from {key} within {self.spec.window_seconds}s"

    def process(self, event: SecurityEvent) -> Outcome:
        if not self._match(event):
            return _NO_HIT
        key = self._key(event)
        value = self._value(event)
        if key is None or value is None:
            return _NO_HIT
        slot = self._slot(key)
        if not self._push(slot, event, value) or self._cooling(slot, event.timestamp):
            return _NO_HIT
        n = self._count(slot)
        if n < self.spec.threshold:
            return _NO_HIT
        evidence = [e for _, e, _ in slot.events]
        slot.events.clear()
        return True, self._fire(slot, event, evidence, self._describe(key, n))


class _Threshold(_Counting):
    pass


class _Distinct(_Counting):
    def _value(self, event: SecurityEvent) -> Any:
        field_path = self.spec.distinct_field
        return get_field(event, field_path) if field_path else None

    def _count(self, slot: _Slot) -> int:
        return len({v for _, _, v in slot.events})

    def _describe(self, key: str, n: int) -> str:
        return (
            f"{n} distinct {self.spec.distinct_field} values from {key} "
            f"within {self.spec.window_seconds}s"
        )


class _Sequence(_Rule):
    def __init__(self, spec: RuleSpec) -> None:
        super().__init__(spec)
        self._steps = tuple(build_all(step.match) for step in spec.steps)

    def process(self, event: SecurityEvent) -> Outcome:
        key = self._key(event)
        if key is None:
            return _NO_HIT
        # Only touch state if the event can advance (or start) a chain.
        slot = self._slot(key)
        ts = event.timestamp
        if slot.stage:
            if ts - slot.chain[0].timestamp > self.window:
                slot.stage, slot.chain = 0, []  # chain expired; this event may start a new one
            elif ts < slot.chain[-1].timestamp:
                return _NO_HIT  # out-of-order event
        if not self._steps[slot.stage](event):
            return _NO_HIT
        slot.chain.append(event)
        slot.stage += 1
        if slot.stage < len(self._steps):
            return _NO_HIT
        evidence, slot.stage, slot.chain = slot.chain, 0, []
        if self._cooling(slot, ts):
            return _NO_HIT
        return True, self._fire(
            slot,
            event,
            evidence,
            f"{len(evidence)}-step sequence for {key} within {self.spec.window_seconds}s",
        )


_FACTORIES: dict[str, Callable[[RuleSpec], _Rule]] = {
    "signature": _Signature,
    "threshold": _Threshold,
    "distinct": _Distinct,
    "sequence": _Sequence,
}


class RuleEngine:
    def __init__(
        self,
        specs: Iterable[RuleSpec],
        *,
        sources: Mapping[str, str] | None = None,
    ) -> None:
        self._all: list[RuleSpec] = []
        self._rules: list[_Rule] = []
        self._sources: dict[str, str] = {}
        self.hits: Counter[str] = Counter()
        self.replace_rules(specs, sources=sources)

    # -- construction / hot reload ------------------------------------------
    @classmethod
    def from_directory(cls, directory: str | Path) -> RuleEngine:
        loaded = load_rules(directory)
        return cls((r.spec for r in loaded), sources={r.spec.id: r.source for r in loaded})

    def reload_from_directory(self, directory: str | Path) -> int:
        """Validate everything first; swap only on full success (old rules stay on error)."""
        loaded: list[LoadedRule] = load_rules(directory)
        self.replace_rules((r.spec for r in loaded), sources={r.spec.id: r.source for r in loaded})
        return len(loaded)

    def replace_rules(
        self, specs: Iterable[RuleSpec], *, sources: Mapping[str, str] | None = None
    ) -> None:
        all_specs = list(specs)
        compiled = [
            _FACTORIES[s.type](s) for s in all_specs if s.enabled
        ]  # may raise: nothing swapped
        self._all, self._rules = all_specs, compiled
        self._sources = dict(sources or {})

    # -- evaluation ------------------------------------------------------------
    def evaluate(self, event: SecurityEvent) -> list[Detection]:
        detections: list[Detection] = []
        for rule in self._rules:
            hit, detection = rule.process(event)
            if hit:
                self.hits[rule.spec.id] += 1
            if detection is not None:
                detections.append(detection)
        return detections

    # -- introspection (dashboard rules viewer) -----------------------------------
    def describe(self) -> list[dict[str, Any]]:
        return [
            {
                "id": s.id,
                "name": s.name,
                "description": s.description,
                "severity": s.severity.value,
                "type": s.type,
                "enabled": s.enabled,
                "mitre_tactic": s.mitre.tactic,
                "mitre_technique_id": s.mitre.technique_id,
                "mitre_technique": s.mitre.technique,
                "hits": self.hits.get(s.id, 0),
                "source": self._sources.get(s.id, ""),
            }
            for s in self._all
        ]
