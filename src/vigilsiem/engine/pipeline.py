"""Detection pipeline: events -> rule engine + anomaly scorer -> detections."""

from __future__ import annotations

from collections.abc import Iterable

from vigilsiem.engine.anomaly import AnomalyScorer
from vigilsiem.engine.correlation import RuleEngine
from vigilsiem.engine.detection import Detection
from vigilsiem.models.schemas import SecurityEvent


class DetectionPipeline:
    def __init__(self, rules: RuleEngine, scorer: AnomalyScorer | None = None) -> None:
        self.rules = rules
        self.scorer = scorer or AnomalyScorer()

    def process(self, events: Iterable[SecurityEvent]) -> list[Detection]:
        detections: list[Detection] = []
        for event in events:
            detections.extend(self.rules.evaluate(event))
            detections.extend(self.scorer.score(event))
        return detections
