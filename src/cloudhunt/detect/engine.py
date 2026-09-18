"""The detection engine — wires the three layers over one event stream.

    engine = DetectionEngine()                       # loads YAML rules
    result = engine.run(events,
                        baseline_events=history,      # optional Layer-2 training
                        privesc_paths=paths_by_arn)   # optional M3 enrichment

Layer 1 (signatures) runs per event; Layer 2 (behavioural) fits a baseline from
``baseline_events`` (if given) then scores the stream; Layer 3 (correlation)
clusters everything into candidate cases. New-geo scoring is skipped when no
baseline is supplied (there is nothing to be "new" against).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable, Optional

from cloudhunt.detect.base import Detection
from cloudhunt.detect.baselines import BaselineModel, BehaviouralEngine
from cloudhunt.detect.correlate import CloudCase, correlate, enrich_with_privesc
from cloudhunt.detect.signatures import SignatureEngine, load_rules
from cloudhunt.models.events import CloudEvent


@dataclass
class DetectionResult:
    detections: list[Detection] = field(default_factory=list)
    cases: list[CloudCase] = field(default_factory=list)


class DetectionEngine:
    def __init__(
        self,
        rules_dir: Optional[str] = None,
        automation_principals: Optional[set[str]] = None,
        correlation_window_minutes: int = 60,
        behavioural_kwargs: Optional[dict] = None,
    ):
        self.signatures = SignatureEngine(load_rules(rules_dir))
        self.automation_principals = automation_principals or set()
        self.correlation_window_minutes = correlation_window_minutes
        self.behavioural_kwargs = behavioural_kwargs or {}

    def run(
        self,
        events: Iterable[CloudEvent],
        baseline_events: Optional[Iterable[CloudEvent]] = None,
        privesc_paths: Optional[dict] = None,
        advanced_detections: Optional[Iterable[Detection]] = None,
    ) -> DetectionResult:
        events = list(events)
        detections: list[Detection] = []

        # Layer 1 — signatures
        for e in events:
            detections.extend(self.signatures.match(e))

        # Layer 2 — behavioural
        model = BaselineModel.fit(baseline_events) if baseline_events is not None else None
        behavioural = BehaviouralEngine(
            model=model, automation_principals=self.automation_principals,
            **self.behavioural_kwargs,
        )
        detections.extend(behavioural.run(events))

        # Milestone 8 — configuration/graph/baseline findings are computed from
        # snapshot-aware detectors and injected here so they use the same case
        # correlation pipeline. No AWS writes or UI coupling occur in this step.
        if advanced_detections is not None:
            detections.extend(list(advanced_detections))

        # Layer 3 — correlation
        cases = correlate(detections, self.correlation_window_minutes)
        if privesc_paths:
            for case in cases:
                enrich_with_privesc(case, privesc_paths)
            cases.sort(key=lambda c: c.score, reverse=True)

        return DetectionResult(detections=detections, cases=cases)
