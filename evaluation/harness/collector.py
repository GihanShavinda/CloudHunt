from __future__ import annotations
from dataclasses import dataclass, field

@dataclass
class RunArtifacts:
    events: list = field(default_factory=list)
    detections: list = field(default_factory=list)
    cases: list = field(default_factory=list)
    chains: list = field(default_factory=list)
    privesc_paths: dict = field(default_factory=dict)
    blast_scores: dict = field(default_factory=dict)
