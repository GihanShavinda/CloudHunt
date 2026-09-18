from __future__ import annotations
from dataclasses import asdict, dataclass, field
from typing import Any

@dataclass
class EvaluationResult:
    scenario: str
    passed: bool
    duration_ms: float = 0.0
    detections_expected: list[str] = field(default_factory=list)
    detections_actual: list[str] = field(default_factory=list)
    precision: float = 0.0
    recall: float = 0.0
    f1: float = 0.0
    false_positive_rate: float = 0.0
    correlation_score: float = 0.0
    privesc_path_score: float = 0.0
    chain_accuracy: float = 0.0
    blast_rank_correct: bool | None = None
    safety_violations: int = 0
    notes: list[str] = field(default_factory=list)
    attack_ids: list[str] = field(default_factory=list)
    timing: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

@dataclass
class EvaluationSummary:
    scenarios_total: int = 0
    scenarios_passed: int = 0
    scenarios_failed: int = 0
    overall_precision: float = 0.0
    overall_recall: float = 0.0
    overall_f1: float = 0.0
    overall_fpr: float = 0.0
    average_chain_accuracy: float = 0.0
    average_privesc_accuracy: float = 0.0
    average_correlation_accuracy: float = 0.0
    safety_violations: int = 0
    total_runtime_ms: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
