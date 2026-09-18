from __future__ import annotations
from dataclasses import dataclass, asdict

@dataclass(frozen=True)
class DetectionMetrics:
    tp: int
    fp: int
    tn: int
    fn: int
    precision: float
    recall: float
    f1: float
    false_positive_rate: float

    def to_dict(self):
        return asdict(self)

def _safe(n: float, d: float) -> float:
    return n / d if d else 0.0

def from_counts(tp: int, fp: int, tn: int, fn: int) -> DetectionMetrics:
    precision = _safe(tp, tp + fp)
    recall = _safe(tp, tp + fn)
    f1 = _safe(2 * precision * recall, precision + recall)
    fpr = _safe(fp, fp + tn)
    return DetectionMetrics(tp, fp, tn, fn, precision, recall, f1, fpr)

def binary_metrics(expected_attack: list[bool], predicted_attack: list[bool]) -> DetectionMetrics:
    if len(expected_attack) != len(predicted_attack):
        raise ValueError('expected and predicted lengths differ')
    tp = fp = tn = fn = 0
    for expected, predicted in zip(expected_attack, predicted_attack):
        if expected and predicted: tp += 1
        elif not expected and predicted: fp += 1
        elif not expected and not predicted: tn += 1
        else: fn += 1
    return from_counts(tp, fp, tn, fn)

def rule_set_metrics(expected: set[str], actual: set[str]) -> DetectionMetrics:
    tp = len(expected & actual)
    fp = len(actual - expected)
    fn = len(expected - actual)
    # TN is undefined in open-world rule space, so keep it zero.
    return from_counts(tp, fp, 0, fn)
