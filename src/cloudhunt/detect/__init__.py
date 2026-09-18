"""Detection engine (Milestone 4 / P4): signatures + behaviour + correlation.

Public surface:
    DetectionEngine, DetectionResult   orchestrator over the three layers
    SignatureEngine, load_rules, Rule  Layer 1 (Sigma-style YAML)
    BaselineModel, BehaviouralEngine   Layer 2 (per-principal baselines)
    correlate, CloudCase               Layer 3 (candidate cases)
    Detection, Layer                   the finding record
    attack                             ATT&CK Cloud technique registry
"""

from cloudhunt.detect import attack
from cloudhunt.detect.base import Detection, Layer
from cloudhunt.detect.baselines import (
    BaselineModel,
    BehaviouralEngine,
    detect_automation_iam_write,
    detect_enumeration_bursts,
    detect_impossible_travel,
    detect_new_geo,
)
from cloudhunt.detect.correlate import CloudCase, correlate, enrich_with_privesc
from cloudhunt.detect.engine import DetectionEngine, DetectionResult
from cloudhunt.detect.signatures import Rule, SignatureEngine, load_rules

__all__ = [
    "DetectionEngine", "DetectionResult",
    "SignatureEngine", "load_rules", "Rule",
    "BaselineModel", "BehaviouralEngine",
    "detect_new_geo", "detect_automation_iam_write",
    "detect_impossible_travel", "detect_enumeration_bursts",
    "correlate", "CloudCase", "enrich_with_privesc",
    "Detection", "Layer", "attack",
]
