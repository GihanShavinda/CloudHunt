from __future__ import annotations
from datetime import datetime

def _ms(a: datetime | None, b: datetime | None) -> float | None:
    if not a or not b: return None
    return round((b-a).total_seconds()*1000, 3)

def timing_metrics(*, event_ingested=None, detected=None, case_created=None, investigation_started=None,
                   response_recommended=None, approved=None, response_completed=None, simulated=False) -> dict:
    return {
        'detection_latency_ms': _ms(event_ingested, detected),
        'case_creation_latency_ms': _ms(event_ingested, case_created),
        'mtti_ms': _ms(case_created, investigation_started),
        'mttr_ms': _ms(investigation_started, response_completed),
        'recommendation_latency_ms': _ms(case_created, response_recommended),
        'approval_to_completion_ms': _ms(approved, response_completed),
        'simulated_analyst_timing': bool(simulated),
    }
