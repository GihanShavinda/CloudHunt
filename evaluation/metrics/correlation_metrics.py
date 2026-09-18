from __future__ import annotations

def correlation_score(expected_event_ids: set[str], case_event_ids: list[set[str]], benign_event_ids: set[str] | None = None) -> float:
    """Score attack cohesion and benign exclusion in [0,1]."""
    if not expected_event_ids:
        return 1.0
    benign_event_ids = benign_event_ids or set()
    best = 0.0
    for ids in case_event_ids:
        included = len(expected_event_ids & ids) / len(expected_event_ids)
        contamination = len(benign_event_ids & ids) / max(1, len(ids))
        best = max(best, included * (1.0 - contamination))
    return round(best, 4)
