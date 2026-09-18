"""The ingest -> normalise -> enrich pipeline.

Dispatch by ``RawRecord.source`` to the right normaliser, then enrich. This is
the one place that knows the full set of sources, so adding a source is: write a
normaliser, register it here. Everything downstream consumes the uniform
``CloudEvent`` stream.

Idempotency is enforced here (not in each source) so it holds regardless of how
an event arrived — the same eventID delivered twice by CloudTrail is emitted
once.
"""

from __future__ import annotations

from typing import Callable, Iterator

from cloudhunt.ingest.base import CloudTelemetrySource, RawRecord
from cloudhunt.models.events import CloudEvent, Source
from cloudhunt.normalise.cloudtrail import normalise_cloudtrail
from cloudhunt.normalise.enrich import Enricher
from cloudhunt.normalise.guardduty import normalise_guardduty

NORMALISERS: dict[Source, Callable[[RawRecord], CloudEvent]] = {
    Source.cloudtrail: normalise_cloudtrail,
    Source.guardduty: normalise_guardduty,
}


def normalise(raw: RawRecord) -> CloudEvent:
    try:
        fn = NORMALISERS[raw.source]
    except KeyError:  # pragma: no cover - defensive
        raise ValueError(f"No normaliser registered for source {raw.source!r}")
    return fn(raw)


def run(source: CloudTelemetrySource, enricher: Enricher) -> Iterator[CloudEvent]:
    """Stream normalised, enriched, de-duplicated events from a source."""
    seen: set[str] = set()
    for raw in source.records():
        event = enricher.enrich(normalise(raw))
        key = event.dedup_key()
        if key in seen:
            continue
        seen.add(key)
        yield event
