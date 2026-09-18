"""Source (b): a folder of sample CloudTrail JSON files.

Each file is a standard CloudTrail delivery object: ``{"Records": [ ... ]}``.
This is the workhorse for offline development and for the test-suite — no AWS,
no LocalStack, fully deterministic. It is also the shape of a downloaded
CloudTrail log file, so the same normaliser path is exercised as in production.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

from cloudhunt.ingest.base import CloudTelemetrySource, RawRecord
from cloudhunt.models.events import Source


class FolderCloudTrailSource(CloudTelemetrySource):
    source = Source.cloudtrail

    def __init__(self, directory: str | Path):
        self.directory = Path(directory)

    def records(self) -> Iterator[RawRecord]:
        if not self.directory.is_dir():
            raise FileNotFoundError(f"CloudTrail sample dir not found: {self.directory}")
        for path in sorted(self.directory.glob("*.json")):
            payload = json.loads(path.read_text(encoding="utf-8"))
            for rec in payload.get("Records", []):
                event_id = rec.get("eventID", "unknown")
                yield RawRecord(
                    record=rec,
                    raw_ref=f"file://{path}#{event_id}",
                    source=Source.cloudtrail,
                )
