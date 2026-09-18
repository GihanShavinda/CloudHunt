"""GuardDuty findings ingestion.

Folder ingestion is fully implemented (findings are just JSON, and the test
suite normalises them). The live path — GuardDuty -> EventBridge -> SQS — is
stubbed here because it reuses the SQS transport from :mod:`cloudhunt.ingest.sqs`
and only differs in the message ``detail`` shape; it is wired up in a later
milestone.

Findings files may be either a bare JSON array of findings or an object with a
``Findings`` key (both are shapes the AWS CLI/SDK emit); we accept both.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterator

from cloudhunt.ingest.base import CloudTelemetrySource, RawRecord
from cloudhunt.models.events import Source


def _findings_of(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        return payload.get("Findings", [])
    return []


class FolderGuardDutySource(CloudTelemetrySource):
    source = Source.guardduty

    def __init__(self, directory: str | Path):
        self.directory = Path(directory)

    def records(self) -> Iterator[RawRecord]:
        if not self.directory.is_dir():
            raise FileNotFoundError(f"GuardDuty sample dir not found: {self.directory}")
        for path in sorted(self.directory.glob("*.json")):
            payload = json.loads(path.read_text(encoding="utf-8"))
            for finding in _findings_of(payload):
                fid = finding.get("Id", "unknown")
                yield RawRecord(
                    record=finding,
                    raw_ref=f"file://{path}#{fid}",
                    source=Source.guardduty,
                )


class EventBridgeGuardDutySource(CloudTelemetrySource):
    """STUB (later milestone): live findings via EventBridge -> SQS.

    Reuses :class:`cloudhunt.ingest.sqs.SqsCloudTrailSource`'s transport; only
    the ``detail`` payload differs (a GuardDuty finding rather than a CloudTrail
    event). Intentionally not implemented in Milestone 1.
    """

    source = Source.guardduty

    def records(self) -> Iterator[RawRecord]:  # pragma: no cover - stub
        raise NotImplementedError("EventBridge GuardDuty ingestion arrives in a later milestone")
