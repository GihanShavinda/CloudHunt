"""The ingestion contract.

Every source — LocalStack, a folder of sample files, an SQS queue — produces the
same thing: a stream of :class:`RawRecord`. A ``RawRecord`` is the *native,
already-parsed* JSON object (a dict), never a text blob to be scraped, plus a
provenance pointer (``raw_ref``) and the source tag.

Keeping sources this thin means the normaliser is completely source-transport
agnostic: it only ever sees ``{record, raw_ref, source}``. Add a Kinesis source
tomorrow and nothing downstream changes.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Iterator

from cloudhunt.models.events import Source


@dataclass(slots=True)
class RawRecord:
    """A single parsed telemetry record plus where it came from."""

    record: dict[str, Any]
    raw_ref: str
    source: Source


class CloudTelemetrySource(ABC):
    """A pull-based source of raw telemetry records."""

    source: Source

    @abstractmethod
    def records(self) -> Iterator[RawRecord]:
        """Yield raw records. Implementations MUST parse JSON natively."""
        raise NotImplementedError
