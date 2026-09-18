"""Source (c): the S3-delivery / EventBridge -> SQS shape.

In a real deployment CloudTrail arrives one of two ways, both landing on an SQS
queue:

1. **EventBridge**: the message body is an EventBridge envelope whose
   ``detail`` *is* the CloudTrail event.
2. **S3 delivery notification**: CloudTrail writes a gzipped ``Records[]`` file
   to a bucket, S3 emits an ``s3:ObjectCreated`` notification to the queue, and
   we must fetch + gunzip the object to get the records.

The transport (polling SQS, calling S3) is I/O and needs LocalStack or AWS. The
*parsing* — turning a message body into records — is pure logic, so it lives in
:func:`iter_records_from_message` and is unit-tested directly with fixtures and
a fake S3 reader. That split is deliberate: it means the interesting logic has
zero infrastructure dependencies.
"""

from __future__ import annotations

import gzip
import json
from typing import Any, Callable, Iterator, Optional

from cloudhunt.ingest.base import CloudTelemetrySource, RawRecord
from cloudhunt.models.events import Source

# A reader that, given (bucket, key), returns the raw object bytes.
S3Reader = Callable[[str, str], bytes]


def _records_from_s3_object(raw_bytes: bytes) -> list[dict[str, Any]]:
    """CloudTrail S3 objects are gzipped ``{"Records": [...]}``; tolerate plain too."""
    try:
        raw_bytes = gzip.decompress(raw_bytes)
    except (OSError, gzip.BadGzipFile):
        pass  # already-decompressed object (e.g. a test fixture)
    return json.loads(raw_bytes).get("Records", [])


def iter_records_from_message(
    body: dict[str, Any],
    s3_reader: Optional[S3Reader] = None,
) -> Iterator[tuple[dict[str, Any], str]]:
    """Yield ``(record, raw_ref)`` pairs from one SQS message body.

    Handles the EventBridge envelope, the S3 notification, and (defensively) a
    raw delivery file or a single bare record. ``raw_ref`` is a provenance
    pointer, not the payload.
    """
    # 1) EventBridge envelope wrapping a CloudTrail event.
    if body.get("detail-type") and isinstance(body.get("detail"), dict):
        detail = body["detail"]
        raw_ref = f"eventbridge://{body.get('id', detail.get('eventID', 'unknown'))}"
        yield detail, raw_ref
        return

    # 2) S3 object-created notification -> fetch + gunzip.
    records = body.get("Records")
    if records and isinstance(records[0], dict) and "s3" in records[0]:
        if s3_reader is None:
            raise ValueError("S3 notification received but no s3_reader provided")
        for note in records:
            bucket = note["s3"]["bucket"]["name"]
            key = note["s3"]["object"]["key"]
            for rec in _records_from_s3_object(s3_reader(bucket, key)):
                yield rec, f"s3://{bucket}/{key}#{rec.get('eventID', 'unknown')}"
        return

    # 3) A raw CloudTrail delivery file pushed directly as the body.
    if records is not None:
        for rec in records:
            yield rec, f"sqs://raw#{rec.get('eventID', 'unknown')}"
        return

    # 4) A single bare CloudTrail record.
    yield body, f"sqs://raw#{body.get('eventID', 'unknown')}"


class SqsCloudTrailSource(CloudTelemetrySource):
    """Polls an SQS queue and yields CloudTrail records. Needs LocalStack/AWS.

    ``sqs_client`` and ``s3_client`` are injected so this class is testable with
    fakes and so the same code runs against LocalStack or real AWS just by
    swapping ``endpoint_url`` on the boto3 clients.
    """

    source = Source.cloudtrail

    def __init__(self, queue_url: str, sqs_client: Any, s3_client: Any, max_batches: int = 1):
        self.queue_url = queue_url
        self.sqs = sqs_client
        self.s3 = s3_client
        self.max_batches = max_batches

    def _read_s3(self, bucket: str, key: str) -> bytes:
        return self.s3.get_object(Bucket=bucket, Key=key)["Body"].read()

    def records(self) -> Iterator[RawRecord]:
        for _ in range(self.max_batches):
            resp = self.sqs.receive_message(
                QueueUrl=self.queue_url, MaxNumberOfMessages=10, WaitTimeSeconds=1
            )
            messages = resp.get("Messages", [])
            if not messages:
                break
            for msg in messages:
                body = json.loads(msg["Body"])
                for rec, raw_ref in iter_records_from_message(body, self._read_s3):
                    yield RawRecord(record=rec, raw_ref=raw_ref, source=Source.cloudtrail)
                self.sqs.delete_message(QueueUrl=self.queue_url, ReceiptHandle=msg["ReceiptHandle"])
