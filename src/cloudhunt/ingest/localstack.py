"""Source (a): LocalStack (mocked AWS APIs) via boto3.

Uses the CloudTrail ``lookup_events`` API against a LocalStack endpoint. The API
returns each event with the actual record encoded as a JSON *string* in the
``CloudTrailEvent`` field, which we parse natively into a dict — no text
scraping. Point ``endpoint_url`` at real AWS and the exact same code path works.

This source is exercised in the live LocalStack demo (``make up`` +
``scripts/ingest_demo.py``), not in the offline unit tests, since it needs a
running endpoint.
"""

from __future__ import annotations

import json
from typing import Any, Iterator, Optional

from cloudhunt.core.config import settings
from cloudhunt.ingest.base import CloudTelemetrySource, RawRecord
from cloudhunt.models.events import Source


class LocalStackCloudTrailSource(CloudTelemetrySource):
    source = Source.cloudtrail

    def __init__(self, client: Optional[Any] = None, max_results: int = 200):
        if client is None:
            import boto3  # imported lazily so offline tests never need boto3 configured

            client = boto3.client(
                "cloudtrail",
                endpoint_url=settings.localstack_endpoint,
                region_name=settings.aws_region,
            )
        self.client = client
        self.max_results = max_results

    def records(self) -> Iterator[RawRecord]:
        paginator = self.client.get_paginator("lookup_events")
        for page in paginator.paginate(MaxResults=self.max_results):
            for event in page.get("Events", []):
                rec = json.loads(event["CloudTrailEvent"])
                event_id = rec.get("eventID", event.get("EventId", "unknown"))
                yield RawRecord(
                    record=rec,
                    raw_ref=f"localstack://cloudtrail#{event_id}",
                    source=Source.cloudtrail,
                )
