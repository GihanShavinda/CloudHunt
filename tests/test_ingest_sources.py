"""Unit-test the pure SQS message parser across every envelope shape."""

from __future__ import annotations

import gzip
import json

import pytest

from cloudhunt.ingest.sqs import iter_records_from_message

_CT_RECORD = {
    "eventID": "eb-1",
    "eventTime": "2026-09-10T03:20:00Z",
    "eventName": "AssumeRole",
    "awsRegion": "us-east-1",
    "recipientAccountId": "111122223333",
    "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::111122223333:user/ci-bot"},
}


def test_eventbridge_envelope():
    body = {
        "id": "eb-msg-1",
        "detail-type": "AWS API Call via CloudTrail",
        "detail": _CT_RECORD,
    }
    out = list(iter_records_from_message(body))
    assert len(out) == 1
    rec, raw_ref = out[0]
    assert rec["eventName"] == "AssumeRole"
    assert raw_ref.startswith("eventbridge://")


def test_s3_notification_fetches_and_gunzips():
    payload = gzip.compress(json.dumps({"Records": [_CT_RECORD]}).encode("utf-8"))

    def fake_s3_reader(bucket: str, key: str) -> bytes:
        assert bucket == "ct-bucket" and key == "AWSLogs/x.json.gz"
        return payload

    body = {
        "Records": [
            {"s3": {"bucket": {"name": "ct-bucket"}, "object": {"key": "AWSLogs/x.json.gz"}}}
        ]
    }
    out = list(iter_records_from_message(body, fake_s3_reader))
    assert len(out) == 1
    rec, raw_ref = out[0]
    assert rec["eventID"] == "eb-1"
    assert raw_ref == "s3://ct-bucket/AWSLogs/x.json.gz#eb-1"


def test_s3_notification_without_reader_raises():
    body = {"Records": [{"s3": {"bucket": {"name": "b"}, "object": {"key": "k"}}}]}
    with pytest.raises(ValueError):
        list(iter_records_from_message(body))


def test_raw_delivery_file_body():
    out = list(iter_records_from_message({"Records": [_CT_RECORD]}))
    assert len(out) == 1 and out[0][0]["eventID"] == "eb-1"


def test_single_bare_record():
    out = list(iter_records_from_message(_CT_RECORD))
    assert len(out) == 1 and out[0][0]["eventName"] == "AssumeRole"
