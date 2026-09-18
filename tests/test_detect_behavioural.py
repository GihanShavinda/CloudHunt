"""Layer 2 behavioural tests — should/shouldn't-fire for each detector."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from cloudhunt.detect.baselines import (
    BaselineModel,
    detect_automation_iam_write,
    detect_enumeration_bursts,
    detect_impossible_travel,
    detect_new_geo,
)
from cloudhunt.models.events import CloudEvent, Source

T0 = datetime(2026, 9, 10, 3, 0, tzinfo=timezone.utc)


def ev(principal="arn:aws:iam::111122223333:user/alice", event="GetObject",
       geo="US", minutes=0, **kw) -> CloudEvent:
    base = dict(ts=T0 + timedelta(minutes=minutes), account="111122223333",
                region="us-east-1", event=event, principal=principal, geo=geo,
                raw_ref="r", event_id=f"e{minutes}", source=Source.cloudtrail)
    base.update(kw)
    return CloudEvent(**base)


# --- new-geo ---
def test_new_geo_fires_for_known_principal():
    model = BaselineModel.fit([ev(geo="US"), ev(geo="US")])
    d = detect_new_geo(ev(geo="DE"), model)
    assert d is not None and d.attack_ids == ["T1078.004"]


def test_same_geo_does_not_fire():
    model = BaselineModel.fit([ev(geo="US")])
    assert detect_new_geo(ev(geo="US"), model) is None


def test_unbaselined_principal_does_not_fire_new_geo():
    model = BaselineModel.fit([ev(principal="arn:aws:iam::111122223333:user/bob", geo="US")])
    assert detect_new_geo(ev(geo="DE"), model) is None  # alice unknown -> no baseline


# --- impossible travel ---
def test_impossible_travel_fires():
    events = [ev(geo="US", minutes=0), ev(geo="DE", minutes=30)]
    out = detect_impossible_travel(events, max_gap_minutes=60)
    assert len(out) == 1 and out[0].evidence["from"] == "US" and out[0].evidence["to"] == "DE"


def test_same_country_no_impossible_travel():
    events = [ev(geo="US", minutes=0), ev(geo="US", minutes=5)]
    assert detect_impossible_travel(events) == []


def test_slow_travel_is_allowed():
    events = [ev(geo="US", minutes=0), ev(geo="DE", minutes=600)]
    assert detect_impossible_travel(events, max_gap_minutes=60) == []


# --- automation doing IAM writes ---
def test_automation_iam_write_fires():
    d = detect_automation_iam_write(
        ev(principal="arn:aws:iam::111122223333:user/ci-bot", event="CreateAccessKey"))
    assert d is not None and d.attack_ids == ["T1098"]


def test_automation_read_does_not_fire():
    assert detect_automation_iam_write(
        ev(principal="arn:aws:iam::111122223333:user/ci-bot", event="GetObject")) is None


def test_human_iam_write_does_not_fire_as_automation():
    assert detect_automation_iam_write(
        ev(principal="arn:aws:iam::111122223333:user/alice", event="CreateAccessKey")) is None


# --- enumeration burst ---
def test_enumeration_burst_fires():
    reads = ["DescribeInstances", "DescribeSecurityGroups", "ListBuckets",
             "ListRoles", "GetAccountAuthorizationDetails", "DescribeVpcs",
             "ListUsers", "ListPolicies"]
    events = [ev(event=name, minutes=i) for i, name in enumerate(reads)]
    out = detect_enumeration_bursts(events, window_minutes=10, distinct_threshold=8)
    assert len(out) == 1 and out[0].attack_ids == ["T1580"]


def test_few_reads_no_burst():
    events = [ev(event="DescribeInstances", minutes=0),
              ev(event="ListBuckets", minutes=1)]
    assert detect_enumeration_bursts(events, distinct_threshold=8) == []
