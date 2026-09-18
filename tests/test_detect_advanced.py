"""Milestone 8 advanced detection fixtures and should/shouldn't-fire tests."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cloudhunt.detect.advanced import (
    S3BaselineModel,
    detect_backdoor_trust_policy,
    detect_granted_but_unused,
    detect_new_privesc_paths,
    detect_s3_exfiltration,
)
from cloudhunt.graph.policy_eval import EffectivePermissions, ResolvedGrant
from cloudhunt.models.events import CloudEvent, Source
from cloudhunt.privesc.pathfind import Hop, PrivEscPath

FIX = Path(__file__).parent / "fixtures" / "m8"
T0 = datetime(2026, 9, 1, 12, 0, tzinfo=timezone.utc)


def _load(name):
    return json.loads((FIX / name).read_text())


def ev(*, principal, event="GetObject", day=0, minute=0, region="us-east-1",
       bucket="patient-records", bytes_=0, params=None):
    p = {"bucketName": bucket, "__event_source": "s3.amazonaws.com"}
    if bytes_:
        p["bytesTransferred"] = bytes_
    if params:
        p.update(params)
    return CloudEvent(
        ts=T0 + timedelta(days=day, minutes=minute), account="111122223333",
        region=region, event=event, principal=principal,
        target=f"arn:aws:s3:::{bucket}", raw_ref="r", event_id=f"{event}-{day}-{minute}-{region}",
        source=Source.cloudtrail, params=p,
    )


# --- least-privilege granted-but-unused ---

def test_unused_permission_fires_but_used_permission_does_not():
    f = _load("drift.json")
    grants = [ResolvedGrant("Allow", g["actions"], g["resources"], False, g["source"])
              for g in f["grants"]]
    ep = EffectivePermissions(f["principal"], allows=grants)
    events = [ev(principal=f["principal"], event="GetObject", day=29)]
    out = detect_granted_but_unused({f["principal"]: ep}, events, lookback_days=30,
                                    as_of=T0 + timedelta(days=30))
    assert len(out) == 1
    unused = out[0].evidence["unused_grants"]
    assert ["iam:CreatePolicyVersion"] in [g["actions"] for g in unused]
    assert ["s3:GetObject"] not in [g["actions"] for g in unused]
    assert out[0].attack_ids == ["T1548"]


def test_all_permissions_used_does_not_fire():
    principal = "arn:aws:iam::111122223333:user/alice"
    ep = EffectivePermissions(principal, allows=[
        ResolvedGrant("Allow", ["s3:GetObject"], ["*"], False, "managed:reader")
    ])
    events = [ev(principal=principal, event="GetObject")]
    assert detect_granted_but_unused({principal: ep}, events, as_of=T0) == []


# --- newly-created privesc path diff ---

def _path(tech="AttachUserPolicy"):
    p = "arn:aws:iam::111122223333:user/alice"
    return PrivEscPath(
        principal=p, target="admin:111122223333", target_priv="admin-equivalent",
        techniques=[tech], path=[Hop(p, tech, "admin:111122223333", False, "T1548")],
    )


def test_new_privesc_path_fires():
    out = detect_new_privesc_paths([], [_path()], observed_at=T0)
    assert len(out) == 1 and out[0].key == "m8-new-privesc-path"


def test_unchanged_privesc_path_does_not_fire():
    p = _path()
    assert detect_new_privesc_paths([p], [p], observed_at=T0) == []


# --- backdoor trust-policy ---

def test_trust_policy_condition_drop_fires():
    f = _load("trust_policy_diffs.json")
    out = detect_backdoor_trust_policy(
        account_id=f["account"], role_arn=f["role"],
        before_policy=f["safe_before"], after_policy=f["condition_dropped_after"],
    )
    assert len(out) == 1
    assert any(x["type"] == "condition_dropped" for x in out[0].evidence["changes"])
    assert out[0].attack_ids == ["T1098"]


def test_trust_policy_wildcard_fires():
    f = _load("trust_policy_diffs.json")
    out = detect_backdoor_trust_policy(
        account_id=f["account"], role_arn=f["role"],
        before_policy=f["safe_before"], after_policy=f["wildcard_after"],
    )
    assert any(x["type"] == "wildcard_principal" for x in out[0].evidence["changes"])


def test_unchanged_trust_policy_does_not_fire():
    f = _load("trust_policy_diffs.json")
    assert detect_backdoor_trust_policy(
        account_id=f["account"], role_arn=f["role"],
        before_policy=f["safe_before"], after_policy=f["safe_before"],
    ) == []


def test_allowlisted_external_account_does_not_fire():
    f = _load("trust_policy_diffs.json")
    empty = {"Version": "2012-10-17", "Statement": []}
    assert detect_backdoor_trust_policy(
        account_id=f["account"], role_arn=f["role"], before_policy=empty,
        after_policy=f["safe_before"], allowed_external_accounts={"444455556666"},
    ) == []


# --- S3 baselines ---

def _baseline_fixture():
    f = _load("s3_baseline.json")
    events = []
    for d in f["baseline_days"]:
        for i in range(d["count"]):
            events.append(ev(principal=f["principal"], day=d["day"], minute=i,
                             region=d["region"], bytes_=d["bytes_each"]))
    return f, S3BaselineModel.fit(events)


def test_s3_volume_spike_fires():
    f, model = _baseline_fixture()
    current = [ev(principal=f["principal"], day=10, minute=i, bytes_=5 * 1024 * 1024)
               for i in range(40)]
    out = detect_s3_exfiltration(current, model)
    assert len(out) == 1
    kinds = {r["type"] for r in out[0].evidence["reasons"]}
    assert "getobject_volume_anomaly" in kinds and "byte_volume_anomaly" in kinds
    assert out[0].attack_ids == ["T1530", "T1537"]


def test_s3_normal_usage_does_not_fire():
    f, model = _baseline_fixture()
    current = [ev(principal=f["principal"], day=10, minute=i, bytes_=1024 * 1024)
               for i in range(11)]
    assert detect_s3_exfiltration(current, model) == []


def test_s3_cross_region_fires():
    f, model = _baseline_fixture()
    current = [ev(principal=f["principal"], day=10, region="eu-west-1", bytes_=1024)]
    out = detect_s3_exfiltration(current, model)
    assert len(out) == 1
    assert out[0].evidence["reasons"][0]["type"] == "cross_region_access"


def test_sensitive_bucket_public_change_fires():
    f, model = _baseline_fixture()
    event = ev(principal=f["principal"], event="DeletePublicAccessBlock", day=10,
               bucket=f["sensitive_bucket"])
    out = detect_s3_exfiltration([event], model, sensitive_buckets={f["sensitive_bucket"]})
    assert len(out) == 1 and out[0].key == "m8-s3-sensitive-public-access"


def test_non_sensitive_bucket_public_change_does_not_fire():
    f, model = _baseline_fixture()
    event = ev(principal=f["principal"], event="DeletePublicAccessBlock", day=10,
               bucket="public-assets")
    assert detect_s3_exfiltration([event], model,
                                  sensitive_buckets={f["sensitive_bucket"]}) == []
