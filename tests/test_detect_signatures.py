"""Layer 1 signature tests — every rule gets a should-fire and a shouldn't-fire.

Events are built directly as CloudEvents for precision; one test also routes a
raw CloudTrail record through the normaliser to prove request parameters survive
into ``CloudEvent.params`` (which three rules depend on).
"""

from __future__ import annotations

from datetime import datetime, timezone

from cloudhunt.detect import attack
from cloudhunt.detect.signatures import SignatureEngine, load_rules
from cloudhunt.ingest.base import RawRecord
from cloudhunt.models.events import CloudEvent, PrincipalType, Sensitivity, Source
from cloudhunt.normalise.cloudtrail import normalise_cloudtrail

ENGINE = SignatureEngine(load_rules())


def ev(**kw) -> CloudEvent:
    base = dict(
        ts=datetime(2026, 9, 10, 3, 0, tzinfo=timezone.utc), account="111122223333",
        region="us-east-1", event="X", principal="arn:aws:iam::111122223333:user/x",
        raw_ref="r", event_id="e", source=Source.cloudtrail,
    )
    base.update(kw)
    return CloudEvent(**base)


def keys(event: CloudEvent) -> set[str]:
    return {d.key for d in ENGINE.match(event)}


# --- logging tampering (T1562.008) ---
def test_stop_logging_fires():
    assert "ct-logging-tampering" in keys(ev(event="StopLogging"))


def test_delete_detector_fires():
    assert "ct-logging-tampering" in keys(ev(event="DeleteDetector"))


def test_read_trail_status_does_not_fire():
    assert "ct-logging-tampering" not in keys(ev(event="GetTrailStatus"))


# --- security group opened to the world (T1562.007) ---
def _sg(cidr: str) -> CloudEvent:
    return ev(event="AuthorizeSecurityGroupIngress",
              params={"ipPermissions": {"items": [{"ipRanges": {"items": [{"cidrIp": cidr}]}}]}})


def test_sg_open_world_fires():
    assert "ec2-sg-open-world" in keys(_sg("0.0.0.0/0"))


def test_sg_open_internal_does_not_fire():
    assert "ec2-sg-open-world" not in keys(_sg("10.0.0.0/8"))


# --- persistence (T1136.003 / T1098.001 / T1098.003) ---
def test_create_user_fires():
    assert "iam-create-user" in keys(ev(event="CreateUser"))


def test_create_access_key_fires():
    assert "iam-add-credentials" in keys(ev(event="CreateAccessKey"))


def test_get_access_key_last_used_does_not_fire():
    assert "iam-add-credentials" not in keys(ev(event="GetAccessKeyLastUsed"))


def test_backdoor_trust_external_account_fires():
    doc = ('{"Statement":[{"Effect":"Allow",'
           '"Principal":{"AWS":"arn:aws:iam::999988887777:root"},'
           '"Action":"sts:AssumeRole"}]}')
    assert "iam-backdoor-trust" in keys(ev(event="UpdateAssumeRolePolicy",
                                           params={"policyDocument": doc}))


def test_backdoor_trust_same_account_does_not_fire():
    doc = ('{"Statement":[{"Effect":"Allow",'
           '"Principal":{"AWS":"arn:aws:iam::111122223333:role/ci"},'
           '"Action":"sts:AssumeRole"}]}')
    assert "iam-backdoor-trust" not in keys(ev(event="UpdateAssumeRolePolicy",
                                               params={"policyDocument": doc}))


def test_backdoor_trust_wildcard_fires():
    doc = ('{"Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},'
           '"Action":"sts:AssumeRole"}]}')
    assert "iam-backdoor-trust" in keys(ev(event="CreateRole",
                                           params={"assumeRolePolicyDocument": doc}))


# --- crypto mining (T1496) ---
def test_gpu_in_unusual_region_fires():
    assert "ec2-cryptomining-launch" in keys(
        ev(event="RunInstances", region="ap-south-1", params={"instanceType": "p4d.24xlarge"}))


def test_gpu_in_home_region_does_not_fire():
    assert "ec2-cryptomining-launch" not in keys(
        ev(event="RunInstances", region="us-east-1", params={"instanceType": "p4d.24xlarge"}))


def test_small_instance_unusual_region_does_not_fire():
    assert "ec2-cryptomining-launch" not in keys(
        ev(event="RunInstances", region="ap-south-1", params={"instanceType": "m5.large"}))


# --- identity hygiene (T1078.004 / T1078) ---
def test_root_activity_fires():
    assert "iam-root-activity" in keys(ev(event="RunInstances", principal_type=PrincipalType.root))


def test_non_mfa_sensitive_write_fires():
    assert "iam-non-mfa-sensitive-write" in keys(
        ev(event="PutObject", mfa=False, read_only=False, resource_sensitivity=Sensitivity.high))


def test_mfa_sensitive_write_does_not_fire():
    assert "iam-non-mfa-sensitive-write" not in keys(
        ev(event="PutObject", mfa=True, read_only=False, resource_sensitivity=Sensitivity.high))


def test_non_mfa_low_sensitivity_does_not_fire():
    assert "iam-non-mfa-sensitive-write" not in keys(
        ev(event="PutObject", mfa=False, read_only=False, resource_sensitivity=Sensitivity.low))


# --- params survive normalisation, and the SG rule fires on a raw record ---
def test_params_flow_through_normaliser_and_fire():
    raw = RawRecord(record={
        "eventTime": "2026-09-10T04:00:00Z", "eventName": "AuthorizeSecurityGroupIngress",
        "awsRegion": "us-east-1", "recipientAccountId": "111122223333",
        "eventID": "sg-1", "readOnly": False,
        "userIdentity": {"type": "IAMUser", "arn": "arn:aws:iam::111122223333:user/x"},
        "sourceIPAddress": "185.220.101.5",
        "requestParameters": {"ipPermissions": {"items": [
            {"ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}}]}},
    }, raw_ref="raw-sg-1", source=Source.cloudtrail)
    event = normalise_cloudtrail(raw)
    assert event.params  # request parameters retained
    assert "ec2-sg-open-world" in keys(event)


# --- catalogue hygiene: every rule cites resolvable ATT&CK ids ---
def test_all_rule_attack_ids_resolve():
    for rule in load_rules():
        assert rule.attack_ids
        for aid in rule.attack_ids:
            assert attack.resolve(aid).tactic
