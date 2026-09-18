"""Milestone 5 tests — chain reconstruction, blast radius, and queue ranking.

The headline test feeds a multi-detection scenario through the whole stack
(detection -> correlation -> case assembly) and asserts it collapses to ONE case
with the chain in correct causal order. Supporting tests cover the real
attack-chain fixture end-to-end, blast-radius explainability, and ranking.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from cloudhunt.correlate import (
    Case,
    RankWeights,
    build_cases,
    prepare_graph,
    rank_cases,
    reconstruct_chain,
    score_blast,
)
from cloudhunt.core.config import settings
from cloudhunt.detect.engine import DetectionEngine
from cloudhunt.graph.authorization import IamAuthorization
from cloudhunt.ingest.base import RawRecord
from cloudhunt.models.events import CloudEvent, PrincipalType, SessionContext, Source
from cloudhunt.normalise.cloudtrail import normalise_cloudtrail
from cloudhunt.normalise.enrich import Enricher

ACC = "111122223333"
IP = "185.220.101.5"
CIBOT = f"arn:aws:iam::{ACC}:user/ci-bot"
DEPLOY_ROLE = f"arn:aws:iam::{ACC}:role/deploy"
SESS = f"arn:aws:sts::{ACC}:assumed-role/deploy/sess1"
CROWN = "arn:aws:s3:::acme-crown-jewels"
TRAIL = f"arn:aws:cloudtrail:us-east-1:{ACC}:trail/org-trail"
POLICY = f"arn:aws:iam::{ACC}:policy/deploy-policy"
T0 = datetime(2026, 9, 10, 3, 0, tzinfo=timezone.utc)


def _auth() -> IamAuthorization:
    return IamAuthorization.from_file(
        settings.sample_data_dir / "iam_auth" / "authz_snapshot_01.json")


def _ci(event, m, target=None, geo="DE") -> CloudEvent:
    return CloudEvent(ts=T0 + timedelta(minutes=m), account=ACC, region="us-east-1",
                      event=event, principal=CIBOT, principal_type=PrincipalType.user,
                      geo=geo, src_ip=IP, target=target, raw_ref="r",
                      event_id=f"ci{m}", source=Source.cloudtrail)


def _dep(event, m, target=None) -> CloudEvent:
    return CloudEvent(ts=T0 + timedelta(minutes=m), account=ACC, region="us-east-1",
                      event=event, principal=SESS, principal_type=PrincipalType.assumed_role,
                      session=SessionContext(issuer_arn=DEPLOY_ROLE, issuer_type="Role"),
                      geo="DE", src_ip=IP, target=target, raw_ref="r",
                      event_id=f"dep{m}", source=Source.cloudtrail)


def _scenario() -> tuple[list[CloudEvent], list[CloudEvent]]:
    baseline = [_ci("ListBuckets", -120, geo="US"), _ci("GetCallerIdentity", -119, geo="US")]
    stream = [
        _ci("ListBuckets", 0),                       # key-abuse recon -> new-geo detection
        _ci("AssumeRole", 1, target=DEPLOY_ROLE),    # T1548
        _dep("CreatePolicyVersion", 2, target=POLICY),   # T1098.003
        _dep("DescribeInstances", 3), _dep("ListRoles", 4),  # discovery burst
        _dep("GetObject", 5, target=CROWN),          # T1530 exfil
        _dep("StopLogging", 6, target=TRAIL),        # T1562.008
    ]
    return baseline, stream


# --- headline: multi-detection -> one case + correct chain order ---
def test_multi_detection_forms_one_case_with_ordered_chain():
    baseline, stream = _scenario()
    result = DetectionEngine().run(stream, baseline_events=baseline)

    assert len(result.detections) >= 2                 # multi-detection
    assert len(result.cases) == 1                       # ...one case

    auth = _auth()
    graph, evaluator, _ = prepare_graph(auth)
    cases = build_cases(result.cases, stream, auth, graph, evaluator)
    assert len(cases) == 1
    chain = cases[0].chain

    assert [s.action for s in chain.steps] == [
        "ListBuckets", "AssumeRole", "CreatePolicyVersion",
        "Discovery (2 reads)", "GetObject", "StopLogging",
    ]
    assert chain.tactic_sequence() == [
        "Discovery", "Privilege Escalation", "Privilege Escalation",
        "Discovery", "Collection", "Defense Evasion",
    ]


def test_assumed_role_session_attributed_to_issuer():
    _, stream = _scenario()
    auth = _auth()
    graph, evaluator, _ = prepare_graph(auth)
    result = DetectionEngine().run(stream, baseline_events=_scenario()[0])
    case = build_cases(result.cases, stream, auth, graph, evaluator)[0]
    steps = case.chain.steps
    assert steps[0].actor == CIBOT and steps[1].actor == CIBOT      # before assume
    assert all(s.actor == DEPLOY_ROLE for s in steps[2:])           # after assume


def test_discovery_reads_collapse():
    _, stream = _scenario()
    auth = _auth()
    graph, evaluator, _ = prepare_graph(auth)
    result = DetectionEngine().run(stream, baseline_events=_scenario()[0])
    case = build_cases(result.cases, stream, auth, graph, evaluator)[0]
    disco = [s for s in case.chain.steps if s.tactic == "Discovery" and s.read_count > 1]
    assert len(disco) == 1 and disco[0].read_count == 2


def test_chain_steps_expose_graph_edges():
    _, stream = _scenario()
    auth = _auth()
    graph, evaluator, _ = prepare_graph(auth)
    result = DetectionEngine().run(stream, baseline_events=_scenario()[0])
    case = build_cases(result.cases, stream, auth, graph, evaluator)[0]
    by_action = {s.action: s for s in case.chain.steps}
    assert by_action["AssumeRole"].via_edge.startswith("CAN_ASSUME")
    assert by_action["GetObject"].via_edge.startswith("CAN_ACCESS")


# --- blast radius (0..100, explainable) ---
def test_blast_score_and_explainability():
    _, stream = _scenario()
    auth = _auth()
    graph, evaluator, _ = prepare_graph(auth)
    result = DetectionEngine().run(stream, baseline_events=_scenario()[0])
    case = build_cases(result.cases, stream, auth, graph, evaluator)[0]
    b = case.blast

    assert 0.0 <= b.score <= 100.0
    # deploy reaches a high-sensitivity bucket -> that term is fully on
    assert b.components["reach_sensitive"]["value"] == 1.0
    assert b.reach_sensitive_path is not None and b.reach_sensitive_path.path
    # score is exactly the sum of the four weighted contributions
    total = sum(c["contribution"] for c in b.components.values())
    assert abs(b.score - round(total, 1)) < 1e-9
    assert "high" in b.explanation()


def test_blast_terms_match_formula():
    auth = _auth()
    graph, evaluator, _ = prepare_graph(auth)
    b = score_blast(CIBOT, auth, graph, evaluator)
    # ci-bot can assume deploy and thereby reach the crown jewels
    assert b.components["reach_sensitive"]["value"] == 1.0
    assert "can_assume" in b.current_privilege_caps


# --- queue ranking ---
def test_rank_blends_blast_and_confidence():
    _, stream = _scenario()
    auth = _auth()
    graph, evaluator, _ = prepare_graph(auth)
    result = DetectionEngine().run(stream, baseline_events=_scenario()[0])
    case = build_cases(result.cases, stream, auth, graph, evaluator)[0]
    rw = RankWeights()
    expected = rw.alpha * (case.blast.score / 100.0) + rw.beta * case.detection_confidence
    assert abs(case.rank - round(expected, 4)) < 1e-6


def test_rank_cases_orders_by_rank_desc():
    a = Case("case-a", None, None, None, rank=0.2)
    b = Case("case-b", None, None, None, rank=0.9)
    c = Case("case-c", None, None, None, rank=0.5)
    assert [x.case_id for x in rank_cases([a, b, c])] == ["case-b", "case-c", "case-a"]


# --- chain reconstruction is robust to a single-detection cluster too ---
def test_real_attack_chain_fixture_end_to_end():
    import json
    recs = json.loads(
        (settings.sample_data_dir / "cloudtrail" / "attack_chain_01.json").read_text())["Records"]
    enricher = Enricher()
    events = [enricher.enrich(normalise_cloudtrail(
        RawRecord(record=r, raw_ref=r["eventID"], source=Source.cloudtrail))) for r in recs]

    result = DetectionEngine().run(events)          # no baseline needed
    assert len(result.cases) == 1

    auth = _auth()
    graph, evaluator, _ = prepare_graph(auth)
    case = build_cases(result.cases, events, auth, graph, evaluator)[0]
    assert [s.action for s in case.chain.steps] == [
        "AssumeRole", "CreatePolicyVersion", "GetObject", "StopLogging"]
    assert case.chain.steps[0].actor == CIBOT
    assert case.chain.steps[-1].actor == DEPLOY_ROLE
    assert case.rank > 0
