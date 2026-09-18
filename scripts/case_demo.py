"""Milestone 5 — the first full-slice demo.

    python scripts/case_demo.py

Runs the whole pipeline offline on a leaked-key scenario: detect (3 layers) ->
correlate into one case -> reconstruct the attack chain -> score blast radius ->
rank for the triage queue. No AWS, no Neo4j.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from cloudhunt.core.config import settings
from cloudhunt.correlate import build_cases, prepare_graph
from cloudhunt.detect.engine import DetectionEngine
from cloudhunt.graph.authorization import IamAuthorization
from cloudhunt.models.events import CloudEvent, PrincipalType, SessionContext, Source

ACC = "111122223333"
IP = "185.220.101.5"
CIBOT = f"arn:aws:iam::{ACC}:user/ci-bot"
DEPLOY_ROLE = f"arn:aws:iam::{ACC}:role/deploy"
SESS = f"arn:aws:sts::{ACC}:assumed-role/deploy/sess1"
CROWN = "arn:aws:s3:::acme-crown-jewels"
TRAIL = f"arn:aws:cloudtrail:us-east-1:{ACC}:trail/org-trail"
POLICY = f"arn:aws:iam::{ACC}:policy/deploy-policy"
T0 = datetime(2026, 9, 10, 3, 0, tzinfo=timezone.utc)


def ci(event, m, target=None, geo="DE"):
    return CloudEvent(ts=T0 + timedelta(minutes=m), account=ACC, region="us-east-1",
                      event=event, principal=CIBOT, principal_type=PrincipalType.user,
                      geo=geo, src_ip=IP, target=target, raw_ref="r",
                      event_id=f"ci{m}", source=Source.cloudtrail)


def dep(event, m, target=None):
    return CloudEvent(ts=T0 + timedelta(minutes=m), account=ACC, region="us-east-1",
                      event=event, principal=SESS, principal_type=PrincipalType.assumed_role,
                      session=SessionContext(issuer_arn=DEPLOY_ROLE, issuer_type="Role"),
                      geo="DE", src_ip=IP, target=target, raw_ref="r",
                      event_id=f"dep{m}", source=Source.cloudtrail)


def main() -> None:
    baseline = [ci("ListBuckets", -120, geo="US"), ci("GetCallerIdentity", -119, geo="US")]
    stream = [
        ci("ListBuckets", 0),
        ci("AssumeRole", 1, target=DEPLOY_ROLE),
        dep("CreatePolicyVersion", 2, target=POLICY),
        dep("DescribeInstances", 3), dep("ListRoles", 4),
        dep("GetObject", 5, target=CROWN),
        dep("StopLogging", 6, target=TRAIL),
    ]

    result = DetectionEngine().run(stream, baseline_events=baseline)
    print(f"detections: {len(result.detections)}   correlated cases: {len(result.cases)}")

    auth = IamAuthorization.from_file(
        settings.sample_data_dir / "iam_auth" / "authz_snapshot_01.json")
    graph, evaluator, _ = prepare_graph(auth)
    cases = build_cases(result.cases, stream, auth, graph, evaluator)

    print("\n================  TRIAGE QUEUE  ================")
    for c in cases:
        print(f"\nRANK {c.rank:.3f}   {c.case_id}   "
              f"(blast {c.blast.score:.0f}/100 x conf {c.detection_confidence:.2f})")
        print(f"  {c.title}")
        print("  reconstructed chain:")
        for s in c.chain.steps:
            det = f"  <detections: {', '.join(s.detection_keys)}>" if s.detection_keys else ""
            via = f"   [{s.via_edge}]" if s.via_edge else ""
            print(f"    {s.order}. {s.tactic:20} {s.action:22} "
                  f"by {s.actor.split('/')[-1]:9}{via}{det}")
        print("  blast radius (why):")
        for line in c.blast.explanation().splitlines()[1:]:
            print("  " + line)


if __name__ == "__main__":
    main()
