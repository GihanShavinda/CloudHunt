"""Milestone 6 — response layer demo.

    python scripts/respond_demo.py

Continues the full slice: detect -> correlate -> case -> RESPOND. Shows the
decision engine auto-running only the safe reversible action, holding the rest for
human approval, approving one with MFA, undoing it, and the append-only audit log
that results. Offline (FakeActionExecutor); swap in Boto3ActionExecutor with a
LocalStack endpoint for a live dry-run.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from cloudhunt.core.config import settings
from cloudhunt.correlate import build_cases, prepare_graph
from cloudhunt.detect.engine import DetectionEngine
from cloudhunt.graph.authorization import IamAuthorization
from cloudhunt.models.events import CloudEvent, PrincipalType, SessionContext, Source
from cloudhunt.respond import (
    Approval,
    FakeActionExecutor,
    ResponseEngine,
)

ACC = "111122223333"; IP = "185.220.101.5"
CIBOT = f"arn:aws:iam::{ACC}:user/ci-bot"; DEPLOY = f"arn:aws:iam::{ACC}:role/deploy"
SESS = f"arn:aws:sts::{ACC}:assumed-role/deploy/sess1"
CROWN = "arn:aws:s3:::acme-crown-jewels"; POLICY = f"arn:aws:iam::{ACC}:policy/deploy-policy"
TRAIL = f"arn:aws:cloudtrail:us-east-1:{ACC}:trail/org-trail"
T0 = datetime(2026, 9, 10, 3, 0, tzinfo=timezone.utc)


def ci(ev, m, t=None, geo="DE"):
    return CloudEvent(ts=T0 + timedelta(minutes=m), account=ACC, region="us-east-1", event=ev,
                      principal=CIBOT, principal_type=PrincipalType.user, geo=geo, src_ip=IP,
                      target=t, raw_ref="r", event_id=f"ci{m}", source=Source.cloudtrail)


def dep(ev, m, t=None):
    return CloudEvent(ts=T0 + timedelta(minutes=m), account=ACC, region="us-east-1", event=ev,
                      principal=SESS, principal_type=PrincipalType.assumed_role,
                      session=SessionContext(issuer_arn=DEPLOY, issuer_type="Role"), geo="DE",
                      src_ip=IP, target=t, raw_ref="r", event_id=f"dep{m}", source=Source.cloudtrail)


def main() -> None:
    baseline = [ci("ListBuckets", -120, geo="US")]
    stream = [ci("ListBuckets", 0), ci("AssumeRole", 1, DEPLOY),
              dep("CreatePolicyVersion", 2, POLICY), dep("DescribeInstances", 3),
              dep("ListRoles", 4), dep("GetObject", 5, CROWN), dep("StopLogging", 6, TRAIL)]

    res = DetectionEngine().run(stream, baseline_events=baseline)
    auth = IamAuthorization.from_file(
        settings.sample_data_dir / "iam_auth" / "authz_snapshot_01.json")
    graph, evaluator, _ = prepare_graph(auth)
    case = build_cases(res.cases, stream, auth, graph, evaluator)[0]
    print(f"case {case.case_id}: rank {case.rank:.3f}, blast {case.blast.score:.0f}, "
          f"confidence {case.detection_confidence:.2f}")

    # Seed the (fake) cloud with the compromised resources.
    ex = FakeActionExecutor()
    ex.add_user("ci-bot", {"AKIALEAKED0001": "Active"})
    ex.add_role("deploy")
    ex.add_trail("org-trail", False)
    eng = ResponseEngine(ex)

    plan = eng.run(case)
    print("\n--- AUTO-EXECUTED (reversible, low-impact, high-confidence) ---")
    for r in plan.executed:
        print(f"  {r.action_key}: {r.before} -> {r.after}   [undo_ref set: {bool(r.undo_ref)}]")
    print("\n--- PENDING HUMAN APPROVAL ---")
    for it in plan.pending:
        print(f"  {it.proposed.action_key:22} why: {it.decision.reasons[0]}")

    print("\n--- ANALYST APPROVES QUARANTINE (with MFA) ---")
    q = next(i for i in plan.pending if i.proposed.action_key == "quarantine-principal")
    rec = eng.approve(q, Approval("alice", "administrator", mfa_verified=True), case.case_id)
    print(f"  quarantine executed by {rec.approver}: {rec.after}")

    print("\n--- OPERATOR UNDOES THE QUARANTINE (reversibility) ---")
    undo = eng.undo(rec, actor="alice")
    print(f"  status={undo.status}, deploy inline policies now: "
          f"{ex.roles['deploy']['inline'] or '{}'}")

    print("\n--- APPEND-ONLY AUDIT LOG ---")
    for r in eng.audit.records():
        print(f"  [{r.decision:5}] {r.action_key:22} {r.status:8} "
              f"by {r.approver or 'system'}  ({r.reason[:48]})")


if __name__ == "__main__":
    main()
