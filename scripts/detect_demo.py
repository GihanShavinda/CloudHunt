"""Offline, end-to-end demonstration of the Milestone 4 detection engine.

    python scripts/detect_demo.py

Simulates a leaked-key scenario for one principal (ci-bot) and runs all three
layers — signatures, behavioural baselines, correlation — then enriches the
resulting case with the Milestone 3 privilege-escalation path computed for that
same principal from the IAM graph. No AWS, no Neo4j.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from cloudhunt.core.config import settings
from cloudhunt.detect import attack
from cloudhunt.detect.engine import DetectionEngine
from cloudhunt.graph.authorization import IamAuthorization
from cloudhunt.graph.model import build_graph
from cloudhunt.graph.policy_eval import PolicyEvaluator
from cloudhunt.models.events import CloudEvent, Source
from cloudhunt.privesc import detect_escalations, find_privesc_paths

CIBOT = "arn:aws:iam::111122223333:user/ci-bot"
T0 = datetime(2026, 9, 10, 3, 0, tzinfo=timezone.utc)


def ev(event, minutes, geo="DE", **kw) -> CloudEvent:
    base = dict(ts=T0 + timedelta(minutes=minutes), account="111122223333",
                region="us-east-1", event=event, principal=CIBOT, geo=geo,
                src_ip="185.220.101.5", raw_ref="r", event_id=f"e{minutes}",
                source=Source.cloudtrail)
    base.update(kw)
    return CloudEvent(**base)


def main() -> None:
    # --- Milestone 3 privesc reachability for the same principal ---
    auth = IamAuthorization.from_file(
        settings.sample_data_dir / "iam_auth" / "authz_snapshot_01.json")
    graph = build_graph(auth)
    ev_eval = PolicyEvaluator(auth)
    detect_escalations(auth, graph, ev_eval)
    paths = {p.principal: p for p in find_privesc_paths(auth, graph, ev_eval)}

    # --- the attack stream (leaked long-term key used from a new country) ---
    baseline = [ev("GetObject", -60, geo="US"), ev("ListBuckets", -59, geo="US")]
    reads = ["DescribeInstances", "DescribeSecurityGroups", "ListRoles",
             "ListUsers", "GetAccountAuthorizationDetails", "ListPolicies",
             "DescribeVpcs", "ListAccessKeys"]
    stream = [ev(r, i) for i, r in enumerate(reads)]                 # enumeration burst
    stream += [
        ev("CreateAccessKey", 9),                                   # persistence + automation
        ev("StopLogging", 11),                                      # defense evasion
        ev("AuthorizeSecurityGroupIngress", 12,
           params={"ipPermissions": {"items": [{"ipRanges": {"items": [{"cidrIp": "0.0.0.0/0"}]}}]}}),
    ]

    result = DetectionEngine().run(stream, baseline_events=baseline, privesc_paths=paths)

    print("=== detections ===")
    for d in sorted(result.detections, key=lambda x: (x.layer.value, x.key)):
        tac = ",".join(d.tactics)
        print(f"  [{d.layer.value:11}] {d.key:26} {','.join(d.attack_ids):10} "
              f"conf={d.confidence:.2f}  ({tac})")

    print(f"\n=== correlated cases: {len(result.cases)} ===")
    for c in result.cases:
        print(f"\n  {c.case_id}  score={c.score}  principals={{{', '.join(s.split('/')[-1] for s in c.principals)}}}")
        print(f"  kill-chain: {c.title}")
        print(f"  techniques: {', '.join(sorted(c.techniques))}")
        for n in c.notes:
            print(f"  note: {n}")


if __name__ == "__main__":
    main()
