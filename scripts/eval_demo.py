"""Offline demonstration of the M2 graph + evaluator (no AWS, no Neo4j needed).

    python scripts/eval_demo.py

Builds the identity graph from the sample authorization snapshot, then answers
"what can X do?" and "who can do Y on Z?" and prints the CAN_ASSUME edges with
their external-trust flag.
"""

from __future__ import annotations

from cloudhunt.core.config import settings
from cloudhunt.graph.authorization import IamAuthorization
from cloudhunt.graph.model import build_graph
from cloudhunt.graph.policy_eval import PolicyEvaluator
from cloudhunt.graph.query import what_can_principal_do, who_can_do

ACCT = "111122223333"
CROWN_OBJ = "arn:aws:s3:::acme-crown-jewels/customers.csv"
DEPLOY_POLICY = f"arn:aws:iam::{ACCT}:policy/deploy-policy"
TRAIL = f"arn:aws:cloudtrail:us-east-1:{ACCT}:trail/org-trail"


def main() -> None:
    snap = settings.sample_data_dir / "iam_auth" / "authz_snapshot_01.json"
    auth = IamAuthorization.from_file(snap)
    graph = build_graph(auth)
    ev = PolicyEvaluator(auth)

    print("=== CAN_ASSUME edges (trust) ===")
    for e in graph.edges_of("CAN_ASSUME"):
        flag = "EXTERNAL/backdoor" if e.props.get("external") else "in-account"
        print(f"  {e.src:55} -> {e.dst:45} [{flag}]")

    print("\n=== what can role/deploy do? (concrete allows) ===")
    caps = what_can_principal_do(ev, f"arn:aws:iam::{ACCT}:role/deploy")
    for d in caps.concrete:
        tag = "conditional" if d.conditional else "allow"
        print(f"  {d.action:24} on {d.resource:50} [{tag}]")

    print("\n=== who can iam:CreatePolicyVersion on deploy-policy? ===")
    res = who_can_do(ev, "iam:CreatePolicyVersion", DEPLOY_POLICY,
                     graph=graph, include_assume_paths=True)
    for d in res.allowed:
        print(f"  DIRECT   {d.principal}")
    for assumer, role in res.via_assume:
        print(f"  INDIRECT {assumer}  (via assuming {role})")

    print("\n=== who can s3:GetObject on crown-jewels/customers.csv? ===")
    for d in who_can_do(ev, "s3:GetObject", CROWN_OBJ).allowed:
        note = "  (conditional on MFA)" if d.conditional else ""
        print(f"  {d.principal}{note}")

    print("\n=== who can cloudtrail:StopLogging on org-trail? ===")
    r = who_can_do(ev, "cloudtrail:StopLogging", TRAIL)
    print(f"  allowed: {[d.principal for d in r.allowed] or 'NOBODY'}")
    print(f"  explicitly denied: {[d.principal for d in r.denied]}")


if __name__ == "__main__":
    main()
