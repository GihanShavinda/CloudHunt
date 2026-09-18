"""Offline demonstration of Milestone 3 privilege-escalation analysis.

    python scripts/privesc_demo.py            # CloudGoat-mirror fixture
    python scripts/privesc_demo.py m2         # the Milestone 2 fixture

Builds the identity graph, detects CAN_ESCALATE_VIA / CAN_ACCESS edges, and
prints the shortest escalation chain for every principal that has one.
"""

from __future__ import annotations

import sys

from cloudhunt.core.config import settings
from cloudhunt.graph.authorization import IamAuthorization
from cloudhunt.graph.model import build_graph
from cloudhunt.graph.policy_eval import PolicyEvaluator
from cloudhunt.privesc import detect_escalations, find_privesc_paths


def main() -> None:
    which = sys.argv[1] if len(sys.argv) > 1 else "cloudgoat"
    fname = "authz_snapshot_01.json" if which == "m2" else "cloudgoat_privesc_01.json"
    snap = settings.sample_data_dir / "iam_auth" / fname

    auth = IamAuthorization.from_file(snap)
    graph = build_graph(auth)
    ev = PolicyEvaluator(auth)

    edges = detect_escalations(auth, graph, ev)
    esc = [e for e in edges if e.kind == "CAN_ESCALATE_VIA"]
    acc = [e for e in edges if e.kind == "CAN_ACCESS"]
    print(f"snapshot: {fname}")
    print(f"detected {len(esc)} escalation edge(s), {len(acc)} sensitive-access edge(s)\n")

    print("=== escalation edges (technique  |  ATT&CK) ===")
    for e in esc:
        cond = " [conditional]" if e.props.get("conditional") else ""
        print(f"  {e.src.split(':')[-1]:22} --{e.props['technique']:18}--> "
              f"{e.dst.split(':')[-1]:22} ({e.props['attack_id']}){cond}")

    print("\n=== shortest privilege-escalation paths ===")
    paths = find_privesc_paths(auth, graph, ev)
    if not paths:
        print("  (none)")
    for p in paths:
        print(f"  [{p.length} hop] {p.summary()}")
        for h in p.path:
            print(f"        {h.src.split(':')[-1]}  --{h.technique}-->  {h.dst.split(':')[-1]}")


if __name__ == "__main__":
    main()
