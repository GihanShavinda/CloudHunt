"""Turn a Case into Cytoscape.js elements for the workspace graph.

Two overlaid stories in one graph: the **AssumeRole / activity chain** (who did
what, in order) and the **privilege-escalation paths** behind the blast score.
Nodes are identities and resources; edges are actions (chain) and escalation hops
(blast paths). Pure and deterministic so it is trivially testable.
"""

from __future__ import annotations


def _ntype(arn: str) -> str:
    if ":role/" in arn:
        return "role"
    if ":user/" in arn:
        return "user"
    return "resource"


def _short(arn: str) -> str:
    return arn.split("/")[-1] or arn.split(":")[-1] or arn


def case_to_elements(case) -> dict:
    nodes: dict[str, dict] = {}
    edges: list[dict] = []
    eid = 0

    def add_node(arn: str, ntype: str | None = None) -> None:
        if arn and arn not in nodes:
            nodes[arn] = {"data": {"id": arn, "label": _short(arn),
                                   "type": ntype or _ntype(arn)}}

    # Activity / AssumeRole chain
    for step in case.chain.steps:
        add_node(step.actor)
        if step.target:
            add_node(step.target)
            edges.append({"data": {"id": f"a{eid}", "source": step.actor,
                                   "target": step.target, "label": step.action,
                                   "kind": "activity", "tactic": step.tactic}})
            eid += 1

    # Privilege-escalation paths behind the blast score
    for path in (getattr(case.blast, "reach_admin_path", None),
                 getattr(case.blast, "reach_sensitive_path", None)):
        if not path or not path.path:
            continue
        for hop in path.path:
            add_node(hop.src)
            add_node(hop.dst)
            edges.append({"data": {"id": f"e{eid}", "source": hop.src,
                                   "target": hop.dst, "label": hop.technique,
                                   "kind": "escalation"}})
            eid += 1

    return {"nodes": list(nodes.values()), "edges": edges}
