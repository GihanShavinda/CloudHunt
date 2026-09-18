"""The identity graph: nodes + typed edges, built from an IamAuthorization.

This realises the graph model from the design phase. It is the structural,
*ingested* layer — who holds what policy, who belongs to what group, who may
assume whom, who owns what. Effective-permission ("CAN_ACCESS") and
privilege-escalation ("CAN_ESCALATE_VIA") edges are computed by the evaluator
(this milestone) and the privesc engine (Milestone 3) respectively; they are not
baked in here.

Kept as a plain in-memory structure so it is trivially testable and so the Neo4j
writer is a thin projection rather than the source of truth.

Edge types (per the M2 brief):
  HAS_POLICY          Principal -> Policy         (attached | inline)
  MEMBER_OF           user      -> group
  CAN_ASSUME          Principal -> role           {external: bool}
  OWNS_RESOURCE       Account   -> Resource
  PERMISSION_BOUNDARY Principal -> Policy         (boundary; structural, aids M3)
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from cloudhunt.graph.authorization import IamAuthorization

_ASSUME_ACTIONS = {
    "sts:assumerole",
    "sts:assumerolewithsaml",
    "sts:assumerolewithwebidentity",
}


@dataclass(frozen=True)
class Node:
    kind: str          # "Account" | "Principal" | "Policy" | "Resource"
    id: str            # arn or account id
    label: str
    props: tuple = ()  # (key, value) pairs, kept hashable

    def prop(self, key: str, default=None):
        return dict(self.props).get(key, default)


@dataclass
class Edge:
    kind: str          # HAS_POLICY | MEMBER_OF | CAN_ASSUME | OWNS_RESOURCE | PERMISSION_BOUNDARY
    src: str
    dst: str
    props: dict = field(default_factory=dict)


@dataclass
class IdentityGraph:
    nodes: dict[str, Node] = field(default_factory=dict)
    edges: list[Edge] = field(default_factory=list)

    def add_node(self, node: Node) -> None:
        self.nodes.setdefault(node.id, node)

    def add_edge(self, edge: Edge) -> None:
        self.edges.append(edge)

    def edges_of(self, kind: str) -> list[Edge]:
        return [e for e in self.edges if e.kind == kind]

    def assume_targets(self, principal_arn: str) -> list[str]:
        return [e.dst for e in self.edges if e.kind == "CAN_ASSUME" and e.src == principal_arn]


def _account_of(arn: str) -> Optional[str]:
    # arn:aws:iam::111122223333:user/x  -> 111122223333
    parts = arn.split(":")
    return parts[4] if len(parts) > 4 and parts[4] else None


def _grants_assume_role(statement) -> bool:
    if not statement.is_allow:
        return False
    for a in statement.actions:
        al = a.lower()
        if al == "*" or al == "sts:*" or al in _ASSUME_ACTIONS:
            return True
    return False


def _assume_principals(trust_statements) -> list[str]:
    out: list[str] = []
    for s in trust_statements:
        if not _grants_assume_role(s):
            continue
        principal = s.principal or {}
        if isinstance(principal, str):
            out.append(principal)
        elif isinstance(principal, dict):
            aws = principal.get("AWS")
            out.extend(aws if isinstance(aws, list) else [aws] if aws else [])
    return out


def build_graph(auth: IamAuthorization) -> IdentityGraph:
    g = IdentityGraph()
    acct = auth.account
    g.add_node(Node("Account", acct, acct))

    for mp in auth.managed_policies.values():
        g.add_node(Node("Policy", mp.arn, mp.name, (("ptype", "managed"),)))

    for prin in auth.principals.values():
        g.add_node(Node(
            "Principal", prin.arn, prin.name,
            (("ptype", prin.ptype), ("sensitivity", prin.sensitivity.value)),
        ))
        for parn in prin.attached_managed_policies:
            g.add_node(Node("Policy", parn, parn, (("ptype", "managed"),)))
            g.add_edge(Edge("HAS_POLICY", prin.arn, parn, {"attachment": "attached"}))
        for name in prin.inline_policies:
            pid = f"{prin.arn}#inline/{name}"
            g.add_node(Node("Policy", pid, name, (("ptype", "inline"),)))
            g.add_edge(Edge("HAS_POLICY", prin.arn, pid, {"attachment": "inline"}))
        if prin.permission_boundary:
            g.add_node(Node("Policy", prin.permission_boundary, prin.permission_boundary, (("ptype", "managed"),)))
            g.add_edge(Edge("PERMISSION_BOUNDARY", prin.arn, prin.permission_boundary))
        for gname in prin.groups:
            grp = auth.groups_by_name.get(gname)
            if grp:
                g.add_edge(Edge("MEMBER_OF", prin.arn, grp.arn))

    # CAN_ASSUME from role trust policies, with external-trust detection.
    for role in (p for p in auth.principals.values() if p.ptype == "role"):
        for who in _assume_principals(role.trust_statements):
            src_acct = None if who == "*" else _account_of(who)
            external = who == "*" or (src_acct is not None and src_acct != acct)
            if who not in g.nodes:
                g.add_node(Node("Principal", who, who,
                                (("ptype", "external" if external else "user"),)))
            g.add_edge(Edge("CAN_ASSUME", who, role.arn, {"external": external}))

    for res in auth.resources.values():
        g.add_node(Node(
            "Resource", res.arn, res.arn,
            (("rtype", res.rtype), ("sensitivity", res.sensitivity.value)),
        ))
        g.add_edge(Edge("OWNS_RESOURCE", acct, res.arn))

    return g
