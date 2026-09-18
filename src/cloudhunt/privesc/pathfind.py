"""Shortest-path search over escalation edges → PrivEscPath records.

Given the ``CAN_ESCALATE_VIA`` / ``CAN_ACCESS`` edges the detector added to the
graph, find the shortest chain from a principal to an admin-equivalent target or
a sensitive resource. We use a breadth-first search (shortest by number of hops)
as the offline source of truth; :func:`neo4j_shortest_path_query` gives the
equivalent Neo4j ``shortestPath`` Cypher for the persisted graph.
"""

from __future__ import annotations

from collections import deque
from dataclasses import dataclass, field
from typing import Optional

from cloudhunt.graph.authorization import IamAuthorization
from cloudhunt.graph.model import IdentityGraph
from cloudhunt.graph.policy_eval import PolicyEvaluator
from cloudhunt.privesc import catalogue as cat
from cloudhunt.privesc.detector import admin_node_id, is_admin_equivalent

_TRAVERSABLE = ("CAN_ESCALATE_VIA", "CAN_ACCESS")


@dataclass
class Hop:
    src: str
    technique: str      # technique key (escalation) or action (access)
    dst: str
    conditional: bool = False
    attack_id: Optional[str] = None


@dataclass
class PrivEscPath:
    principal: str
    target: str
    target_priv: str            # "admin-equivalent" | "sensitive-resource:high"
    techniques: list[str] = field(default_factory=list)
    path: list[Hop] = field(default_factory=list)
    conditional: bool = False   # any hop depends on an unevaluated condition

    @property
    def length(self) -> int:
        return len(self.path)

    def summary(self) -> str:
        chain = "  ->  ".join(
            f"{h.technique}{'?' if h.conditional else ''}" for h in self.path
        )
        flag = "  [conditional]" if self.conditional else ""
        return f"{self.principal}  =={chain}==>  {self.target_priv}{flag}"


@dataclass
class _Goals:
    admin_node: str
    admin_principals: set
    sensitive: dict          # resource arn -> sensitivity label

    def target_priv(self, node_id: str) -> Optional[str]:
        if node_id == self.admin_node or node_id in self.admin_principals:
            return "admin-equivalent"
        if node_id in self.sensitive:
            return f"sensitive-resource:{self.sensitive[node_id]}"
        return None


def _compute_goals(auth: IamAuthorization, evaluator: PolicyEvaluator) -> _Goals:
    admin_princs = {arn for arn in auth.principals
                    if is_admin_equivalent(evaluator, arn)}
    sensitive = {r.arn: r.sensitivity.value for r in auth.resources.values()
                 if r.sensitivity.value == "high"}
    return _Goals(admin_node_id(auth.account), admin_princs, sensitive)


def _adjacency(graph: IdentityGraph):
    adj: dict[str, list[tuple]] = {}
    for e in graph.edges:
        if e.kind not in _TRAVERSABLE:
            continue
        tech = e.props.get("technique") or e.props.get("action") or e.kind
        adj.setdefault(e.src, []).append(
            (e.dst, tech, bool(e.props.get("conditional")), e.props.get("attack_id"))
        )
    return adj


def shortest_path(
    graph: IdentityGraph, goals: _Goals, source: str,
) -> Optional[PrivEscPath]:
    """BFS for the nearest goal reachable from ``source``. None if unreachable."""
    # A source that is already admin has a trivial zero-length "path".
    if goals.target_priv(source) == "admin-equivalent":
        return PrivEscPath(source, source, "admin-equivalent")

    adj = _adjacency(graph)
    prev: dict[str, tuple] = {source: (None, None, False, None)}
    q = deque([source])
    while q:
        node = q.popleft()
        for dst, tech, cond, attack_id in adj.get(node, []):
            if dst in prev:
                continue
            prev[dst] = (node, tech, cond, attack_id)
            tp = goals.target_priv(dst)
            if tp is not None:
                return _reconstruct(source, dst, tp, prev)
            q.append(dst)
    return None


def _reconstruct(source, target, target_priv, prev) -> PrivEscPath:
    hops: list[Hop] = []
    node = target
    while prev[node][0] is not None:
        pnode, tech, cond, attack_id = prev[node]
        hops.append(Hop(pnode, tech, node, cond, attack_id))
        node = pnode
    hops.reverse()
    return PrivEscPath(
        principal=source, target=target, target_priv=target_priv,
        techniques=[h.technique for h in hops], path=hops,
        conditional=any(h.conditional for h in hops),
    )


def find_privesc_paths(
    auth: IamAuthorization, graph: IdentityGraph, evaluator: PolicyEvaluator,
) -> list[PrivEscPath]:
    """Shortest escalation path for every non-admin principal that has one."""
    goals = _compute_goals(auth, evaluator)
    out: list[PrivEscPath] = []
    for arn, prin in auth.principals.items():
        if arn in goals.admin_principals:      # already admin, nothing to escalate
            continue
        p = shortest_path(graph, goals, arn)
        if p is not None and p.length > 0:
            out.append(p)
    out.sort(key=lambda p: (p.length, p.principal))
    return out


def neo4j_shortest_path_query() -> str:
    """Equivalent Cypher over the persisted graph (params: $source, $admin)."""
    return (
        "MATCH (s {id: $source}), (t) "
        "WHERE t.id = $admin OR t.sensitivity = 'high' "
        "MATCH p = shortestPath( (s)-[:CAN_ESCALATE_VIA|CAN_ACCESS*1..10]->(t) ) "
        "RETURN p ORDER BY length(p) ASC LIMIT 1"
    )
