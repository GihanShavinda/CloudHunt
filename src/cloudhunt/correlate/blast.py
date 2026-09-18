"""Blast-radius scoring — how much damage a compromised principal enables.

    blast(p) = w1*reach_sensitive + w2*reach_admin + w3*privesc_available
             + w4*current_privilege                        (scaled to 0..100)

Each term is in [0, 1]. The first three are graph-reachability booleans; the
fourth grades what the principal can *already* do. Crucially the score is
**explainable**: the returned :class:`BlastRadius` carries the actual graph paths
(admin and sensitive) and the current-privilege capabilities that produced it, so
an analyst can see *why* a number is high, not just that it is.

Reachability reuses the Milestone-3 search over ``CAN_ESCALATE_VIA`` /
``CAN_ACCESS`` edges; run :func:`cloudhunt.privesc.detect_escalations` on the
graph first so those edges exist.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from cloudhunt.graph.authorization import IamAuthorization
from cloudhunt.graph.model import IdentityGraph
from cloudhunt.graph.policy_eval import PolicyEvaluator
from cloudhunt.privesc.detector import is_admin_equivalent
from cloudhunt.privesc.pathfind import (
    PrivEscPath,
    _Goals,
    _compute_goals,
    shortest_path,
)

# IAM mutating verbs — used to grade "can already manipulate identity".
_IAM_WRITE_VERBS = ("create", "update", "put", "attach", "detach", "delete",
                    "add", "remove", "set")
# Capability -> contribution to current_privilege (admin short-circuits to 1.0).
_CAP_WEIGHT = {"read_sensitive": 0.5, "iam_write": 0.3, "can_assume": 0.2}


@dataclass
class Weights:
    reach_sensitive: float = 0.30
    reach_admin: float = 0.30
    privesc_available: float = 0.20
    current_privilege: float = 0.20


@dataclass
class BlastRadius:
    principal: str
    score: float                              # 0..100
    components: dict = field(default_factory=dict)   # term -> {value, weight, contribution}
    reach_admin_path: Optional[PrivEscPath] = None
    reach_sensitive_path: Optional[PrivEscPath] = None
    current_privilege_caps: list[str] = field(default_factory=list)

    def explanation(self) -> str:
        lines = [f"blast {self.score:.0f}/100 for {self.principal}"]
        for term, c in self.components.items():
            lines.append(f"  {term:18} value={c['value']:.2f} "
                         f"x w={c['weight']:.2f} -> {c['contribution']:.1f}")
        if self.reach_admin_path and self.reach_admin_path.path:
            lines.append(f"  admin path:     {self.reach_admin_path.summary()}")
        if self.reach_sensitive_path and self.reach_sensitive_path.path:
            lines.append(f"  sensitive path: {self.reach_sensitive_path.summary()}")
        if self.current_privilege_caps:
            lines.append(f"  current caps:   {', '.join(self.current_privilege_caps)}")
        return "\n".join(lines)


def _has_iam_write_now(evaluator: PolicyEvaluator, arn: str) -> bool:
    ep = evaluator.effective_permissions(arn)
    for g in ep.allows:
        if g.conditional or g.effect.lower() != "allow" or not g.resources:
            continue
        for a in g.actions:
            al = a.lower()
            if al in ("*", "iam:*"):
                return True
            if al.startswith("iam:") and any(v in al for v in _IAM_WRITE_VERBS):
                return True
    return False


def _reaches_sensitive_now(graph: IdentityGraph, arn: str, sensitive: dict) -> bool:
    for e in graph.edges_of("CAN_ACCESS"):
        if e.src == arn and e.dst in sensitive:
            return True
    return False


def _current_privilege(
    arn: str, auth: IamAuthorization, graph: IdentityGraph,
    evaluator: PolicyEvaluator, sensitive: dict,
) -> tuple[float, list[str]]:
    if is_admin_equivalent(evaluator, arn):
        return 1.0, ["admin-equivalent"]
    caps: list[str] = []
    if _reaches_sensitive_now(graph, arn, sensitive):
        caps.append("read_sensitive")
    if _has_iam_write_now(evaluator, arn):
        caps.append("iam_write")
    if graph.assume_targets(arn):
        caps.append("can_assume")
    value = min(1.0, sum(_CAP_WEIGHT[c] for c in caps))
    return value, caps


def score_blast(
    principal: str,
    auth: IamAuthorization,
    graph: IdentityGraph,
    evaluator: PolicyEvaluator,
    weights: Optional[Weights] = None,
) -> BlastRadius:
    w = weights or Weights()
    goals = _compute_goals(auth, evaluator)
    admin_goals = _Goals(goals.admin_node, goals.admin_principals, {})
    sens_goals = _Goals("\0none", set(), goals.sensitive)

    path_admin = shortest_path(graph, admin_goals, principal)
    path_sensitive = shortest_path(graph, sens_goals, principal)

    reach_admin = 1.0 if path_admin is not None else 0.0
    reach_sensitive = 1.0 if path_sensitive is not None else 0.0
    # An escalation is "available" only if reaching admin needs one or more hops.
    privesc_available = 1.0 if (path_admin is not None and path_admin.length > 0) else 0.0
    current_priv, caps = _current_privilege(principal, auth, graph, evaluator, goals.sensitive)

    terms = {
        "reach_sensitive": (reach_sensitive, w.reach_sensitive),
        "reach_admin": (reach_admin, w.reach_admin),
        "privesc_available": (privesc_available, w.privesc_available),
        "current_privilege": (current_priv, w.current_privilege),
    }
    components = {
        name: {"value": val, "weight": wt, "contribution": round(val * wt * 100, 1)}
        for name, (val, wt) in terms.items()
    }
    score = round(sum(c["contribution"] for c in components.values()), 1)

    return BlastRadius(
        principal=principal, score=score, components=components,
        reach_admin_path=path_admin, reach_sensitive_path=path_sensitive,
        current_privilege_caps=caps,
    )
