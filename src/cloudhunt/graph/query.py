"""The two questions a responder actually asks the graph.

* ``what_can_principal_do`` — a principal's effective permissions, both as the
  symbolic merged grant set and (best-effort) as concrete Allow decisions over
  the resources in the snapshot.
* ``who_can_do`` — every principal that can perform an action on a resource,
  with an option to include indirect reach via ``sts:AssumeRole`` chains.

Both are thin wrappers over :class:`PolicyEvaluator`, so they inherit its
Deny-precedence, boundary handling and uncertainty flags for free.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from cloudhunt.graph.model import IdentityGraph
from cloudhunt.graph.policy_eval import Decision, Effect, EffectivePermissions, PolicyEvaluator

# A floor of high-signal actions always worth probing, even if a policy only
# grants them via a wildcard we can't enumerate.
_SENSITIVE_ACTIONS = (
    "iam:CreatePolicyVersion",
    "iam:PutUserPolicy",
    "iam:AttachUserPolicy",
    "iam:PassRole",
    "sts:AssumeRole",
    "s3:GetObject",
    "s3:PutObject",
    "s3:DeleteObject",
    "cloudtrail:StopLogging",
    "cloudtrail:DeleteTrail",
)


def _action_universe(evaluator: PolicyEvaluator) -> list[str]:
    actions: set[str] = set(_SENSITIVE_ACTIONS)
    auth = evaluator.auth
    pools = [mp.statements for mp in auth.managed_policies.values()]
    for prin in auth.principals.values():
        pools.extend(prin.inline_policies.values())
    for stmts in pools:
        for s in stmts:
            for a in s.actions:
                if "*" not in a and ":" in a:
                    actions.add(a)
    return sorted(actions)


@dataclass
class PrincipalCapabilities:
    principal: str
    symbolic: EffectivePermissions
    concrete: list[Decision] = field(default_factory=list)  # ALLOW / conditional only


def what_can_principal_do(
    evaluator: PolicyEvaluator,
    principal_arn: str,
    resources: Optional[list[str]] = None,
    actions: Optional[list[str]] = None,
) -> PrincipalCapabilities:
    symbolic = evaluator.effective_permissions(principal_arn)
    res_list = resources if resources is not None else list(evaluator.auth.resources.keys())
    act_list = actions if actions is not None else _action_universe(evaluator)

    concrete: list[Decision] = []
    for resource in res_list:
        for action in act_list:
            d = evaluator.evaluate(principal_arn, action, resource)
            if d.allowed:
                concrete.append(d)
    return PrincipalCapabilities(principal_arn, symbolic, concrete)


@dataclass
class WhoCanResult:
    action: str
    resource: str
    allowed: list[Decision] = field(default_factory=list)
    denied: list[Decision] = field(default_factory=list)          # explicit denials
    via_assume: list[tuple[str, str]] = field(default_factory=list)  # (assumer, role)


def _assumers_of(graph: IdentityGraph, role_arn: str, seen: set[str]) -> list[str]:
    """Transitive set of principals that can reach ``role_arn`` via CAN_ASSUME."""
    result: list[str] = []
    for e in graph.edges_of("CAN_ASSUME"):
        if e.dst == role_arn and e.src not in seen:
            seen.add(e.src)
            result.append(e.src)
            result.extend(_assumers_of(graph, e.src, seen))  # chained assumption
    return result


def who_can_do(
    evaluator: PolicyEvaluator,
    action: str,
    resource: str,
    graph: Optional[IdentityGraph] = None,
    include_assume_paths: bool = False,
) -> WhoCanResult:
    out = WhoCanResult(action=action, resource=resource)
    for arn in evaluator.auth.principals:
        d = evaluator.evaluate(arn, action, resource)
        if d.allowed:
            out.allowed.append(d)
        elif d.effect is Effect.EXPLICIT_DENY:
            out.denied.append(d)

    if include_assume_paths and graph is not None:
        direct = {d.principal for d in out.allowed}
        for d in out.allowed:
            if evaluator.auth.principals.get(d.principal) and \
                    evaluator.auth.principals[d.principal].ptype == "role":
                for assumer in _assumers_of(graph, d.principal, set()):
                    if assumer not in direct:
                        out.via_assume.append((assumer, d.principal))
    return out
