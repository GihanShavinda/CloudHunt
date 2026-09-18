"""The offline policy-evaluation engine.

Resolves what a principal can *effectively* do, using only a parsed
:class:`IamAuthorization` snapshot — no live AWS calls. It implements the parts
of IAM request evaluation that can be decided from configuration alone, and is
scrupulous about flagging the parts that cannot.

Decision precedence implemented (single-account, identity-based focus):

1. An explicit, unconditional ``Deny`` (in identity, permission boundary, or the
   resource policy) wins over everything -> ``EXPLICIT_DENY``.
2. Otherwise ``Allow`` requires a matching identity ``Allow`` **and**, if a
   permission boundary exists, a matching ``Allow`` in the boundary too. A
   same-account resource-policy ``Allow`` can also grant on its own.
3. Otherwise the default is ``IMPLICIT_DENY``.

Conditions are **not evaluated** (they depend on request context we don't have
offline). A matched statement that carries a ``Condition`` is honoured
structurally but flagged: an allow becomes "conditional", and a would-be deny is
surfaced as a *potential* deny rather than silently applied. See
``docs/milestone-02-graph-policy-eval.md`` for the full list of simplifications.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from cloudhunt.graph.authorization import IamAuthorization, Statement
from cloudhunt.graph.matching import any_action_matches, any_resource_matches


class Effect(str, Enum):
    ALLOW = "ALLOW"
    EXPLICIT_DENY = "EXPLICIT_DENY"
    IMPLICIT_DENY = "IMPLICIT_DENY"


@dataclass
class Decision:
    effect: Effect
    principal: str
    action: str
    resource: str
    conditional: bool = False
    boundary_limited: bool = False
    reasons: list[str] = field(default_factory=list)
    matched: list[str] = field(default_factory=list)      # provenance labels
    uncertainty: list[str] = field(default_factory=list)  # human-readable caveats

    @property
    def allowed(self) -> bool:
        return self.effect is Effect.ALLOW

    def summary(self) -> str:
        tag = self.effect.value
        if self.allowed and self.conditional:
            tag = "ALLOW (conditional)"
        return f"{tag}: {self.principal} -> {self.action} on {self.resource}"


def _condition_keys(cond: dict) -> list[str]:
    keys: list[str] = []
    for op_block in cond.values():
        if isinstance(op_block, dict):
            keys.extend(op_block.keys())
    return keys


def _stmt_matches(stmt: Statement, action: str, resource: str) -> bool:
    # Action side: Action (positive) or NotAction (negated).
    if stmt.actions:
        if not any_action_matches(stmt.actions, action):
            return False
    elif stmt.not_actions:
        if any_action_matches(stmt.not_actions, action):
            return False
    else:
        return False  # a statement with neither matches nothing useful here

    # Resource side: Resource (positive) or NotResource (negated).
    if stmt.resources:
        if not any_resource_matches(stmt.resources, resource):
            return False
    elif stmt.not_resources:
        if any_resource_matches(stmt.not_resources, resource):
            return False
    # No resource clause at all -> treat as "*"(some AWS APIs omit it); permissive.
    return True


@dataclass
class _Hit:
    conditional: bool
    label: str
    condition_keys: list[str]


class PolicyEvaluator:
    def __init__(self, auth: IamAuthorization):
        self.auth = auth

    # -- low-level: partition matching statements into allow/deny hits --
    def _scan(self, stmts, action, resource, label_prefix=""):
        allows: list[_Hit] = []
        denies: list[_Hit] = []
        for label, stmt in stmts:
            if not _stmt_matches(stmt, action, resource):
                continue
            hit = _Hit(bool(stmt.condition), f"{label_prefix}{label}", _condition_keys(stmt.condition))
            (allows if stmt.is_allow else denies).append(hit)
        return allows, denies

    def evaluate(self, principal_arn: str, action: str, resource: str) -> Decision:
        d = Decision(Effect.IMPLICIT_DENY, principal_arn, action, resource)

        if principal_arn not in self.auth.principals:
            d.reasons.append("unknown principal (not in snapshot)")
            d.uncertainty.append("principal absent from snapshot; result is a guess")
            return d

        identity = self.auth.statements_for(principal_arn)
        id_allows, id_denies = self._scan(identity, action, resource)

        # Resource-based policy (same-account simplification).
        res = self.auth.resources.get(resource)
        res_allows, res_denies = ([], [])
        if res is not None and res.resource_statements:
            labelled = [("resource-policy", s) for s in res.resource_statements]
            res_allows, res_denies = self._scan(labelled, action, resource)
            d.uncertainty.append(
                "resource-based policy present; cross-account/service-specific "
                "semantics are simplified"
            )

        # 1) Explicit unconditional Deny anywhere wins.
        for hit in id_denies + res_denies:
            if not hit.conditional:
                d.effect = Effect.EXPLICIT_DENY
                d.reasons.append(f"explicit Deny in {hit.label}")
                d.matched.append(hit.label)
                return d
        # Conditional denies: cannot resolve offline -> surface as potential.
        for hit in id_denies + res_denies:
            if hit.conditional:
                d.uncertainty.append(
                    f"potential Deny in {hit.label} under condition(s): "
                    f"{', '.join(hit.condition_keys) or 'unspecified'}"
                )

        # 2) Allow (identity) + permission boundary.
        boundary = self.auth.boundary_statements(principal_arn)
        allow_hit = _pick(id_allows)
        if allow_hit is not None:
            if boundary is not None:
                b_labelled = [("boundary", s) for s in boundary]
                b_allows, b_denies = self._scan(b_labelled, action, resource)
                for h in b_denies:
                    if not h.conditional:
                        d.effect = Effect.EXPLICIT_DENY
                        d.reasons.append("explicit Deny in permission boundary")
                        d.matched.append(h.label)
                        return d
                b_allow = _pick(b_allows)
                if b_allow is None:
                    d.effect = Effect.IMPLICIT_DENY
                    d.boundary_limited = True
                    d.reasons.append("action not permitted by permission boundary")
                    d.matched.append(allow_hit.label)
                    return d
                d.boundary_limited = True
                d.reasons.append("permitted within permission boundary")
                if b_allow.conditional:
                    allow_hit = _Hit(True, allow_hit.label, allow_hit.condition_keys + b_allow.condition_keys)

            d.effect = Effect.ALLOW
            d.matched.append(allow_hit.label)
            d.reasons.append(f"Allow in {allow_hit.label}")
            if allow_hit.conditional:
                d.conditional = True
                d.uncertainty.append(
                    f"Allow depends on unevaluated condition(s): "
                    f"{', '.join(allow_hit.condition_keys) or 'unspecified'}"
                )
            return d

        # 2b) No identity allow, but a same-account resource-policy allow can grant.
        res_allow = _pick(res_allows)
        if res_allow is not None:
            d.effect = Effect.ALLOW
            d.matched.append(res_allow.label)
            d.reasons.append("Allow via resource-based policy")
            d.conditional = res_allow.conditional or d.conditional
            return d

        # 3) Default.
        d.reasons.append("no matching Allow (implicit deny)")
        return d

    def effective_permissions(self, principal_arn: str) -> "EffectivePermissions":
        """Symbolic view of a principal's grants — the merged statement set.

        Concrete "can X do action A on resource R?" answers come from
        :meth:`evaluate`; this is the human-readable merge used by
        ``what_can_principal_do`` and the demo.
        """
        ep = EffectivePermissions(principal_arn)
        prin = self.auth.principals.get(principal_arn)
        if prin is None:
            ep.uncertainty.append("principal absent from snapshot")
            return ep
        for label, stmt in self.auth.statements_for(principal_arn):
            grant = ResolvedGrant(
                effect=stmt.effect,
                actions=stmt.actions or [f"NOT {a}" for a in stmt.not_actions],
                resources=stmt.resources or [f"NOT {r}" for r in stmt.not_resources],
                conditional=bool(stmt.condition),
                source=label,
            )
            (ep.denies if stmt.is_deny else ep.allows).append(grant)
        if prin.permission_boundary:
            ep.boundary = prin.permission_boundary
            ep.uncertainty.append(f"permission boundary applies: {prin.permission_boundary}")
        return ep


def _pick(hits: list[_Hit]) -> Optional[_Hit]:
    """Prefer an unconditional hit over a conditional one."""
    if not hits:
        return None
    for h in hits:
        if not h.conditional:
            return h
    return hits[0]


@dataclass
class ResolvedGrant:
    effect: str
    actions: list[str]
    resources: list[str]
    conditional: bool
    source: str


@dataclass
class EffectivePermissions:
    principal: str
    allows: list[ResolvedGrant] = field(default_factory=list)
    denies: list[ResolvedGrant] = field(default_factory=list)
    boundary: Optional[str] = None
    uncertainty: list[str] = field(default_factory=list)
