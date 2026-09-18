"""The IAM authorization model — the substrate the evaluator reasons over.

This is a simplified shape of AWS IAM ``get-account-authorization-details``
(the offline, no-API way to obtain a full account's identity configuration). A
snapshot is parsed into :class:`IamAuthorization`, which indexes principals,
policies and resources for O(1) lookup during evaluation.

Snapshot shape (see ``sample_data/iam_auth/``)::

    {
      "account": "111122223333",
      "users":  [ {"arn","name","tags","attached_managed_policies":[arn...],
                   "inline_policies": {name: <policy-doc>}, "groups":[name...],
                   "permission_boundary": arn|null} ],
      "groups": [ {"arn","name","attached_managed_policies","inline_policies"} ],
      "roles":  [ {"arn","name","tags","attached_managed_policies",
                   "inline_policies","permission_boundary",
                   "trust_policy": <assume-role-policy-doc>} ],
      "managed_policies": [ {"arn","name","document": <policy-doc>} ],
      "resources": [ {"arn","type","tags","resource_policy": <policy-doc>|null} ]
    }

A *policy document* is a standard IAM document: ``{"Statement": [ {...} ]}``.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

from cloudhunt.models.events import Sensitivity


def _sensitivity_from_tags(tags: dict[str, str]) -> Sensitivity:
    try:
        return Sensitivity(str(tags.get("Sensitivity", "")).lower())
    except ValueError:
        return Sensitivity.unknown


@dataclass(slots=True)
class Statement:
    """One policy statement, normalised. Effect + (Action|NotAction) + (Resource|NotResource)."""

    effect: str  # "Allow" | "Deny"
    actions: list[str] = field(default_factory=list)
    not_actions: list[str] = field(default_factory=list)
    resources: list[str] = field(default_factory=list)
    not_resources: list[str] = field(default_factory=list)
    condition: dict[str, Any] = field(default_factory=dict)
    principal: Any = None  # only meaningful for trust / resource policies
    sid: Optional[str] = None

    @property
    def is_allow(self) -> bool:
        return self.effect.lower() == "allow"

    @property
    def is_deny(self) -> bool:
        return self.effect.lower() == "deny"


def _as_list(value) -> list[str]:
    if value is None:
        return []
    return [value] if isinstance(value, str) else list(value)


def parse_statements(document: Optional[dict[str, Any]]) -> list[Statement]:
    """Parse a policy document into normalised statements. Empty doc -> []."""
    if not document:
        return []
    raw = document.get("Statement", [])
    if isinstance(raw, dict):  # a single statement is legal
        raw = [raw]
    out: list[Statement] = []
    for s in raw:
        out.append(
            Statement(
                effect=s.get("Effect", "Deny"),
                actions=_as_list(s.get("Action")),
                not_actions=_as_list(s.get("NotAction")),
                resources=_as_list(s.get("Resource")),
                not_resources=_as_list(s.get("NotResource")),
                condition=s.get("Condition", {}) or {},
                principal=s.get("Principal"),
                sid=s.get("Sid"),
            )
        )
    return out


@dataclass
class Principal:
    arn: str
    name: str
    ptype: str  # "user" | "role" | "group"
    tags: dict[str, str] = field(default_factory=dict)
    attached_managed_policies: list[str] = field(default_factory=list)
    inline_policies: dict[str, list[Statement]] = field(default_factory=dict)
    groups: list[str] = field(default_factory=list)
    permission_boundary: Optional[str] = None
    trust_statements: list[Statement] = field(default_factory=list)  # roles only

    @property
    def sensitivity(self) -> Sensitivity:
        return _sensitivity_from_tags(self.tags)


@dataclass
class ManagedPolicy:
    arn: str
    name: str
    statements: list[Statement]


@dataclass
class Resource:
    arn: str
    rtype: str
    tags: dict[str, str] = field(default_factory=dict)
    resource_statements: list[Statement] = field(default_factory=list)

    @property
    def sensitivity(self) -> Sensitivity:
        return _sensitivity_from_tags(self.tags)


@dataclass
class IamAuthorization:
    account: str = "unknown"
    principals: dict[str, Principal] = field(default_factory=dict)  # keyed by arn
    groups_by_name: dict[str, Principal] = field(default_factory=dict)
    managed_policies: dict[str, ManagedPolicy] = field(default_factory=dict)  # keyed by arn
    resources: dict[str, Resource] = field(default_factory=dict)  # keyed by arn

    # ---- construction ----
    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "IamAuthorization":
        auth = cls(account=payload.get("account", "unknown"))

        for mp in payload.get("managed_policies", []):
            auth.managed_policies[mp["arn"]] = ManagedPolicy(
                arn=mp["arn"], name=mp.get("name", mp["arn"]),
                statements=parse_statements(mp.get("document")),
            )

        def _mk(p: dict[str, Any], ptype: str) -> Principal:
            return Principal(
                arn=p["arn"], name=p.get("name", p["arn"]), ptype=ptype,
                tags=p.get("tags", {}),
                attached_managed_policies=list(p.get("attached_managed_policies", [])),
                inline_policies={n: parse_statements(d)
                                 for n, d in (p.get("inline_policies", {}) or {}).items()},
                groups=list(p.get("groups", [])),
                permission_boundary=p.get("permission_boundary"),
                trust_statements=parse_statements(p.get("trust_policy")),
            )

        for g in payload.get("groups", []):
            prin = _mk(g, "group")
            auth.principals[prin.arn] = prin
            auth.groups_by_name[prin.name] = prin
        for u in payload.get("users", []):
            prin = _mk(u, "user")
            auth.principals[prin.arn] = prin
        for r in payload.get("roles", []):
            prin = _mk(r, "role")
            auth.principals[prin.arn] = prin

        for res in payload.get("resources", []):
            auth.resources[res["arn"]] = Resource(
                arn=res["arn"], rtype=res.get("type", "unknown"),
                tags=res.get("tags", {}),
                resource_statements=parse_statements(res.get("resource_policy")),
            )
        return auth

    @classmethod
    def from_file(cls, path: str | Path) -> "IamAuthorization":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))

    # ---- helpers used by the evaluator ----
    def statements_for(self, arn: str) -> list[tuple[str, Statement]]:
        """All identity statements applying to a principal, tagged with provenance.

        Returns ``(source_label, statement)`` pairs so a decision can name the
        policy that produced it. For a user this includes inline + attached +
        every group's inline + attached policies.
        """
        prin = self.principals.get(arn)
        if prin is None:
            return []
        out: list[tuple[str, Statement]] = []
        self._collect(prin, out)
        for gname in prin.groups:
            grp = self.groups_by_name.get(gname)
            if grp:
                self._collect(grp, out, prefix=f"group:{gname}/")
        return out

    def _collect(self, prin: Principal, out: list, prefix: str = "") -> None:
        for name, stmts in prin.inline_policies.items():
            for s in stmts:
                out.append((f"{prefix}inline:{name}", s))
        for parn in prin.attached_managed_policies:
            mp = self.managed_policies.get(parn)
            if mp:
                for s in mp.statements:
                    out.append((f"{prefix}managed:{mp.name}", s))

    def boundary_statements(self, arn: str) -> Optional[list[Statement]]:
        """The permission-boundary policy's statements, or ``None`` if no boundary."""
        prin = self.principals.get(arn)
        if prin is None or not prin.permission_boundary:
            return None
        mp = self.managed_policies.get(prin.permission_boundary)
        return mp.statements if mp else []
