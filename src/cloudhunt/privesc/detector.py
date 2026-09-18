"""Detect privilege-escalation edges by probing preconditions through the evaluator.

For each principal we ask the offline evaluator (Milestone 2) whether it *can*
perform the trigger action(s) of each catalogue technique on the right resource.
Because every check goes through ``PolicyEvaluator.evaluate`` we inherit Deny
precedence, permission-boundary capping and condition flagging for free — a
boundary-blocked ``iam:CreatePolicyVersion`` simply never produces an edge, and a
condition-gated trigger produces an edge marked ``conditional``.

Emitted edges (added to the :class:`IdentityGraph`):

  CAN_ESCALATE_VIA  principal -> admin-node | role   {technique, attack_id, ...}
  CAN_ACCESS        principal -> resource            {action, sensitivity, ...}

The admin-node (``Privilege`` / ``admin:<account>``) is the synthetic target for
self-grant techniques and the goal of the path search.
"""

from __future__ import annotations

from dataclasses import dataclass

from cloudhunt.graph.authorization import IamAuthorization, Principal
from cloudhunt.graph.model import Edge, IdentityGraph, Node
from cloudhunt.graph.policy_eval import PolicyEvaluator
from cloudhunt.models.events import Sensitivity
from cloudhunt.privesc import catalogue as cat


def admin_node_id(account: str) -> str:
    return f"admin:{account}"


def is_admin_equivalent(evaluator: PolicyEvaluator, arn: str) -> bool:
    """True if the principal holds an unconditional ``*``/``iam:*`` on ``*`` allow."""
    ep = evaluator.effective_permissions(arn)
    for g in ep.allows:
        if g.conditional or g.effect.lower() != "allow":
            continue
        acts = {a.lower() for a in g.actions}
        res = set(g.resources)
        if ("*" in acts or "iam:*" in acts) and "*" in res:
            return True
    return False


def _trust_allows_service(role: Principal, service_principal: str) -> bool:
    for s in role.trust_statements:
        if not s.is_allow:
            continue
        p = s.principal or {}
        svc = p.get("Service") if isinstance(p, dict) else None
        svcs = svc if isinstance(svc, list) else [svc] if svc else []
        if service_principal in svcs:
            return True
    return False


@dataclass
class _E:
    """Small carrier before we materialise a graph Edge."""
    src: str
    dst: str
    technique: cat.Technique
    conditional: bool
    detail: dict


def _probe(evaluator, arn, action, resource):
    d = evaluator.evaluate(arn, action, resource)
    return d.allowed, d.conditional


def detect_escalations(
    auth: IamAuthorization,
    graph: IdentityGraph,
    evaluator: PolicyEvaluator,
    add_to_graph: bool = True,
) -> list[Edge]:
    admin_id = admin_node_id(auth.account)
    if add_to_graph:
        graph.add_node(Node("Privilege", admin_id, "admin-equivalent"))

    found: list[_E] = []
    roles = [p for p in auth.principals.values() if p.ptype == "role"]

    for prin in auth.principals.values():
        arn = prin.arn

        # --- self-grant via CreatePolicyVersion on an attached managed policy ---
        for pol_arn in prin.attached_managed_policies:
            ok, cond = _probe(evaluator, arn, "iam:CreatePolicyVersion", pol_arn)
            if ok:
                found.append(_E(arn, admin_id, cat.CREATE_POLICY_VERSION, cond,
                                {"policy": pol_arn}))
                break

        # --- self-grant via attach/put policy on self (user vs role variants) ---
        if prin.ptype == "user":
            self_techs = [("iam:AttachUserPolicy", cat.ATTACH_USER_POLICY),
                          ("iam:PutUserPolicy", cat.PUT_USER_POLICY)]
        elif prin.ptype == "role":
            self_techs = [("iam:AttachRolePolicy", cat.ATTACH_ROLE_POLICY),
                          ("iam:PutRolePolicy", cat.PUT_ROLE_POLICY)]
        else:
            self_techs = []
        for action, tech in self_techs:
            ok, cond = _probe(evaluator, arn, action, arn)
            if ok:
                found.append(_E(arn, admin_id, tech, cond, {"on": arn}))

        # --- PassRole + compute launch ---
        for role in roles:
            passable, pass_cond = _probe(evaluator, arn, "iam:PassRole", role.arn)
            if not passable:
                continue
            for _svc, (tech, launch_action, svc_principal) in cat.PASS_ROLE_SERVICES.items():
                if not _trust_allows_service(role, svc_principal):
                    continue
                launch_ok, launch_cond = _probe(evaluator, arn, launch_action, "*")
                if launch_ok:
                    found.append(_E(arn, role.arn, tech, pass_cond or launch_cond,
                                    {"passed_role": role.arn, "launch": launch_action}))

    # --- AssumeRole escalation: trust edge (M2) + identity permission (evaluator) ---
    for e in graph.edges_of("CAN_ASSUME"):
        if e.src not in auth.principals:      # skip external/stub principals as sources
            continue
        ok, cond = _probe(evaluator, e.src, "sts:AssumeRole", e.dst)
        if ok:
            found.append(_E(e.src, e.dst, cat.ASSUME_ROLE, cond,
                            {"external_trust": bool(e.props.get("external"))}))

    edges: list[Edge] = []
    for f in found:
        edges.append(Edge(
            "CAN_ESCALATE_VIA", f.src, f.dst,
            {"technique": f.technique.key, "label": f.technique.label,
             "target": f.technique.target, "attack_id": f.technique.attack_id,
             "conditional": f.conditional, **f.detail},
        ))

    # --- CAN_ACCESS edges to sensitive (high) resources, for data-target paths ---
    for res in auth.resources.values():
        if res.sensitivity is not Sensitivity.high:
            continue
        probe_res = f"{res.arn}/cloudhunt-probe" if res.rtype == "AWS::S3::Bucket" else res.arn
        action = "s3:GetObject" if res.rtype == "AWS::S3::Bucket" else "*"
        for prin in auth.principals.values():
            ok, cond = _probe(evaluator, prin.arn, action, probe_res)
            if ok:
                edges.append(Edge(
                    "CAN_ACCESS", prin.arn, res.arn,
                    {"action": action, "sensitivity": res.sensitivity.value,
                     "conditional": cond},
                ))

    if add_to_graph:
        for e in edges:
            graph.add_edge(e)
    return edges
