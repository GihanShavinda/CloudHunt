"""The response action catalogue.

Each action declares its safety metadata — ``impact``, ``scope``, ``reversible``,
``always_human`` — which the decision engine reads, and implements ``execute`` and
``undo``. ``execute`` returns an :class:`Outcome` carrying the before/after state
and an ``undo_ref``; ``undo`` consumes that ``undo_ref`` to restore the prior
state. Reversibility is therefore not a claim in a comment — it is exercised by
the tests, which execute then undo every action and assert the world is back.

Only actions that are ``reversible`` *and* ``impact == LOW`` *and*
``scope == PRINCIPAL`` *and not* ``always_human`` are even eligible to auto-run;
see :mod:`cloudhunt.respond.decision`. By that definition exactly one action here
(deactivate access key) can auto-run — everything else is human-gated by
construction.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from cloudhunt.respond.executor import ActionExecutor

QUARANTINE_POLICY = "CloudHuntQuarantine"
REVOKE_POLICY = "CloudHuntRevokeOlderSessions"
_DENY_ALL = {"Version": "2012-10-17",
             "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*"}]}


class Impact(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"


class Scope(str, Enum):
    principal = "principal"      # affects one identity
    resource = "resource"        # affects one resource (instance/volume)
    account = "account"          # account/org-wide (e.g. a trail)


@dataclass
class ActionTarget:
    principal_arn: Optional[str] = None
    user_name: Optional[str] = None
    role_name: Optional[str] = None
    access_key_id: Optional[str] = None
    instance_id: Optional[str] = None
    volume_id: Optional[str] = None
    trail_name: Optional[str] = None
    quarantine_sg: Optional[str] = None


@dataclass
class Outcome:
    before: dict = field(default_factory=dict)
    after: dict = field(default_factory=dict)
    undo_ref: dict = field(default_factory=dict)


class Action:
    """Base action. Subclasses set metadata and implement execute/undo."""

    key: str = ""
    title: str = ""
    impact: Impact = Impact.high
    scope: Scope = Scope.principal
    reversible: bool = True
    always_human: bool = True

    def execute(self, ex: ActionExecutor, t: ActionTarget) -> Outcome:  # pragma: no cover
        raise NotImplementedError

    def undo(self, ex: ActionExecutor, undo_ref: dict) -> Outcome:      # pragma: no cover
        raise NotImplementedError


class DeactivateAccessKey(Action):
    """Set a user's leaked access key(s) to Inactive. The one auto-eligible action.

    Low impact (a key can be reactivated instantly), reversible, confined to a
    single principal. If no specific key id is given, every currently-Active key
    for the user is deactivated (full containment of a leaked long-term cred).
    FP cost is tiny and instantly undoable, which is exactly why it may auto-run.
    """

    key = "deactivate-access-key"
    title = "Deactivate access key"
    impact = Impact.low
    scope = Scope.principal
    reversible = True
    always_human = False

    def execute(self, ex, t):
        keys = ex.list_access_keys(t.user_name)
        targets = ([{"AccessKeyId": t.access_key_id,
                     "Status": next((k["Status"] for k in keys
                                     if k["AccessKeyId"] == t.access_key_id), "Active")}]
                   if t.access_key_id else [k for k in keys if k["Status"] == "Active"])
        before = {k["AccessKeyId"]: k["Status"] for k in targets}
        for k in targets:
            ex.update_access_key(t.user_name, k["AccessKeyId"], "Inactive")
        after = {kid: "Inactive" for kid in before}
        return Outcome(before=before, after=after,
                       undo_ref={"user_name": t.user_name, "restore": before})

    def undo(self, ex, undo_ref):
        before = {kid: "Inactive" for kid in undo_ref["restore"]}
        for kid, status in undo_ref["restore"].items():
            ex.update_access_key(undo_ref["user_name"], kid, status)
        return Outcome(before=before, after=dict(undo_ref["restore"]), undo_ref={})


class QuarantinePrincipal(Action):
    """Attach an explicit deny-all inline policy to a principal (freeze it).

    Reversible (detach to restore), but high impact — it can break a legitimate
    workload — so it ALWAYS requires human approval.
    """

    key = "quarantine-principal"
    title = "Quarantine principal (explicit deny)"
    impact = Impact.high
    scope = Scope.principal
    reversible = True
    always_human = True

    def _is_role(self, t: ActionTarget) -> bool:
        arn = t.principal_arn or ""
        return bool(t.role_name) or ":role/" in arn

    def execute(self, ex, t):
        if self._is_role(t):
            name = t.role_name or (t.principal_arn or "").split("/")[-1]
            before = {"inline_policies": ex.list_role_policies(name)}
            ex.put_role_policy(name, QUARANTINE_POLICY, _DENY_ALL)
            after = {"inline_policies": ex.list_role_policies(name)}
            ref = {"kind": "role", "name": name, "policy": QUARANTINE_POLICY}
        else:
            name = t.user_name or (t.principal_arn or "").split("/")[-1]
            before = {"inline_policies": ex.list_user_policies(name)}
            ex.put_user_policy(name, QUARANTINE_POLICY, _DENY_ALL)
            after = {"inline_policies": ex.list_user_policies(name)}
            ref = {"kind": "user", "name": name, "policy": QUARANTINE_POLICY}
        return Outcome(before=before, after=after, undo_ref=ref)

    def undo(self, ex, undo_ref):
        if undo_ref["kind"] == "role":
            before = {"inline_policies": ex.list_role_policies(undo_ref["name"])}
            ex.delete_role_policy(undo_ref["name"], undo_ref["policy"])
            after = {"inline_policies": ex.list_role_policies(undo_ref["name"])}
        else:
            before = {"inline_policies": ex.list_user_policies(undo_ref["name"])}
            ex.delete_user_policy(undo_ref["name"], undo_ref["policy"])
            after = {"inline_policies": ex.list_user_policies(undo_ref["name"])}
        return Outcome(before=before, after=after, undo_ref={})


class RevokeSessions(Action):
    """Invalidate a role's existing temporary sessions via a token-issue-time deny.

    Reversible (remove the policy), but medium impact — it also kicks out
    legitimate sessions — so it does not auto-run.
    """

    key = "revoke-sessions"
    title = "Revoke active sessions"
    impact = Impact.medium
    scope = Scope.principal
    reversible = True
    always_human = True

    def _doc(self):
        stamp = datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        return {"Version": "2012-10-17", "Statement": [{
            "Effect": "Deny", "Action": "*", "Resource": "*",
            "Condition": {"DateLessThan": {"aws:TokenIssueTime": stamp}}}]}

    def execute(self, ex, t):
        name = t.role_name or (t.principal_arn or "").split("/")[-1]
        before = {"inline_policies": ex.list_role_policies(name)}
        ex.put_role_policy(name, REVOKE_POLICY, self._doc())
        after = {"inline_policies": ex.list_role_policies(name)}
        return Outcome(before=before, after=after,
                       undo_ref={"name": name, "policy": REVOKE_POLICY})

    def undo(self, ex, undo_ref):
        before = {"inline_policies": ex.list_role_policies(undo_ref["name"])}
        ex.delete_role_policy(undo_ref["name"], undo_ref["policy"])
        after = {"inline_policies": ex.list_role_policies(undo_ref["name"])}
        return Outcome(before=before, after=after, undo_ref={})


class IsolateInstance(Action):
    """Swap an EC2 instance's security groups for a single quarantine SG.

    Reversible (restore original SGs), high impact (severs the instance's
    network) — always human-approved.
    """

    key = "isolate-instance"
    title = "Isolate EC2 instance (quarantine SG)"
    impact = Impact.high
    scope = Scope.resource
    reversible = True
    always_human = True

    def execute(self, ex, t):
        original = ex.instance_security_groups(t.instance_id)
        qsg = t.quarantine_sg or "sg-quarantine"
        before = {"security_groups": original}
        ex.set_instance_security_groups(t.instance_id, [qsg])
        after = {"security_groups": [qsg]}
        return Outcome(before=before, after=after,
                       undo_ref={"instance_id": t.instance_id, "restore": original})

    def undo(self, ex, undo_ref):
        before = {"security_groups": ex.instance_security_groups(undo_ref["instance_id"])}
        ex.set_instance_security_groups(undo_ref["instance_id"], undo_ref["restore"])
        after = {"security_groups": list(undo_ref["restore"])}
        return Outcome(before=before, after=after, undo_ref={})


class ReEnableLogging(Action):
    """Restart a CloudTrail trail an attacker stopped.

    Account/org-wide scope (a trail governs the whole account), so it always
    requires human approval even though it is a restorative action.
    """

    key = "re-enable-logging"
    title = "Re-enable CloudTrail logging"
    impact = Impact.medium
    scope = Scope.account
    reversible = True
    always_human = True

    def execute(self, ex, t):
        before = {"is_logging": ex.trail_is_logging(t.trail_name)}
        ex.start_logging(t.trail_name)
        after = {"is_logging": ex.trail_is_logging(t.trail_name)}
        return Outcome(before=before, after=after,
                       undo_ref={"trail_name": t.trail_name, "prior": before["is_logging"]})

    def undo(self, ex, undo_ref):
        before = {"is_logging": ex.trail_is_logging(undo_ref["trail_name"])}
        if undo_ref["prior"]:
            ex.start_logging(undo_ref["trail_name"])
        else:
            ex.stop_logging(undo_ref["trail_name"])
        after = {"is_logging": ex.trail_is_logging(undo_ref["trail_name"])}
        return Outcome(before=before, after=after, undo_ref={})


class SnapshotForensics(Action):
    """Create an EBS snapshot for forensics.

    Reversible (delete the snapshot) and low impact, but resource-scoped rather
    than principal-scoped, so it is not auto-eligible and stays human-approved.
    """

    key = "snapshot-forensics"
    title = "Snapshot volume for forensics"
    impact = Impact.low
    scope = Scope.resource
    reversible = True
    always_human = True

    def execute(self, ex, t):
        before = {"snapshot_id": None}
        sid = ex.create_snapshot(t.volume_id, f"cloudhunt-forensics {t.volume_id}")
        after = {"snapshot_id": sid}
        return Outcome(before=before, after=after, undo_ref={"snapshot_id": sid})

    def undo(self, ex, undo_ref):
        before = {"snapshot_id": undo_ref["snapshot_id"]}
        ex.delete_snapshot(undo_ref["snapshot_id"])
        return Outcome(before=before, after={"snapshot_id": None}, undo_ref={})


ACTIONS: dict[str, Action] = {a.key: a for a in [
    DeactivateAccessKey(), QuarantinePrincipal(), RevokeSessions(),
    IsolateInstance(), ReEnableLogging(), SnapshotForensics(),
]}
