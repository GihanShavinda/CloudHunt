"""The response engine — turn a case into audited, reversible action.

    engine = ResponseEngine(executor, audit_log)
    plan = engine.run(case)          # auto actions execute; the rest wait
    engine.approve(item, Approval("alice", "administrator", mfa_verified=True))
    engine.undo(record, actor="alice")

Auto actions execute immediately; everything else lands in ``plan.pending`` for a
human. Human approval requires a fresh MFA second factor (the FastAPI endpoint
supplies ``mfa_verified`` only after validating TOTP). Every execution — auto,
approved, or undo — writes a before/after/undo_ref record to the append-only log.

A hard invariant guards the auto path: :meth:`_execute` refuses to auto-run any
action that is not :func:`is_auto_eligible`, raising :class:`ResponseSafetyError`.
So even a bug in the decision engine cannot cause an irreversible or org-wide
action to auto-execute.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
import uuid
from typing import Optional

from cloudhunt.respond.audit import AuditLog, AuditRecord, InMemoryAuditLog
from cloudhunt.respond.catalogue import ACTIONS, Action, ActionTarget
from cloudhunt.respond.decision import (
    Decision,
    DecisionMode,
    DecisionPolicy,
    ProposedAction,
    decide,
    is_auto_eligible,
    propose_actions,
)
from cloudhunt.respond.executor import ActionExecutor

_APPROVER_ROLES = {"administrator", "cloud_analyst"}


class ResponseSafetyError(Exception):
    """Raised if something tries to auto-execute a non-auto-eligible action."""


class ApprovalError(Exception):
    """Raised when a human approval is missing MFA or an authorised role."""


@dataclass
class Approval:
    approver: str
    role: str
    mfa_verified: bool
    channel: str = "web"


@dataclass
class PlanItem:
    proposed: ProposedAction
    decision: Decision
    action_id: str = field(default_factory=lambda: uuid.uuid4().hex)


@dataclass
class ResponsePlan:
    case_id: str
    items: list[PlanItem] = field(default_factory=list)
    executed: list[AuditRecord] = field(default_factory=list)
    pending: list[PlanItem] = field(default_factory=list)


class ResponseEngine:
    def __init__(self, executor: ActionExecutor, audit_log: Optional[AuditLog] = None,
                 policy: Optional[DecisionPolicy] = None):
        self.executor = executor
        self.audit = audit_log or InMemoryAuditLog()
        self.policy = policy or DecisionPolicy()

    # -- planning --
    def plan(self, case) -> list[PlanItem]:
        items = []
        for pa in propose_actions(case):
            action = ACTIONS[pa.action_key]
            d = decide(action, case.detection_confidence, case.blast.score,
                       pa.resource_sensitivity, self.policy)
            items.append(PlanItem(proposed=pa, decision=d))
        return items

    def run(self, case) -> ResponsePlan:
        plan = ResponsePlan(case_id=case.case_id, items=self.plan(case))
        for item in plan.items:
            if item.decision.mode == DecisionMode.auto:
                rec = self._execute(item.proposed, DecisionMode.auto,
                                    approver=None, case_id=case.case_id,
                                    reason="auto: " + "; ".join(item.decision.reasons))
                plan.executed.append(rec)
            else:
                plan.pending.append(item)
        return plan

    # -- human approval --
    @staticmethod
    def validate_approval(approval: Approval) -> None:
        if not approval.mfa_verified:
            raise ApprovalError("human approval requires a verified MFA second factor")
        if approval.role not in _APPROVER_ROLES:
            raise ApprovalError(f"role {approval.role!r} may not approve actions")

    def approve(self, item: PlanItem, approval: Approval, case_id: str = "") -> AuditRecord:
        self.validate_approval(approval)
        return self._execute(item.proposed, DecisionMode.human,
                             approver=approval.approver, case_id=case_id,
                             reason=f"approved by {approval.approver} ({approval.role})",
                             channel=approval.channel, approval_decision="approve")

    # -- undo (reversibility, itself audited) --
    def undo(self, record: AuditRecord, actor: str) -> AuditRecord:
        action = ACTIONS[record.action_key]
        outcome = action.undo(self.executor, record.undo_ref)
        rec = AuditRecord(
            action_key=record.action_key, decision="human", status="undone",
            target=record.target, before=outcome.before, after=outcome.after,
            undo_ref={}, approver=actor, case_id=record.case_id,
            reason=f"undo of {record.record_id}", parent_id=record.record_id)
        return self.audit.append(rec)

    # -- the one place actions execute --
    def _execute(self, pa: ProposedAction, mode: DecisionMode,
                 approver: Optional[str], case_id: str, reason: str,
                 channel: str = "system", approval_decision: Optional[str] = None) -> AuditRecord:
        action: Action = ACTIONS[pa.action_key]
        # HARD SAFETY INVARIANT — independent of the decision engine.
        if mode == DecisionMode.auto and not is_auto_eligible(action):
            raise ResponseSafetyError(
                f"refusing to auto-execute non-auto-eligible action {action.key!r}")
        try:
            outcome = action.execute(self.executor, pa.target)
        except Exception as exc:  # record the failure, then re-raise
            self.audit.append(AuditRecord(
                action_key=action.key, decision=mode.value, status="failed",
                target=asdict(pa.target), approver=approver, case_id=case_id,
                reason=f"{reason} | error: {exc}", channel=channel,
                approval_decision=approval_decision))
            raise
        rec = AuditRecord(
            action_key=action.key, decision=mode.value, status="executed",
            target=asdict(pa.target), before=outcome.before, after=outcome.after,
            undo_ref=outcome.undo_ref, approver=approver, case_id=case_id, reason=reason,
            channel=channel, approval_decision=approval_decision)
        return self.audit.append(rec)
