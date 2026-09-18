"""Reversible response + decision engine + audit (Milestone 6 / P6).

    ACTIONS, Action, ActionTarget      the scoped, reversible action catalogue
    ActionExecutor, Boto3ActionExecutor, FakeActionExecutor   the only AWS surface
    decide, is_auto_eligible, DecisionPolicy, propose_actions  Auto-vs-Human engine
    ResponseEngine, ResponsePlan, Approval                    orchestration
    AuditRecord, InMemoryAuditLog, JsonlAuditLog              append-only audit

Safety contract: only reversible + low-impact + single-principal + high-confidence
actions may auto-run; a hard invariant in ResponseEngine makes auto-execution of
anything else impossible, and every action is reversible + audited.
"""

from cloudhunt.respond.audit import (
    AuditLog,
    AuditRecord,
    InMemoryAuditLog,
    JsonlAuditLog,
)
from cloudhunt.respond.catalogue import (
    ACTIONS,
    Action,
    ActionTarget,
    Impact,
    Outcome,
    Scope,
)
from cloudhunt.respond.decision import (
    Decision,
    DecisionMode,
    DecisionPolicy,
    ProposedAction,
    decide,
    is_auto_eligible,
    propose_actions,
)
from cloudhunt.respond.engine import (
    Approval,
    ApprovalError,
    PlanItem,
    ResponseEngine,
    ResponsePlan,
    ResponseSafetyError,
)
from cloudhunt.respond.executor import (
    ActionExecutor,
    Boto3ActionExecutor,
    FakeActionExecutor,
)

__all__ = [
    "ACTIONS", "Action", "ActionTarget", "Impact", "Scope", "Outcome",
    "ActionExecutor", "Boto3ActionExecutor", "FakeActionExecutor",
    "decide", "is_auto_eligible", "DecisionPolicy", "Decision", "DecisionMode",
    "ProposedAction", "propose_actions",
    "ResponseEngine", "ResponsePlan", "PlanItem", "Approval",
    "ResponseSafetyError", "ApprovalError",
    "AuditRecord", "AuditLog", "InMemoryAuditLog", "JsonlAuditLog",
]
