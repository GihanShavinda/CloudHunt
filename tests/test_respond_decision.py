"""Safety proofs for the decision engine.

The central guarantee: an irreversible, org-wide, or otherwise-dangerous action
can never auto-execute — not through the decision engine, and not even if forced
past it. Plus: human approval requires MFA, and exactly one catalogue action is
auto-eligible.
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from cloudhunt.correlate.chain import AttackChain, ChainStep
from cloudhunt.respond.catalogue import (
    ACTIONS,
    Action,
    ActionTarget,
    Impact,
    Outcome,
    Scope,
)
from cloudhunt.respond.decision import (
    DecisionMode,
    DecisionPolicy,
    ProposedAction,
    decide,
    is_auto_eligible,
)
from cloudhunt.respond.engine import (
    Approval,
    ApprovalError,
    ResponseEngine,
    ResponseSafetyError,
)
from cloudhunt.respond.executor import FakeActionExecutor

IDEAL = dict(confidence=1.0, blast=0.0, resource_sensitivity="low")


# --- exactly one action is auto-eligible ---
def test_only_deactivate_access_key_is_auto_eligible():
    for key, action in ACTIONS.items():
        assert is_auto_eligible(action) == (key == "deactivate-access-key")


def test_ideal_conditions_auto_only_for_deactivate_key():
    for key, action in ACTIONS.items():
        d = decide(action, **IDEAL)
        expected = DecisionMode.auto if key == "deactivate-access-key" else DecisionMode.human
        assert d.mode == expected, f"{key} decided {d.mode}"


# --- irreversible can never auto (metadata gate) ---
class _Irreversible(Action):
    key = "irreversible-test"
    impact = Impact.low            # deliberately "safe-looking" on every other axis
    scope = Scope.principal
    reversible = False
    always_human = False

    def execute(self, ex, t):
        return Outcome(before={}, after={}, undo_ref={})


def test_irreversible_action_never_auto_eligible():
    a = _Irreversible()
    assert is_auto_eligible(a) is False
    assert decide(a, **IDEAL).mode == DecisionMode.human


# --- org-wide / always-human can never auto ---
def test_org_wide_action_never_auto():
    d = decide(ACTIONS["re-enable-logging"], **IDEAL)          # scope == account
    assert d.mode == DecisionMode.human
    assert any("single-principal" in r or "always requires" in r for r in d.reasons)


@pytest.mark.parametrize("key", ["quarantine-principal", "isolate-instance",
                                 "re-enable-logging", "revoke-sessions", "snapshot-forensics"])
def test_non_auto_actions_stay_human_under_ideal_conditions(key):
    assert decide(ACTIONS[key], **IDEAL).mode == DecisionMode.human


# --- dynamic gates on the one auto action ---
def test_low_confidence_downgrades_to_human():
    d = decide(ACTIONS["deactivate-access-key"], confidence=0.5, blast=90,
               resource_sensitivity="low")
    assert d.mode == DecisionMode.human


def test_high_sensitivity_blocks_auto():
    d = decide(ACTIONS["deactivate-access-key"], confidence=1.0, blast=10,
               resource_sensitivity="high")
    assert d.mode == DecisionMode.human


# --- the hard engine invariant: forcing an auto-exec of a human action fails ---
def test_engine_refuses_forced_auto_of_human_action():
    eng = ResponseEngine(FakeActionExecutor())
    pa = ProposedAction("quarantine-principal",
                        ActionTarget(role_name="deploy",
                                     principal_arn="arn:aws:iam::1:role/deploy"))
    with pytest.raises(ResponseSafetyError):
        eng._execute(pa, DecisionMode.auto, approver=None, case_id="c", reason="forced")


# --- human approval requires MFA + an authorised role ---
def _pending_quarantine_engine():
    ex = FakeActionExecutor(); ex.add_role("deploy")
    eng = ResponseEngine(ex)
    from cloudhunt.respond.engine import PlanItem
    from cloudhunt.respond.decision import decide as _decide
    pa = ProposedAction("quarantine-principal",
                        ActionTarget(role_name="deploy",
                                     principal_arn="arn:aws:iam::1:role/deploy"))
    item = PlanItem(pa, _decide(ACTIONS["quarantine-principal"], **IDEAL))
    return eng, ex, item


def test_approval_requires_mfa():
    eng, ex, item = _pending_quarantine_engine()
    with pytest.raises(ApprovalError):
        eng.approve(item, Approval("alice", "administrator", mfa_verified=False))


def test_approval_requires_authorised_role():
    eng, ex, item = _pending_quarantine_engine()
    with pytest.raises(ApprovalError):
        eng.approve(item, Approval("vic", "viewer", mfa_verified=True))


def test_approval_with_mfa_executes_and_audits():
    eng, ex, item = _pending_quarantine_engine()
    rec = eng.approve(item, Approval("alice", "administrator", mfa_verified=True), "case-9")
    assert rec.decision == "human" and rec.status == "executed"
    assert rec.approver == "alice"
    assert "CloudHuntQuarantine" in ex.roles["deploy"]["inline"]


# --- run(): only the eligible action auto-executes; rest pend ---
def _stub_case():
    steps = [
        ChainStep(1, None, "arn:aws:iam::1:user/ci-bot", "arn:aws:iam::1:user/ci-bot",
                  "AssumeRole", "T1548"),
        ChainStep(2, None, "arn:aws:iam::1:role/deploy", "sess",
                  "CreatePolicyVersion", "T1098.003"),
        ChainStep(3, None, "arn:aws:iam::1:role/deploy", "sess",
                  "StopLogging", "T1562.008",
                  target="arn:aws:cloudtrail:us-east-1:1:trail/org-trail"),
    ]
    chain = AttackChain(case_id="case-1", steps=steps)
    return SimpleNamespace(case_id="case-1", chain=chain,
                           detection_confidence=0.99, blast=SimpleNamespace(score=46.0))


def test_run_auto_executes_only_eligible_action():
    ex = FakeActionExecutor()
    ex.add_user("ci-bot", {"AKIA1": "Active"})
    ex.add_role("deploy"); ex.add_trail("org-trail", False)
    eng = ResponseEngine(ex)
    plan = eng.run(_stub_case())

    executed = {r.action_key for r in plan.executed}
    pending = {i.proposed.action_key for i in plan.pending}
    assert executed == {"deactivate-access-key"}
    assert {"quarantine-principal", "re-enable-logging"} <= pending
    # the auto action actually happened; the human ones did not
    assert ex.users["ci-bot"]["keys"]["AKIA1"] == "Inactive"
    assert ex.trails["org-trail"] is False
    assert ex.roles["deploy"]["inline"] == {}
