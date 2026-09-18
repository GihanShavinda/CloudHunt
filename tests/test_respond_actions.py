"""Reversibility + executor semantics — execute every action, then undo it, and
assert the world is exactly back to where it started."""

from __future__ import annotations

from cloudhunt.respond.catalogue import (
    ACTIONS,
    ActionTarget,
    QUARANTINE_POLICY,
)
from cloudhunt.respond.engine import ResponseEngine
from cloudhunt.respond.executor import FakeActionExecutor


def _seeded() -> FakeActionExecutor:
    ex = FakeActionExecutor()
    ex.add_user("ci-bot", {"AKIA0001": "Active", "AKIA0002": "Inactive"})
    ex.add_user("bob", {})
    ex.add_role("deploy")
    ex.add_instance("i-123", ["sg-app", "sg-web"])
    ex.add_trail("org-trail", False)
    return ex


# --- reversibility, action by action ---
def test_deactivate_access_key_reverses():
    ex = _seeded()
    a = ACTIONS["deactivate-access-key"]
    out = a.execute(ex, ActionTarget(user_name="ci-bot"))
    assert ex.users["ci-bot"]["keys"]["AKIA0001"] == "Inactive"   # active one disabled
    assert out.before == {"AKIA0001": "Active"}                   # only the active key touched
    a.undo(ex, out.undo_ref)
    assert ex.users["ci-bot"]["keys"]["AKIA0001"] == "Active"     # restored


def test_quarantine_role_reverses():
    ex = _seeded()
    a = ACTIONS["quarantine-principal"]
    out = a.execute(ex, ActionTarget(principal_arn="arn:aws:iam::1:role/deploy", role_name="deploy"))
    assert QUARANTINE_POLICY in ex.roles["deploy"]["inline"]
    a.undo(ex, out.undo_ref)
    assert QUARANTINE_POLICY not in ex.roles["deploy"]["inline"]


def test_quarantine_user_reverses():
    ex = _seeded()
    a = ACTIONS["quarantine-principal"]
    out = a.execute(ex, ActionTarget(principal_arn="arn:aws:iam::1:user/bob", user_name="bob"))
    assert QUARANTINE_POLICY in ex.users["bob"]["inline"]
    a.undo(ex, out.undo_ref)
    assert QUARANTINE_POLICY not in ex.users["bob"]["inline"]


def test_revoke_sessions_reverses():
    ex = _seeded()
    a = ACTIONS["revoke-sessions"]
    out = a.execute(ex, ActionTarget(role_name="deploy"))
    assert ex.roles["deploy"]["inline"]                          # a deny policy exists
    a.undo(ex, out.undo_ref)
    assert not ex.roles["deploy"]["inline"]


def test_isolate_instance_reverses():
    ex = _seeded()
    a = ACTIONS["isolate-instance"]
    out = a.execute(ex, ActionTarget(instance_id="i-123", quarantine_sg="sg-q"))
    assert ex.instances["i-123"] == ["sg-q"]
    a.undo(ex, out.undo_ref)
    assert ex.instances["i-123"] == ["sg-app", "sg-web"]         # original SGs restored


def test_re_enable_logging_reverses():
    ex = _seeded()
    a = ACTIONS["re-enable-logging"]
    out = a.execute(ex, ActionTarget(trail_name="org-trail"))
    assert ex.trails["org-trail"] is True
    a.undo(ex, out.undo_ref)
    assert ex.trails["org-trail"] is False                       # back to prior state


def test_snapshot_forensics_reverses():
    ex = _seeded()
    a = ACTIONS["snapshot-forensics"]
    out = a.execute(ex, ActionTarget(volume_id="vol-1"))
    sid = out.after["snapshot_id"]
    assert sid in ex.snapshots
    a.undo(ex, out.undo_ref)
    assert sid not in ex.snapshots


def test_every_action_produces_before_after_and_undo_ref():
    """Contract check: no action may execute without an undo_ref (except none)."""
    checks = {
        "deactivate-access-key": ActionTarget(user_name="ci-bot"),
        "quarantine-principal": ActionTarget(role_name="deploy",
                                             principal_arn="arn:aws:iam::1:role/deploy"),
        "revoke-sessions": ActionTarget(role_name="deploy"),
        "isolate-instance": ActionTarget(instance_id="i-123"),
        "re-enable-logging": ActionTarget(trail_name="org-trail"),
        "snapshot-forensics": ActionTarget(volume_id="vol-1"),
    }
    for key, target in checks.items():
        ex = _seeded()
        out = ACTIONS[key].execute(ex, target)
        assert out.undo_ref, f"{key} produced no undo_ref"
        assert out.before is not None and out.after is not None


# --- audit capture through the engine ---
def test_engine_execution_is_audited_with_state_and_undo():
    from cloudhunt.respond.decision import ProposedAction, DecisionMode
    ex = _seeded()
    eng = ResponseEngine(ex)
    pa = ProposedAction("deactivate-access-key", ActionTarget(user_name="ci-bot"))
    rec = eng._execute(pa, DecisionMode.auto, approver=None, case_id="case-1",
                       reason="test")
    assert rec.status == "executed" and rec.decision == "auto"
    assert rec.before == {"AKIA0001": "Active"} and rec.after == {"AKIA0001": "Inactive"}
    assert rec.undo_ref and rec.case_id == "case-1"
    assert eng.audit.records()[-1].record_id == rec.record_id


def test_in_memory_audit_is_append_only():
    from cloudhunt.respond.audit import AuditRecord, InMemoryAuditLog
    log = InMemoryAuditLog()
    log.append(AuditRecord(action_key="x", decision="auto", status="executed"))
    snapshot = log.records()
    snapshot.clear()                       # mutating the returned copy...
    assert len(log.records()) == 1         # ...does not affect the log
