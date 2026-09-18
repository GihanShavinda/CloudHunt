"""M11 mobile approval: safety parity, scoped tokens, push privacy and audit."""
from __future__ import annotations

from types import SimpleNamespace

import pytest

from cloudhunt.api.casestore import CaseService
from cloudhunt.correlate.chain import AttackChain, ChainStep
from cloudhunt.mobile import ApprovalTokenError, ApprovalTokenStore, DeviceRegistry, InMemoryPushGateway, PushService
from cloudhunt.respond import Approval, FakeActionExecutor, InMemoryAuditLog, ResponseEngine


def _case():
    steps = [
        ChainStep(1, None, "arn:aws:iam::1:user/ci-bot", "arn:aws:iam::1:user/ci-bot", "AssumeRole", "T1548"),
        ChainStep(2, None, "arn:aws:iam::1:role/deploy", "sess", "CreatePolicyVersion", "T1098.003"),
        ChainStep(3, None, "arn:aws:iam::1:role/deploy", "sess", "StopLogging", "T1562.008",
                  target="arn:aws:cloudtrail:us-east-1:1:trail/org-trail"),
    ]
    return SimpleNamespace(case_id="case-mobile", chain=AttackChain(case_id="case-mobile", steps=steps),
                           detection_confidence=0.99, blast=SimpleNamespace(score=46.0))


def _service(ttl=300):
    ex = FakeActionExecutor()
    ex.add_user("ci-bot", {"AKIA1": "Active"})
    ex.add_role("deploy")
    ex.add_trail("org-trail", False)
    gateway = InMemoryPushGateway()
    push = PushService(DeviceRegistry(), gateway)
    svc = CaseService(ResponseEngine(ex, InMemoryAuditLog()), ex,
                      push_service=push, approval_tokens=ApprovalTokenStore(ttl))
    return svc, ex, gateway


def _mobile_approval():
    return Approval("analyst", "cloud_analyst", True, channel="mobile")


def test_push_only_for_human_items_and_payload_has_case_reference_only():
    svc, ex, gateway = _service()
    svc.push.registry.register("analyst", "opaque-device-token", "android")
    plan = svc.add_case(_case(), [])
    assert {r.action_key for r in plan.executed} == {"deactivate-access-key"}
    assert len(gateway.sent) == len(plan.pending)
    assert gateway.sent
    for _device_id, payload in gateway.sent:
        assert payload == {"type": "approval_required", "case_id": "case-mobile"}
        assert "arn:" not in repr(payload) and "target" not in payload and "evidence" not in payload


def test_mobile_token_is_single_use_and_action_scoped():
    store = ApprovalTokenStore()
    token, rec = store.issue("c1", "a1", "quarantine-principal")
    with pytest.raises(ApprovalTokenError, match="scope mismatch"):
        store.consume(token, "c1", "a2", "quarantine-principal")
    store.consume(token, "c1", "a1", "quarantine-principal")
    with pytest.raises(ApprovalTokenError, match="already used"):
        store.consume(token, "c1", "a1", "quarantine-principal")


def test_mobile_approval_executes_through_existing_engine_and_audits_channel():
    svc, ex, _ = _service()
    svc.add_case(_case(), [])
    issued = svc.issue_approval_token("case-mobile", "re-enable-logging")
    rec = svc.approve("case-mobile", "re-enable-logging", _mobile_approval(), token=issued["token"])
    assert rec.status == "executed" and rec.decision == "human"
    assert rec.channel == "mobile" and rec.approval_decision == "approve"
    assert rec.approver == "analyst" and rec.ts
    assert ex.trails["org-trail"] is True


def test_denial_is_single_use_audited_and_does_not_execute():
    svc, ex, _ = _service()
    svc.add_case(_case(), [])
    issued = svc.issue_approval_token("case-mobile", "re-enable-logging")
    rec = svc.deny("case-mobile", "re-enable-logging", _mobile_approval(), token=issued["token"])
    assert rec.status == "denied" and rec.approval_decision == "deny"
    assert rec.channel == "mobile" and rec.approver == "analyst" and rec.ts
    assert ex.trails["org-trail"] is False
    with pytest.raises(KeyError):
        svc.approve("case-mobile", "re-enable-logging", _mobile_approval(), token=issued["token"])


def test_expired_token_fails_closed_and_expiry_is_audited():
    svc, ex, _ = _service(ttl=-1)
    svc.add_case(_case(), [])
    issued = svc.issue_approval_token("case-mobile", "re-enable-logging")
    with pytest.raises(ApprovalTokenError, match="expired"):
        svc.approve("case-mobile", "re-enable-logging", _mobile_approval(), token=issued["token"])
    assert ex.trails["org-trail"] is False
    assert any(r.status == "expired" and r.channel == "mobile" and
               r.approval_decision == "expired" for r in svc.engine.audit.records())
    # fail closed: the action remains pending for a fresh approval attempt
    assert any(i.proposed.action_key == "re-enable-logging"
               for i in svc.entries["case-mobile"].plan.pending)


def test_device_revocation_stops_future_pushes():
    svc, _ex, gateway = _service()
    d = svc.push.registry.register("analyst", "opaque-device-token", "ios")
    assert svc.push.registry.revoke(d.device_id, "analyst") is True
    svc.add_case(_case(), [])
    assert gateway.sent == []
