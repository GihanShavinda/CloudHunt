"""P12 end-to-end integration seam without browser/model/AWS dependencies."""
from __future__ import annotations

from cloudhunt.api.casestore import build_demo_service
from cloudhunt.assistant import summarize_bundle
from cloudhunt.respond import Approval
from cloudhunt.retrieval import CaseContextBuilder


def test_replay_to_case_summary_human_response_audit_frontend_payload():
    # build_demo_service replays normalised events through detect->correlate->blast->response.
    svc = build_demo_service()
    detail = svc.get_case("case-1")
    assert detail and detail["timeline"] and detail["chain"] and detail["blast"]["score"] > 0

    bundle = CaseContextBuilder(svc).build("case-1")
    summary = summarize_bundle(bundle, enabled=False)
    assert summary.source == "template" and summary.text

    rec = svc.approve(
        "case-1", "re-enable-logging",
        Approval("analyst", "cloud_analyst", True, channel="web"),
    )
    assert rec.status == "executed"
    refreshed = svc.get_case("case-1")
    assert any(r["action_key"] == "re-enable-logging" and r["status"] == "executed" for r in refreshed["audit"])
    assert not any(a["action_key"] == "re-enable-logging" and a["status"] == "pending" for a in refreshed["recommended_actions"])
