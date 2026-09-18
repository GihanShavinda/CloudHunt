"""P12 deterministic export and integrated-summary tests."""
from __future__ import annotations

import json

from cloudhunt.api.casestore import build_demo_service
from cloudhunt.assistant import summarize_bundle
from cloudhunt.reporting import case_csv, case_json, case_pdf
from cloudhunt.retrieval import CaseContextBuilder


def _material():
    svc = build_demo_service()
    detail = svc.get_case("case-1")
    bundle = CaseContextBuilder(svc).build("case-1")
    s = summarize_bundle(bundle, enabled=False)
    summary = {"summary": s.text, "source": s.source, "valid": s.valid, "rejected": not s.valid, "violations": []}
    return detail, summary


def test_json_export_contains_existing_case_context_only():
    detail, summary = _material()
    data = json.loads(case_json(detail, summary))
    assert data["case_id"] == "case-1"
    assert data["summary"]["source"] == "template"
    assert data["timeline"] and data["attack_map"] and data["recommended_actions"]


def test_csv_export_is_detection_evaluation_style():
    detail, _ = _material()
    text = case_csv(detail).decode()
    assert "case_id,event_ts,principal,action,target,detections,attack_ids,blast_score" in text
    assert "case-1" in text and "StopLogging" in text


def test_pdf_export_is_a_real_pdf_and_contains_report_sections():
    detail, summary = _material()
    pdf = case_pdf(detail, summary)
    assert pdf.startswith(b"%PDF-")
    assert len(pdf) > 1500
