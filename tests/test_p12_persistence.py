"""Persistence integration contract using a test adapter; Postgres remains opt-in."""
from __future__ import annotations

from cloudhunt.api.casestore import build_demo_service


def test_default_dev_service_stays_in_memory_and_operational():
    svc = build_demo_service()
    assert svc.operational_store is None
    assert svc.get_case("case-1")["case_id"] == "case-1"
