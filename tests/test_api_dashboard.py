"""M7 API tests — dashboard, case detail, MFA-gated approval, live feed."""

from __future__ import annotations

import pyotp
import pytest
from fastapi.testclient import TestClient

from cloudhunt.api.casestore import build_demo_service, get_case_service
from cloudhunt.api.deps import get_store
from cloudhunt.api.main import create_app


@pytest.fixture()
def client():
    app = create_app()
    service = build_demo_service()                 # isolated per test
    app.dependency_overrides[get_case_service] = lambda: service
    return TestClient(app)


def _login(client, username, password):
    r = client.post("/auth/login", data={"username": username, "password": password})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


def _totp_header(username="analyst"):
    secret = get_store().get(username).totp_secret
    return {"X-TOTP-Code": pyotp.TOTP(secret).now()}


# --- reads require auth ---
def test_list_cases_requires_auth(client):
    assert client.get("/cases").status_code == 401


def test_list_cases_returns_ranked(client):
    h = _login(client, "viewer", "ChangeMe!Viewer1")
    cases = client.get("/cases", headers=h).json()["cases"]
    assert cases and cases[0]["case_id"] == "case-1"
    assert cases[0]["blast"] > 0 and cases[0]["pending_actions"] >= 1


def test_dashboard_summary(client):
    h = _login(client, "viewer", "ChangeMe!Viewer1")
    d = client.get("/dashboard/summary", headers=h).json()
    assert d["logging_health"]["healthy"] is False          # attacker stopped the trail
    assert d["sensitive_resource_exposure"]                  # crown jewels reachable
    assert d["cases_by_blast"][0]["blast"] > 0


def test_case_detail_has_workspace_payloads(client):
    h = _login(client, "viewer", "ChangeMe!Viewer1")
    d = client.get("/cases/case-1", headers=h).json()
    assert [s["action"] for s in d["chain"]][:2] == ["ListBuckets", "AssumeRole"]
    assert d["graph"]["nodes"] and d["graph"]["edges"]
    assert d["attack_map"] and d["recommended_actions"]


# --- approval flow (RBAC + MFA) ---
def test_approve_requires_mfa(client):
    h = _login(client, "analyst", "ChangeMe!Analyst1")
    r = client.post("/cases/case-1/actions/re-enable-logging/approve", headers=h)
    assert r.status_code == 401                              # no X-TOTP-Code


def test_viewer_cannot_approve(client):
    h = _login(client, "viewer", "ChangeMe!Viewer1")
    r = client.post("/cases/case-1/actions/re-enable-logging/approve", headers=h)
    assert r.status_code == 403


def test_analyst_approves_re_enable_logging_and_health_recovers(client):
    h = {**_login(client, "analyst", "ChangeMe!Analyst1"), **_totp_header("analyst")}
    r = client.post("/cases/case-1/actions/re-enable-logging/approve", headers=h)
    assert r.status_code == 200 and r.json()["status"] == "executed"
    # logging health recovers after the approved re-enable
    d = client.get("/dashboard/summary", headers=h).json()
    assert d["logging_health"]["healthy"] is True
    # the audit trail now shows a human-approved action
    detail = client.get("/cases/case-1", headers=h).json()
    assert any(a["decision"] == "human" and a["status"] == "executed"
               for a in detail["audit"])


def test_approve_unknown_action_404(client):
    h = {**_login(client, "analyst", "ChangeMe!Analyst1"), **_totp_header("analyst")}
    r = client.post("/cases/case-1/actions/nope/approve", headers=h)
    assert r.status_code == 404


# --- live feed ---
def test_ws_feed_sends_snapshot(client):
    with client.websocket_connect("/ws/cases") as ws:
        msg = ws.receive_json()
    assert msg["type"] == "snapshot"
    assert msg["cases"][0]["case_id"] == "case-1"