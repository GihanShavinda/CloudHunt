"""Auth flow: JWT login, RBAC enforcement, and the TOTP MFA gate."""

from __future__ import annotations

import pyotp
import pytest
from fastapi.testclient import TestClient

from cloudhunt.api.main import create_app
from cloudhunt.api.store import InMemoryUserStore, get_store, seed_demo_users


@pytest.fixture()
def client():
    """Fresh app + isolated seeded store per test (no cross-test state)."""
    store = InMemoryUserStore()
    seed_demo_users(store)
    app = create_app()
    app.dependency_overrides[get_store] = lambda: store
    yield TestClient(app), store
    app.dependency_overrides.clear()


def _login(c: TestClient, username: str, password: str) -> str:
    resp = c.post("/auth/login", data={"username": username, "password": password})
    assert resp.status_code == 200, resp.text
    return resp.json()["access_token"]


def test_health(client):
    c, _ = client
    assert c.get("/healthz").json()["status"] == "ok"


def test_login_and_me(client):
    c, _ = client
    token = _login(c, "analyst", "ChangeMe!Analyst1")
    me = c.get("/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert me.status_code == 200
    assert me.json() == {"username": "analyst", "role": "cloud_analyst", "mfa_enabled": True}


def test_bad_password_rejected(client):
    c, _ = client
    resp = c.post("/auth/login", data={"username": "analyst", "password": "wrong"})
    assert resp.status_code == 401


def test_rbac_viewer_cannot_register(client):
    c, _ = client
    token = _login(c, "viewer", "ChangeMe!Viewer1")
    resp = c.post(
        "/auth/register",
        headers={"Authorization": f"Bearer {token}"},
        json={"username": "x", "password": "y", "role": "viewer"},
    )
    assert resp.status_code == 403


def test_rbac_admin_can_register(client):
    c, _ = client
    token = _login(c, "admin", "ChangeMe!Admin1")
    resp = c.post(
        "/auth/register",
        headers={"Authorization": f"Bearer {token}"},
        json={"username": "newanalyst", "password": "pw", "role": "cloud_analyst"},
    )
    assert resp.status_code == 201
    assert resp.json()["username"] == "newanalyst"


def test_approval_requires_role(client):
    c, _ = client
    token = _login(c, "viewer", "ChangeMe!Viewer1")
    resp = c.post("/actions/act-1/approve", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 403  # viewer blocked before MFA is even considered


def test_approval_requires_totp(client):
    c, _ = client
    token = _login(c, "analyst", "ChangeMe!Analyst1")
    resp = c.post("/actions/act-1/approve", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 401  # role ok, but no TOTP code supplied


def test_approval_succeeds_with_valid_totp(client):
    c, store = client
    token = _login(c, "analyst", "ChangeMe!Analyst1")
    secret = store.get("analyst").totp_secret
    code = pyotp.TOTP(secret).now()
    resp = c.post(
        "/actions/act-1/approve",
        headers={"Authorization": f"Bearer {token}", "X-TOTP-Code": code},
    )
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["approved_by"] == "analyst"
    assert body["status"].startswith("approved")


def test_approval_rejects_wrong_totp(client):
    c, _ = client
    token = _login(c, "analyst", "ChangeMe!Analyst1")
    resp = c.post(
        "/actions/act-1/approve",
        headers={"Authorization": f"Bearer {token}", "X-TOTP-Code": "000000"},
    )
    assert resp.status_code == 401
