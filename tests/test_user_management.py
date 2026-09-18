"""Public signup and administrator user-management tests."""

from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from cloudhunt.api.main import create_app
from cloudhunt.api.store import InMemoryUserStore, get_store, seed_demo_users


@pytest.fixture()
def client():
    store = InMemoryUserStore()
    seed_demo_users(store)
    app = create_app()
    app.dependency_overrides[get_store] = lambda: store
    yield TestClient(app), store
    app.dependency_overrides.clear()


def _login(c: TestClient, username: str, password: str) -> str:
    response = c.post('/auth/login', data={'username': username, 'password': password})
    assert response.status_code == 200, response.text
    return response.json()['access_token']


def _auth(token: str) -> dict[str, str]:
    return {'Authorization': f'Bearer {token}'}


def test_public_signup_creates_viewer(client):
    c, store = client
    response = c.post('/auth/signup', json={
        'username': 'new.viewer',
        'email': 'viewer@example.com',
        'password': 'StrongPassword123!',
    })
    assert response.status_code == 201, response.text
    assert response.json()['role'] == 'viewer'
    assert store.get('new.viewer').role.value == 'viewer'


def test_public_signup_rejects_duplicate_email(client):
    c, _ = client
    payload = {
        'username': 'viewer.one',
        'email': 'same@example.com',
        'password': 'StrongPassword123!',
    }
    assert c.post('/auth/signup', json=payload).status_code == 201
    payload['username'] = 'viewer.two'
    assert c.post('/auth/signup', json=payload).status_code == 409


def test_viewer_cannot_list_users(client):
    c, _ = client
    token = _login(c, 'viewer', 'ChangeMe!Viewer1')
    assert c.get('/users', headers=_auth(token)).status_code == 403


def test_admin_can_create_update_and_delete_user(client):
    c, _ = client
    token = _login(c, 'admin', 'ChangeMe!Admin1')

    created = c.post('/users', headers=_auth(token), json={
        'username': 'managed.user',
        'email': 'managed@example.com',
        'password': 'TemporaryPass123!',
        'role': 'viewer',
    })
    assert created.status_code == 201, created.text

    updated = c.patch('/users/managed.user', headers=_auth(token), json={
        'role': 'cloud_analyst',
        'disabled': True,
    })
    assert updated.status_code == 200, updated.text
    assert updated.json()['role'] == 'cloud_analyst'
    assert updated.json()['disabled'] is True

    deleted = c.delete('/users/managed.user', headers=_auth(token))
    assert deleted.status_code == 200, deleted.text


def test_admin_cannot_delete_self(client):
    c, _ = client
    token = _login(c, 'admin', 'ChangeMe!Admin1')
    response = c.delete('/users/admin', headers=_auth(token))
    assert response.status_code == 409


def test_disabled_user_cannot_login(client):
    c, _ = client
    token = _login(c, 'admin', 'ChangeMe!Admin1')
    create = c.post('/users', headers=_auth(token), json={
        'username': 'disabled.user',
        'email': 'disabled@example.com',
        'password': 'TemporaryPass123!',
        'role': 'viewer',
        'disabled': True,
    })
    assert create.status_code == 201
    login = c.post('/auth/login', data={
        'username': 'disabled.user',
        'password': 'TemporaryPass123!',
    })
    assert login.status_code == 401


def test_reset_mfa(client):
    c, _ = client
    token = _login(c, 'admin', 'ChangeMe!Admin1')
    response = c.post('/users/analyst/reset-mfa', headers=_auth(token))
    assert response.status_code == 200, response.text
    assert response.json()['mfa_enabled'] is False
