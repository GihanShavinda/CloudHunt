"""User persistence seam used by auth and administrator user management.

The current CloudHunt development build keeps platform users in memory.  The
interface deliberately exposes only the small set of operations needed by the
API so it can later be backed by PostgreSQL without changing route behaviour.
"""

from __future__ import annotations

from typing import Optional, Protocol

from cloudhunt.core.config import settings
from cloudhunt.core.security import generate_totp_secret, hash_password
from cloudhunt.models.user import Role, User


class UserStore(Protocol):
    def get(self, username: str) -> Optional[User]: ...
    def put(self, user: User) -> None: ...
    def list(self) -> list[User]: ...
    def delete(self, username: str) -> bool: ...
    def find_by_email(self, email: str) -> Optional[User]: ...


class InMemoryUserStore:
    def __init__(self) -> None:
        self._users: dict[str, User] = {}

    def get(self, username: str) -> Optional[User]:
        return self._users.get(username)

    def put(self, user: User) -> None:
        self._users[user.username] = user

    def list(self) -> list[User]:
        return sorted(self._users.values(), key=lambda user: user.username.lower())

    def delete(self, username: str) -> bool:
        return self._users.pop(username, None) is not None

    def find_by_email(self, email: str) -> Optional[User]:
        wanted = email.strip().lower()
        if not wanted:
            return None
        for user in self._users.values():
            if user.email and user.email.strip().lower() == wanted:
                return user
        return None


def seed_demo_users(store: UserStore) -> None:
    """Seed one account per role. DEV ONLY. Passwords are placeholders."""

    demo = [
        ("admin", "ChangeMe!Admin1", Role.administrator, True),
        ("analyst", "ChangeMe!Analyst1", Role.cloud_analyst, True),
        ("viewer", "ChangeMe!Viewer1", Role.viewer, False),
    ]
    for username, password, role, mfa in demo:
        if store.get(username) is not None:
            continue
        store.put(
            User(
                username=username,
                hashed_password=hash_password(password),
                role=role,
                totp_secret=generate_totp_secret() if mfa else None,
                mfa_enabled=mfa,
            )
        )


_store = InMemoryUserStore()
if settings.is_dev and settings.dev_seed_users:
    seed_demo_users(_store)


def get_store() -> UserStore:
    """FastAPI dependency seam — overridable in tests."""

    return _store
