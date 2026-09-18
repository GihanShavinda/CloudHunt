"""Platform operator identity models.

These accounts are CloudHunt users (administrators, analysts and viewers), not
AWS IAM principals.  Public/self-service projections intentionally exclude
password hashes and TOTP secrets.
"""

from __future__ import annotations

from enum import Enum
from typing import Optional

from pydantic import BaseModel


class Role(str, Enum):
    """RBAC roles from the CloudHunt specification (FR-3)."""

    administrator = "administrator"
    cloud_analyst = "cloud_analyst"
    viewer = "viewer"


class User(BaseModel):
    """A CloudHunt platform operator."""

    username: str
    hashed_password: str
    role: Role
    email: Optional[str] = None
    totp_secret: Optional[str] = None
    mfa_enabled: bool = False
    disabled: bool = False


class UserPublic(BaseModel):
    """Safe projection used by existing auth/profile endpoints.

    Keep this shape stable so existing frontend code and tests are not broken.
    """

    username: str
    role: Role
    mfa_enabled: bool

    @classmethod
    def of(cls, u: User) -> "UserPublic":
        return cls(username=u.username, role=u.role, mfa_enabled=u.mfa_enabled)


class UserAdminPublic(BaseModel):
    """Administrator-facing account projection for the user-management page."""

    username: str
    email: Optional[str] = None
    role: Role
    mfa_enabled: bool
    disabled: bool

    @classmethod
    def of(cls, u: User) -> "UserAdminPublic":
        return cls(
            username=u.username,
            email=u.email,
            role=u.role,
            mfa_enabled=u.mfa_enabled,
            disabled=u.disabled,
        )
