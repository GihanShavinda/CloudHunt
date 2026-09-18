"""Request-scoped dependencies: authn, RBAC, and the MFA step-up gate.

Three composable dependencies:

* :func:`get_current_user` — decode the bearer JWT into a live ``User``.
* :func:`require_role` — RBAC; returns a dependency that 403s unless the caller
  holds one of the allowed roles.
* :func:`require_totp` — the MFA gate for approval endpoints. It demands a fresh
  TOTP code (header ``X-TOTP-Code``) verified against the user's secret. High-
  impact actions must re-assert possession of the second factor, not merely ride
  a login session.
"""

from __future__ import annotations

from typing import Iterable

import jwt
from fastapi import Depends, Header, HTTPException, status
from fastapi.security import OAuth2PasswordBearer

from cloudhunt.api.store import UserStore, get_store
from cloudhunt.core.security import decode_token, verify_totp
from cloudhunt.models.user import Role, User

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

_CREDENTIALS_EXC = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="Could not validate credentials",
    headers={"WWW-Authenticate": "Bearer"},
)


def get_current_user(
    token: str = Depends(oauth2_scheme),
    store: UserStore = Depends(get_store),
) -> User:
    try:
        payload = decode_token(token)
        username = payload.get("sub")
    except jwt.PyJWTError:
        raise _CREDENTIALS_EXC
    if not username:
        raise _CREDENTIALS_EXC
    user = store.get(username)
    if user is None or user.disabled:
        raise _CREDENTIALS_EXC
    return user


def require_role(*allowed: Role):
    allowed_set = set(allowed)

    def _dep(user: User = Depends(get_current_user)) -> User:
        if user.role not in allowed_set:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires one of roles: {sorted(r.value for r in allowed_set)}",
            )
        return user

    return _dep


def require_totp(
    user: User = Depends(get_current_user),
    x_totp_code: str | None = Header(default=None, alias="X-TOTP-Code"),
) -> User:
    """Enforce a valid second factor for this specific request."""
    if not user.mfa_enabled or not user.totp_secret:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="MFA must be enabled to perform approval actions",
        )
    if not x_totp_code or not verify_totp(user.totp_secret, x_totp_code):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Valid X-TOTP-Code header required for this action",
        )
    return user


def roles(*names: str) -> Iterable[Role]:  # small convenience for routers
    return [Role(n) for n in names]
