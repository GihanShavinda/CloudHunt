"""Cryptographic primitives for platform auth.

Three concerns, kept in one small module so the auth routes stay declarative:

* Passwords  -> bcrypt (salted, slow-by-design).
* Sessions   -> short-lived JWTs signed with HS256.
* Step-up    -> TOTP (RFC 6238) for the MFA gate on approval endpoints.

Nothing here reaches into request/response objects; it is pure so it is trivial
to unit test.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import bcrypt
import jwt
import pyotp

from cloudhunt.core.config import settings


# --------------------------------------------------------------------------- #
# Passwords
# --------------------------------------------------------------------------- #
def hash_password(plain: str) -> str:
    return bcrypt.hashpw(plain.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plain.encode("utf-8"), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False


# --------------------------------------------------------------------------- #
# JWT access tokens
# --------------------------------------------------------------------------- #
def create_access_token(subject: str, role: str, extra: Optional[dict[str, Any]] = None) -> str:
    now = datetime.now(timezone.utc)
    payload: dict[str, Any] = {
        "sub": subject,
        "role": role,
        "iat": now,
        "exp": now + timedelta(minutes=settings.access_token_minutes),
    }
    if extra:
        payload.update(extra)
    return jwt.encode(payload, settings.jwt_secret, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> dict[str, Any]:
    """Raises ``jwt.PyJWTError`` on any problem (expired, bad signature, ...)."""
    return jwt.decode(token, settings.jwt_secret, algorithms=[settings.jwt_algorithm])


# --------------------------------------------------------------------------- #
# TOTP (MFA step-up)
# --------------------------------------------------------------------------- #
def generate_totp_secret() -> str:
    return pyotp.random_base32()


def totp_provisioning_uri(secret: str, username: str, issuer: str = "CloudHunt") -> str:
    """otpauth:// URI for an authenticator-app QR code."""
    return pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name=issuer)


def verify_totp(secret: str, code: str, *, valid_window: int = 1) -> bool:
    """``valid_window=1`` tolerates one 30s step of clock skew each way."""
    if not secret or not code:
        return False
    return pyotp.TOTP(secret).verify(code.strip(), valid_window=valid_window)
