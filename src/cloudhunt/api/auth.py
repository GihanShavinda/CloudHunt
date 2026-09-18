"""Authentication, self-service signup and MFA routes."""

from __future__ import annotations

import re

from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.security import OAuth2PasswordRequestForm
from pydantic import BaseModel

from cloudhunt.api.deps import get_current_user, require_role
from cloudhunt.api.store import UserStore, get_store
from cloudhunt.core.security import (
    create_access_token,
    generate_totp_secret,
    hash_password,
    totp_provisioning_uri,
    verify_password,
    verify_totp,
)
from cloudhunt.models.user import Role, User, UserPublic

router = APIRouter(prefix="/auth", tags=["auth"])

_EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
_USERNAME_RE = re.compile(r"^[A-Za-z0-9._-]{3,64}$")


class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"


class RegisterRequest(BaseModel):
    """Legacy administrator provisioning request kept for compatibility."""

    username: str
    password: str
    role: Role


class SignupRequest(BaseModel):
    username: str
    email: str
    password: str


class MfaSetupResponse(BaseModel):
    secret: str
    provisioning_uri: str


class MfaEnableRequest(BaseModel):
    code: str


def _validate_public_identity(username: str, email: str, password: str) -> tuple[str, str]:
    username = username.strip()
    email = email.strip().lower()

    if not _USERNAME_RE.fullmatch(username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username must be 3-64 characters and use only letters, numbers, dot, underscore or hyphen",
        )
    if not _EMAIL_RE.fullmatch(email):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Valid email address required")
    if len(password) < 12:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Password must be at least 12 characters",
        )
    return username, email


@router.post("/login", response_model=Token)
def login(
    form: OAuth2PasswordRequestForm = Depends(),
    store: UserStore = Depends(get_store),
) -> Token:
    user = store.get(form.username)
    if user is None or user.disabled or not verify_password(form.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Bad credentials")
    token = create_access_token(user.username, user.role.value, {"mfa": user.mfa_enabled})
    return Token(access_token=token)


@router.get("/me", response_model=UserPublic)
def me(user: User = Depends(get_current_user)) -> UserPublic:
    return UserPublic.of(user)


@router.post("/signup", response_model=UserPublic, status_code=status.HTTP_201_CREATED)
def signup(req: SignupRequest, store: UserStore = Depends(get_store)) -> UserPublic:
    """Public self-service registration.

    Security invariant: public registration ALWAYS creates a Viewer account.
    Role promotion is only available through the administrator-only /users API.
    """

    username, email = _validate_public_identity(req.username, req.email, req.password)

    if store.get(username) is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Username already exists")
    if store.find_by_email(email) is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Email already exists")

    user = User(
        username=username,
        email=email,
        hashed_password=hash_password(req.password),
        role=Role.viewer,
    )
    store.put(user)
    return UserPublic.of(user)


@router.post("/register", response_model=UserPublic, status_code=status.HTTP_201_CREATED)
def register(
    req: RegisterRequest,
    store: UserStore = Depends(get_store),
    _admin: User = Depends(require_role(Role.administrator)),
) -> UserPublic:
    """Legacy administrator-only account provisioning endpoint."""

    if store.get(req.username) is not None:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="User exists")
    user = User(username=req.username, hashed_password=hash_password(req.password), role=req.role)
    store.put(user)
    return UserPublic.of(user)


@router.post("/mfa/setup", response_model=MfaSetupResponse)
def mfa_setup(
    user: User = Depends(get_current_user),
    store: UserStore = Depends(get_store),
) -> MfaSetupResponse:
    """Generate (but do not yet enable) a TOTP secret for the caller."""

    secret = generate_totp_secret()
    user.totp_secret = secret
    store.put(user)
    return MfaSetupResponse(secret=secret, provisioning_uri=totp_provisioning_uri(secret, user.username))


@router.post("/mfa/enable", response_model=UserPublic)
def mfa_enable(
    req: MfaEnableRequest,
    user: User = Depends(get_current_user),
    store: UserStore = Depends(get_store),
) -> UserPublic:
    """Confirm the authenticator is set up by proving one valid code."""

    if not user.totp_secret or not verify_totp(user.totp_secret, req.code):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Invalid TOTP code")
    user.mfa_enabled = True
    store.put(user)
    return UserPublic.of(user)
