"""Administrator-only CloudHunt platform user management."""

from __future__ import annotations

import re

from fastapi import (
    APIRouter,
    Depends,
    HTTPException,
    status,
)
from pydantic import BaseModel

from cloudhunt.api.deps import require_role
from cloudhunt.api.store import (
    UserStore,
    get_store,
)
from cloudhunt.core.security import (
    hash_password,
)
from cloudhunt.models.user import (
    Role,
    User,
    UserAdminPublic,
)


router = APIRouter(
    prefix="/users",
    tags=["users"],
)


_EMAIL_RE = re.compile(
    r"^[^\s@]+@[^\s@]+\.[^\s@]+$"
)

_USERNAME_RE = re.compile(
    r"^[A-Za-z0-9._-]{3,64}$"
)


# ============================================================
# REQUEST / RESPONSE MODELS
# ============================================================

class CreateUserRequest(
    BaseModel
):
    username: str
    email: str | None = None
    password: str
    role: Role = Role.viewer
    disabled: bool = False


class UpdateUserRequest(
    BaseModel
):
    email: str | None = None
    role: Role | None = None
    disabled: bool | None = None


class PasswordResetRequest(
    BaseModel
):
    new_password: str


class MessageResponse(
    BaseModel
):
    detail: str


# ============================================================
# INTERNAL HELPERS
# ============================================================

def _normalise_email(
    email: str | None,
) -> str | None:

    if email is None:
        return None

    email = (
        email
        .strip()
        .lower()
    )

    if not email:
        return None

    if not _EMAIL_RE.fullmatch(
        email
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                "Valid email address "
                "required"
            ),
        )

    return email


def _validate_username(
    username: str,
) -> str:

    username = (
        username
        .strip()
    )

    if not _USERNAME_RE.fullmatch(
        username
    ):
        raise HTTPException(
            status_code=400,
            detail=(
                "Username must be "
                "3-64 characters and "
                "use only letters, "
                "numbers, dot, "
                "underscore or hyphen"
            ),
        )

    return username


def _validate_password(
    password: str,
) -> None:

    if len(password) < 12:
        raise HTTPException(
            status_code=400,
            detail=(
                "Password must be at "
                "least 12 characters"
            ),
        )


def _active_admins(
    store: UserStore,
) -> list[User]:

    return [
        user
        for user
        in store.list()
        if (
            user.role ==
            Role.administrator
            and
            not user.disabled
        )
    ]


def _ensure_not_removing_last_active_admin(
    store: UserStore,
    target: User,
    *,
    new_role: Role | None = None,
    new_disabled: bool | None = None,
) -> None:

    if (
        target.role !=
        Role.administrator
        or
        target.disabled
    ):
        return

    would_remove_admin = (
        (
            new_role
            is not None
            and
            new_role !=
            Role.administrator
        )
        or
        new_disabled is True
    )

    if (
        would_remove_admin
        and
        len(
            _active_admins(
                store
            )
        ) <= 1
    ):
        raise HTTPException(
            status_code=
                status.HTTP_409_CONFLICT,
            detail=(
                "CloudHunt must retain "
                "at least one active "
                "Administrator"
            ),
        )


# ============================================================
# LIST USERS
# ============================================================

@router.get(
    "",
    response_model=
        list[UserAdminPublic],
)
def list_users(
    _admin: User = Depends(
        require_role(
            Role.administrator
        )
    ),
    store: UserStore = Depends(
        get_store
    ),
) -> list[UserAdminPublic]:

    users = sorted(
        store.list(),
        key=lambda user:
            user.username.lower(),
    )

    return [
        UserAdminPublic.of(
            user
        )
        for user
        in users
    ]


# ============================================================
# CREATE USER
# ============================================================

@router.post(
    "",
    response_model=
        UserAdminPublic,
    status_code=
        status.HTTP_201_CREATED,
)
def create_user(
    req: CreateUserRequest,
    _admin: User = Depends(
        require_role(
            Role.administrator
        )
    ),
    store: UserStore = Depends(
        get_store
    ),
) -> UserAdminPublic:

    username = (
        _validate_username(
            req.username
        )
    )

    _validate_password(
        req.password
    )

    if (
        store.get(
            username
        )
        is not None
    ):
        raise HTTPException(
            status_code=409,
            detail=(
                "Username already "
                "exists"
            ),
        )

    email = (
        _normalise_email(
            req.email
        )
    )

    if (
        email
        and
        store.find_by_email(
            email
        )
        is not None
    ):
        raise HTTPException(
            status_code=409,
            detail=(
                "Email already exists"
            ),
        )

    user = User(
        username=username,
        email=email,
        hashed_password=
            hash_password(
                req.password
            ),
        role=req.role,
        disabled=req.disabled,
    )

    store.put(
        user
    )

    return (
        UserAdminPublic.of(
            user
        )
    )


# ============================================================
# UPDATE USER
# ============================================================

@router.patch(
    "/{username}",
    response_model=
        UserAdminPublic,
)
def update_user(
    username: str,
    req: UpdateUserRequest,
    admin: User = Depends(
        require_role(
            Role.administrator
        )
    ),
    store: UserStore = Depends(
        get_store
    ),
) -> UserAdminPublic:

    target = store.get(
        username
    )

    if target is None:
        raise HTTPException(
            status_code=404,
            detail="User not found",
        )

    # Prevent administrators from
    # disabling themselves.
    if (
        target.username ==
        admin.username
        and
        req.disabled is True
    ):
        raise HTTPException(
            status_code=409,
            detail=(
                "You cannot disable "
                "your own account"
            ),
        )

    # Prevent an administrator from
    # demoting themselves.
    if (
        target.username ==
        admin.username
        and
        req.role is not None
        and
        req.role !=
        Role.administrator
    ):
        raise HTTPException(
            status_code=409,
            detail=(
                "You cannot remove "
                "your own Administrator "
                "role"
            ),
        )

    _ensure_not_removing_last_active_admin(
        store,
        target,
        new_role=req.role,
        new_disabled=
            req.disabled,
    )

    if (
        req.email
        is not None
    ):

        email = (
            _normalise_email(
                req.email
            )
        )

        existing = (
            store.find_by_email(
                email
            )
            if email
            else None
        )

        if (
            existing
            is not None
            and
            existing.username !=
            target.username
        ):
            raise HTTPException(
                status_code=409,
                detail=(
                    "Email already "
                    "exists"
                ),
            )

        target.email = email

    if (
        req.role
        is not None
    ):
        target.role = (
            req.role
        )

    if (
        req.disabled
        is not None
    ):
        target.disabled = (
            req.disabled
        )

    store.put(
        target
    )

    return (
        UserAdminPublic.of(
            target
        )
    )


# ============================================================
# DELETE USER
# ============================================================

@router.delete(
    "/{username}",
    response_model=
        MessageResponse,
)
def delete_user(
    username: str,
    admin: User = Depends(
        require_role(
            Role.administrator
        )
    ),
    store: UserStore = Depends(
        get_store
    ),
) -> MessageResponse:

    target = store.get(
        username
    )

    if target is None:
        raise HTTPException(
            status_code=404,
            detail="User not found",
        )

    if (
        target.username ==
        admin.username
    ):
        raise HTTPException(
            status_code=409,
            detail=(
                "You cannot delete "
                "your own account"
            ),
        )

    if (
        target.role ==
        Role.administrator
        and
        not target.disabled
        and
        len(
            _active_admins(
                store
            )
        ) <= 1
    ):
        raise HTTPException(
            status_code=409,
            detail=(
                "CloudHunt must retain "
                "at least one active "
                "Administrator"
            ),
        )

    store.delete(
        username
    )

    return MessageResponse(
        detail=(
            f"User '{username}' "
            "deleted"
        )
    )


# ============================================================
# RESET MFA
# ============================================================

@router.post(
    "/{username}/reset-mfa",
    response_model=
        UserAdminPublic,
)
def reset_mfa(
    username: str,
    _admin: User = Depends(
        require_role(
            Role.administrator
        )
    ),
    store: UserStore = Depends(
        get_store
    ),
) -> UserAdminPublic:

    target = store.get(
        username
    )

    if target is None:
        raise HTTPException(
            status_code=404,
            detail="User not found",
        )

    target.mfa_enabled = False

    target.totp_secret = None

    store.put(
        target
    )

    return (
        UserAdminPublic.of(
            target
        )
    )


# ============================================================
# ADMIN PASSWORD RESET
# ============================================================

@router.post(
    "/{username}/password-reset",
    response_model=
        UserAdminPublic,
)
def reset_password(
    username: str,
    req: PasswordResetRequest,
    _admin: User = Depends(
        require_role(
            Role.administrator
        )
    ),
    store: UserStore = Depends(
        get_store
    ),
) -> UserAdminPublic:

    target = store.get(
        username
    )

    if target is None:
        raise HTTPException(
            status_code=404,
            detail="User not found",
        )

    _validate_password(
        req.new_password
    )

    target.hashed_password = (
        hash_password(
            req.new_password
        )
    )

    store.put(
        target
    )

    return (
        UserAdminPublic.of(
            target
        )
    )