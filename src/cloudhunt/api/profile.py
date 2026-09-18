"""FR-1 profile and password-management endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from cloudhunt.api.deps import get_current_user, require_role
from cloudhunt.api.store import UserStore, get_store
from cloudhunt.core.security import hash_password, verify_password
from cloudhunt.models.user import Role, User, UserPublic

router = APIRouter(prefix="/profile", tags=["profile"])

class PasswordChange(BaseModel):
    current_password: str
    new_password: str

class AdminPasswordReset(BaseModel):
    new_password: str

@router.get("", response_model=UserPublic)
def profile(user: User = Depends(get_current_user)) -> UserPublic:
    return UserPublic.of(user)

@router.post("/password", response_model=UserPublic)
def change_password(req: PasswordChange, user: User = Depends(get_current_user), store: UserStore = Depends(get_store)) -> UserPublic:
    if not verify_password(req.current_password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Current password is incorrect")
    if len(req.new_password) < 12:
        raise HTTPException(status_code=400, detail="New password must be at least 12 characters")
    user.hashed_password = hash_password(req.new_password)
    store.put(user)
    return UserPublic.of(user)

@router.post("/users/{username}/password-reset", response_model=UserPublic)
def admin_reset(username: str, req: AdminPasswordReset, _: User = Depends(require_role(Role.administrator)), store: UserStore = Depends(get_store)) -> UserPublic:
    user = store.get(username)
    if not user: raise HTTPException(status_code=404, detail="User not found")
    if len(req.new_password) < 12: raise HTTPException(status_code=400, detail="New password must be at least 12 characters")
    user.hashed_password = hash_password(req.new_password)
    store.put(user)
    return UserPublic.of(user)
