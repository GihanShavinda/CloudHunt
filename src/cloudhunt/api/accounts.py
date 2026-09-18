"""Single-account onboarding and ingestion-health surface (FR-4)."""
from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from cloudhunt.api.deps import get_current_user, require_role
from cloudhunt.models.user import Role, User

router = APIRouter(prefix="/accounts", tags=["accounts"])

@dataclass
class CloudAccount:
    account_id: str
    role_arn: str
    ingestion_health: str = "pending"
    last_event_at: Optional[str] = None

class AccountStore:
    def __init__(self): self._items: dict[str, CloudAccount] = {}
    def put(self, account: CloudAccount): self._items[account.account_id] = account
    def get(self, account_id: str): return self._items.get(account_id)
    def all(self): return list(self._items.values())

_store = AccountStore()
def get_account_store() -> AccountStore: return _store

class OnboardRequest(BaseModel):
    account_id: str
    role_arn: str

class HealthUpdate(BaseModel):
    status: str

@router.post("", status_code=status.HTTP_201_CREATED)
def onboard(req: OnboardRequest, _: User = Depends(require_role(Role.administrator)), store: AccountStore = Depends(get_account_store)) -> dict:
    if store.get(req.account_id):
        raise HTTPException(status_code=409, detail="Account already onboarded")
    acct = CloudAccount(req.account_id, req.role_arn)
    store.put(acct)
    return asdict(acct)

@router.get("")
def list_accounts(_: User = Depends(get_current_user), store: AccountStore = Depends(get_account_store)) -> dict:
    return {"accounts": [asdict(x) for x in store.all()]}

@router.patch("/{account_id}/ingestion-health")
def update_health(account_id: str, req: HealthUpdate, _: User = Depends(require_role(Role.administrator, Role.cloud_analyst)), store: AccountStore = Depends(get_account_store)) -> dict:
    acct = store.get(account_id)
    if not acct: raise HTTPException(status_code=404, detail="Account not found")
    acct.ingestion_health = req.status
    acct.last_event_at = datetime.now(timezone.utc).isoformat()
    return asdict(acct)
