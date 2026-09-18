"""Authenticated mobile device registration/revocation for M11."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from cloudhunt.api.casestore import CaseService, get_case_service
from cloudhunt.api.deps import get_current_user
from cloudhunt.models.user import User

router = APIRouter(prefix="/mobile", tags=["mobile"])


class DeviceRegistration(BaseModel):
    push_token: str
    platform: str


@router.post("/devices", status_code=status.HTTP_201_CREATED)
def register_device(req: DeviceRegistration, user: User = Depends(get_current_user),
                    svc: CaseService = Depends(get_case_service)) -> dict:
    d = svc.push.registry.register(user.username, req.push_token, req.platform)
    return {"device_id": d.device_id, "platform": d.platform, "revoked": d.revoked}


@router.delete("/devices/{device_id}")
def revoke_device(device_id: str, user: User = Depends(get_current_user),
                  svc: CaseService = Depends(get_case_service)) -> dict:
    if not svc.push.registry.revoke(device_id, user.username):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Device not found")
    return {"device_id": device_id, "revoked": True}
