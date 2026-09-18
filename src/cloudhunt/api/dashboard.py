"""Dashboard API — the at-a-glance summary widgets."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from cloudhunt.api.casestore import CaseService, get_case_service
from cloudhunt.api.deps import get_current_user
from cloudhunt.models.user import User

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/summary")
def summary(_: User = Depends(get_current_user),
            svc: CaseService = Depends(get_case_service)) -> dict:
    return svc.dashboard_summary()
