"""Case-list, case-workspace, and human-approval API endpoints."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Header, HTTPException, status
from pydantic import BaseModel

from cloudhunt.api.casestore import CaseService, get_case_service
from cloudhunt.api.deps import get_current_user, require_role, require_totp
from cloudhunt.models.user import Role, User
from cloudhunt.respond import Approval
from cloudhunt.mobile import ApprovalTokenError
from cloudhunt.assistant import summarize_bundle, get_summary_model
from cloudhunt.retrieval import CaseContextBuilder

router = APIRouter(prefix="/cases", tags=["cases"])


@router.get("")
def list_cases(
    _: User = Depends(get_current_user),
    svc: CaseService = Depends(get_case_service),
) -> dict:
    """Return ranked cases for the dashboard."""
    return {"cases": svc.list_cases()}


@router.get("/{case_id}")
def case_detail(
    case_id: str,
    _: User = Depends(get_current_user),
    svc: CaseService = Depends(get_case_service),
) -> dict:
    """Return the server-computed analyst workspace payload for one case."""
    detail = svc.get_case(case_id)
    if detail is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
    return detail


@router.get("/{case_id}/summary")
def case_summary(
    case_id: str,
    _: User = Depends(get_current_user),
    svc: CaseService = Depends(get_case_service),
) -> dict:
    """Read-only summary endpoint. With AI disabled it always uses M9 templates."""
    try:
        bundle = CaseContextBuilder(svc).build(case_id)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    result = summarize_bundle(bundle, model=get_summary_model())
    return {
        "case_id": case_id,
        "summary": result.text,
        "source": result.source,
        "valid": result.valid,
        "rejected": not result.valid,
        "violations": list(result.violations),
    }




class ApprovalRequest(BaseModel):
    decision: str = "approve"


@router.post("/{case_id}/actions/{action_key}/approval-token")
def issue_mobile_approval_token(
    case_id: str,
    action_key: str,
    _: User = Depends(require_role(Role.administrator, Role.cloud_analyst)),
    svc: CaseService = Depends(get_case_service),
) -> dict:
    """Mint a short-lived token for one already-pending M6 human action."""
    try:
        return svc.issue_approval_token(case_id, action_key)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc

@router.post("/{case_id}/actions/{action_key}/approve")
def approve_case_action(
    case_id: str,
    action_key: str,
    req: ApprovalRequest | None = None,
    approver: User = Depends(require_role(Role.administrator, Role.cloud_analyst)),
    _mfa: User = Depends(require_totp),
    x_approval_channel: str = Header(default="web", alias="X-Approval-Channel"),
    x_approval_token: str | None = Header(default=None, alias="X-Approval-Token"),
    svc: CaseService = Depends(get_case_service),
) -> dict:
    """Same web/mobile approval endpoint; RBAC + TOTP gates are unchanged."""
    channel = x_approval_channel.lower().strip()
    if channel not in {"web", "mobile"}:
        raise HTTPException(status_code=400, detail="X-Approval-Channel must be web or mobile")
    decision = (req.decision if req else "approve").lower().strip()
    if decision not in {"approve", "deny"}:
        raise HTTPException(status_code=400, detail="decision must be approve or deny")
    approval = Approval(approver=approver.username, role=approver.role.value,
                        mfa_verified=True, channel=channel)
    try:
        if decision == "deny":
            record = svc.deny(case_id, action_key, approval, token=x_approval_token)
        else:
            record = svc.approve(case_id, action_key, approval, token=x_approval_token)
    except KeyError as exc:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(exc)) from exc
    except ApprovalTokenError as exc:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(exc)) from exc

    return {
        "record_id": record.record_id, "case_id": record.case_id,
        "action_key": record.action_key, "status": record.status,
        "decision": record.decision, "approval_decision": record.approval_decision,
        "approver": record.approver, "channel": record.channel,
        "before": record.before, "after": record.after, "reason": record.reason,
    }
