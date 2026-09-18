"""Response-action endpoints.

The real action catalogue (deactivate key, quarantine principal, isolate
instance, re-enable logging) arrives in Milestone 6. What Milestone 1 delivers
is the *gate* those endpoints will sit behind, wired and testable now:

    approval  ==  authenticated
                  AND role in {Administrator, Cloud Analyst}
                  AND a fresh valid TOTP second factor

The handler itself is a stub that records the intent; the point is that no
high-impact action can be reached without clearing every gate.
"""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from cloudhunt.api.deps import require_role, require_totp
from cloudhunt.models.user import Role, User

router = APIRouter(prefix="/actions", tags=["actions"])


class ApprovalResult(BaseModel):
    action_id: str
    approved_by: str
    status: str


@router.post("/{action_id}/approve", response_model=ApprovalResult)
def approve_action(
    action_id: str,
    approver: User = Depends(require_role(Role.administrator, Role.cloud_analyst)),
    _mfa: User = Depends(require_totp),
) -> ApprovalResult:
    # Milestone 6: validate against playbook, execute reversible AWS action,
    # capture before/after + undo_ref, append to the audit log.
    return ApprovalResult(action_id=action_id, approved_by=approver.username, status="approved (stub)")
