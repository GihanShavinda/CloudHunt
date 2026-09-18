"""Authenticated deterministic export endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Response, status

from cloudhunt.api.casestore import CaseService, get_case_service
from cloudhunt.api.deps import get_current_user
from cloudhunt.models.user import User
from cloudhunt.retrieval import CaseContextBuilder
from cloudhunt.assistant import summarize_bundle, get_summary_model
from cloudhunt.reporting import case_csv, case_json, case_pdf

router = APIRouter(prefix="/reports", tags=["reports"])


def _payload(case_id: str, svc: CaseService) -> tuple[dict, dict]:
    detail = svc.get_case(case_id)
    if detail is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Case not found")
    bundle = CaseContextBuilder(svc).build(case_id)
    result = summarize_bundle(bundle, model=get_summary_model())
    summary = {
        "summary": result.text, "source": result.source, "valid": result.valid,
        "rejected": not result.valid, "violations": list(result.violations),
    }
    return detail, summary


@router.get("/cases/{case_id}.json")
def export_json(case_id: str, _: User = Depends(get_current_user), svc: CaseService = Depends(get_case_service)) -> Response:
    detail, summary = _payload(case_id, svc)
    return Response(case_json(detail, summary), media_type="application/json",
                    headers={"Content-Disposition": f'attachment; filename="{case_id}.json"'})


@router.get("/cases/{case_id}.csv")
def export_csv(case_id: str, _: User = Depends(get_current_user), svc: CaseService = Depends(get_case_service)) -> Response:
    detail, _ = _payload(case_id, svc)
    return Response(case_csv(detail), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="{case_id}.csv"'})


@router.get("/cases/{case_id}.pdf")
def export_pdf(case_id: str, _: User = Depends(get_current_user), svc: CaseService = Depends(get_case_service)) -> Response:
    detail, summary = _payload(case_id, svc)
    return Response(case_pdf(detail, summary), media_type="application/pdf",
                    headers={"Content-Disposition": f'attachment; filename="{case_id}.pdf"'})
