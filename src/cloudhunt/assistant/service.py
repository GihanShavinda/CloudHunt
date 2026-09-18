"""Kill-switch coordinator and deterministic fallback.

This coordinator also receives only a completed context bundle.  It cannot
mutate cases, response plans, approvals, or audit state.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from cloudhunt.assistant.engine import GroundedAssistant, SummaryModel
from cloudhunt.core.config import settings
from cloudhunt.retrieval.render import render_case_summary


@dataclass(frozen=True)
class SummaryResult:
    text: str
    source: str                 # "ai" or "template"
    valid: bool
    violations: tuple[str, ...] = ()


def summarize_bundle(
    bundle: dict,
    model: Optional[SummaryModel] = None,
    *,
    enabled: Optional[bool] = None,
) -> SummaryResult:
    """Render a summary without giving the assistant any stateful dependency.

    ``enabled`` is an explicit test seam. Production callers omit it so the
    single ``CLOUDHUNT_ASSISTANT_ENABLED`` setting is authoritative.
    """
    use_ai = settings.assistant_enabled if enabled is None else enabled
    if not use_ai or model is None:
        return SummaryResult(text=render_case_summary(bundle), source="template", valid=True)

    out = GroundedAssistant(model).summarize(bundle)
    if not out.valid:
        # Invalid model output is never displayed. The deterministic M9 summary
        # remains available and carries no model dependency.
        return SummaryResult(
            text=render_case_summary(bundle),
            source="template",
            valid=False,
            violations=out.violations,
        )
    return SummaryResult(text=out.text, source="ai", valid=True)
