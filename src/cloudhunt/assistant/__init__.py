"""Thin, grounded, non-authoritative case explanation layer."""
from cloudhunt.assistant.engine import AssistantOutput, GroundedAssistant, SummaryModel
from cloudhunt.assistant.service import SummaryResult, summarize_bundle
from cloudhunt.assistant.validate import ValidationResult, validate_summary

__all__ = [
    "AssistantOutput", "GroundedAssistant", "SummaryModel",
    "SummaryResult", "summarize_bundle", "ValidationResult", "validate_summary",
]

from cloudhunt.assistant.runtime import get_summary_model, set_summary_model
