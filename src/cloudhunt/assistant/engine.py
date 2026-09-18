"""Pure, isolated assistant engine.

Architectural boundary: this module accepts only a serialisable M9 context
bundle and a read-only model port.  It has no AWS SDK, case store, response
executor, audit log, mutation callback, or tool interface.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Protocol

from cloudhunt.assistant.policy import SYSTEM_PROMPT
from cloudhunt.assistant.validate import ValidationResult, validate_summary


class SummaryModel(Protocol):
    """Minimal read-only model port used by the assistant engine."""

    def generate(self, *, system_prompt: str, context_bundle: dict) -> str: ...


@dataclass(frozen=True)
class AssistantOutput:
    text: str
    valid: bool
    violations: tuple[str, ...]


class GroundedAssistant:
    def __init__(self, model: SummaryModel):
        self._model = model

    def summarize(self, bundle: dict) -> AssistantOutput:
        # Deliberately pass exactly two inputs: fixed policy + the M9 bundle.
        # No retrieved web/general-knowledge context and no tools are exposed.
        text = self._model.generate(system_prompt=SYSTEM_PROMPT, context_bundle=bundle)
        result: ValidationResult = validate_summary(text, bundle)
        return AssistantOutput(text=text, valid=result.valid, violations=result.violations)
