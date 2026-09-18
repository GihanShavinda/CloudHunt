"""Runtime seam for the optional M10 model.

The web/API layer knows only this read-only interface.  The assistant remains
isolated from response/AWS state; deployments may register an implementation at
startup while tests can inject a fake.  No model is configured by default.
"""
from __future__ import annotations
from typing import Optional
from cloudhunt.assistant.engine import SummaryModel

_model: Optional[SummaryModel] = None

def set_summary_model(model: Optional[SummaryModel]) -> None:
    global _model
    _model = model

def get_summary_model() -> Optional[SummaryModel]:
    return _model
