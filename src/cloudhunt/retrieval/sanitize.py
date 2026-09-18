"""Sanitisation boundary for attacker-controllable values.

Attacker-controlled text is represented only as a structured DATA wrapper:
    {"tag":"DATA", "field":"user_agent", "value":"...escaped...",
     "truncated":false, "original_length":12}
Consumers must treat ``value`` as inert display/search data, never instructions.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass
import html
import json
from typing import Any

DEFAULT_CAP = 512

@dataclass(frozen=True)
class DataField:
    tag: str
    field: str
    value: str
    truncated: bool
    original_length: int

    def as_dict(self) -> dict:
        return asdict(self)


def _text(value: Any) -> str:
    if isinstance(value, (dict, list, tuple)):
        return json.dumps(value, sort_keys=True, separators=(",", ":"), default=str)
    return "" if value is None else str(value)


def sanitize_data(field: str, value: Any, cap: int = DEFAULT_CAP) -> dict:
    raw = _text(value)
    clipped = raw[:cap]
    # HTML escaping plus visible escaping of control/newline characters prevents
    # the wrapper from being confused with narrative/instructions when rendered.
    escaped = html.escape(clipped, quote=True).replace("\r", "\\r").replace("\n", "\\n").replace("\t", "\\t")
    return DataField("DATA", field, escaped, len(raw) > cap, len(raw)).as_dict()
