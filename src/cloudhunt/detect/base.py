"""Shared detection types: the :class:`Detection` record and its layer tag.

A ``Detection`` is one finding from any layer. It is intentionally flat and
event-anchored (principal / src_ip / ts / event_id) so Layer 3 can correlate
findings from different layers without special-casing where they came from.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional

from cloudhunt.detect import attack
from cloudhunt.models.events import CloudEvent


class Layer(str, Enum):
    signature = "signature"
    behavioural = "behavioural"
    correlation = "correlation"


@dataclass
class Detection:
    key: str                     # rule/detector id, e.g. "ct-stop-logging"
    title: str
    layer: Layer
    attack_ids: list[str]
    confidence: float            # 0..1 base confidence
    principal: Optional[str] = None
    src_ip: Optional[str] = None
    ts: Optional[datetime] = None
    account: Optional[str] = None
    region: Optional[str] = None
    event_id: Optional[str] = None
    event_name: Optional[str] = None
    message: str = ""
    evidence: dict = field(default_factory=dict)
    false_positive_notes: list[str] = field(default_factory=list)

    @property
    def tactics(self) -> list[str]:
        seen: list[str] = []
        for tid in self.attack_ids:
            t = attack.tactic_for(tid)
            if t not in seen:
                seen.append(t)
        return seen

    @property
    def techniques(self) -> list[attack.Technique]:
        return [attack.resolve(t) for t in self.attack_ids]

    @classmethod
    def from_event(cls, event: CloudEvent, **kw) -> "Detection":
        """Build a detection anchored to a CloudEvent's identity/time fields."""
        base = dict(
            principal=event.principal, src_ip=event.src_ip, ts=event.ts,
            account=event.account, region=event.region,
            event_id=event.event_id, event_name=event.event,
        )
        base.update(kw)
        return cls(**base)
