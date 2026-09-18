"""Append-only audit trail for response actions.

Every AWS write CloudHunt performs — auto or human-approved — records what it did
(``action_key`` + ``target``), *why* it was allowed (``decision`` + ``approver``),
the ``before``/``after`` state, and an ``undo_ref`` sufficient to reverse it. The
log is **append-only**: there is no update or delete, and an undo is itself a new
record that points back at the original. That is the non-repudiation property the
brief requires of every containment action.

Two implementations: :class:`InMemoryAuditLog` (default, dev/tests) and
:class:`JsonlAuditLog` (one JSON object per line, opened in append mode — a
genuinely append-only file store). Production swaps in a Postgres-backed log
behind the same tiny interface; the schema mirrors :class:`AuditRecord`.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Protocol


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class AuditRecord:
    action_key: str
    decision: str                      # "auto" | "human"
    status: str                        # "executed" | "undone" | "failed"
    target: dict = field(default_factory=dict)
    before: dict = field(default_factory=dict)
    after: dict = field(default_factory=dict)
    undo_ref: dict = field(default_factory=dict)
    approver: Optional[str] = None
    case_id: Optional[str] = None
    reason: str = ""
    parent_id: Optional[str] = None    # set on an undo, points at the original
    channel: str = "system"             # system | web | mobile
    approval_decision: Optional[str] = None  # approve | deny | expired
    record_id: str = field(default_factory=lambda: uuid.uuid4().hex)
    ts: str = field(default_factory=_now)

    def to_json(self) -> str:
        return json.dumps(asdict(self), sort_keys=True)


class AuditLog(Protocol):
    def append(self, record: AuditRecord) -> AuditRecord: ...
    def records(self) -> list[AuditRecord]: ...


class InMemoryAuditLog:
    """Append-only in-memory log. Exposes reads only; no mutation of history."""

    def __init__(self) -> None:
        self._records: list[AuditRecord] = []

    def append(self, record: AuditRecord) -> AuditRecord:
        self._records.append(record)
        return record

    def records(self) -> list[AuditRecord]:
        return list(self._records)      # a copy — callers can't mutate history


class JsonlAuditLog:
    """File-backed append-only log: one JSON record per line (open mode 'a')."""

    def __init__(self, path: str | Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)

    def append(self, record: AuditRecord) -> AuditRecord:
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(record.to_json() + "\n")
        return record

    def records(self) -> list[AuditRecord]:
        if not self.path.is_file():
            return []
        out = []
        for line in self.path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                out.append(AuditRecord(**json.loads(line)))
        return out
