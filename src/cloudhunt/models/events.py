"""The unified cloud-event schema.

Every telemetry source (CloudTrail, GuardDuty, VPC Flow, IAM/Config) is
normalised into exactly one shape: :class:`CloudEvent`. The detection engine,
graph builder and correlation logic read *only* this model, never a
source-specific record. That indirection is what lets us add a new source (or a
new cloud) later without touching detection.

Design note on the field set
-----------------------------
The Milestone-1 brief fixes the required top-level fields:
    ts, account, region, event, principal, target, src_ip, asn, geo,
    user_agent, mfa, resource_sensitivity, raw_ref
Those are present verbatim below. A handful of extra fields are added now
because they are cheap to carry and painful to retrofit:

* ``event_id`` — CloudTrail delivers at-least-once, so we need an idempotency
  key to avoid double-counting the same call as two detections.
* ``session`` — AssumeRole chain reconstruction (Milestone 5) is literally a
  walk over ``session.issuer_arn`` links; capturing it at ingest is free.
* ``source`` / ``principal_type`` / ``read_only`` / ``error_code`` — cheap
  triage signals used from Milestone 4 onward.
* ``severity`` — carried straight through from GuardDuty findings.
"""

from __future__ import annotations

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, Field


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Source(str, Enum):
    """Which telemetry stream produced the record."""

    cloudtrail = "cloudtrail"
    guardduty = "guardduty"
    vpcflow = "vpcflow"
    config = "config"


class PrincipalType(str, Enum):
    """Normalised AWS identity type (from CloudTrail ``userIdentity.type``)."""

    user = "user"
    role = "role"
    assumed_role = "assumed_role"
    root = "root"
    service = "service"
    account = "account"
    federated = "federated"
    unknown = "unknown"


class Sensitivity(str, Enum):
    """Resource sensitivity, from tags. Ground truth for blast-radius scoring."""

    high = "high"
    medium = "medium"
    low = "low"
    unknown = "unknown"


class SessionContext(BaseModel):
    """Assumed-role session provenance — the spine of chain reconstruction."""

    issuer_arn: Optional[str] = None
    issuer_type: Optional[str] = None
    session_name: Optional[str] = None
    mfa_authenticated: Optional[bool] = None


class CloudEvent(BaseModel):
    """One normalised cloud event. The single interface into detection."""

    # --- required core (Milestone-1 field list) ---
    ts: datetime
    account: str
    region: str
    event: str
    principal: str
    target: Optional[str] = None
    src_ip: Optional[str] = None
    asn: Optional[str] = None
    geo: Optional[str] = None
    user_agent: Optional[str] = None
    mfa: bool = False
    resource_sensitivity: Sensitivity = Sensitivity.unknown
    raw_ref: str

    # --- justified additions (see module docstring) ---
    event_id: str
    source: Source
    principal_type: PrincipalType = PrincipalType.unknown
    session: Optional[SessionContext] = None
    read_only: Optional[bool] = None
    error_code: Optional[str] = None
    severity: Optional[float] = None
    # Raw request parameters, carried for detection (SG CIDRs, instance types,
    # trust-policy documents, ...). Treated strictly as DATA, never instructions,
    # and only ever pattern-matched. Curated/capped in production; kept whole for
    # the sample datasets. Absent for sources that have none (e.g. GuardDuty).
    params: dict[str, Any] = Field(default_factory=dict)
    ingested_at: datetime = Field(default_factory=_utcnow)

    def dedup_key(self) -> str:
        """Idempotency key. Two records with the same key are the same event."""
        return f"{self.source.value}:{self.event_id}"
