"""GuardDuty finding -> :class:`CloudEvent`.

A GuardDuty finding is a managed *detection*, not a raw API call, so the mapping
differs from CloudTrail:

* ``event`` becomes the finding ``Type`` (e.g.
  ``UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom``) — that is the
  meaningful signal.
* Network context (IP/ASN/country) is already inside the finding under
  ``Service.Action.*.RemoteIpDetails``; we lift it here so the enricher doesn't
  overwrite better data.
* ``severity`` carries straight through (GuardDuty's 0-10 scale) for triage.
* The principal is reconstructed best-effort from ``Resource.AccessKeyDetails``.
"""

from __future__ import annotations

from typing import Any, Optional

from cloudhunt.ingest.base import RawRecord
from cloudhunt.models.events import CloudEvent, PrincipalType, Sensitivity, Source


def _remote_ip_details(finding: dict[str, Any]) -> dict[str, Any]:
    action = (finding.get("Service", {}) or {}).get("Action", {}) or {}
    for sub in ("AwsApiCallAction", "NetworkConnectionAction", "PortProbeAction"):
        details = (action.get(sub, {}) or {}).get("RemoteIpDetails")
        if details:
            return details
    return {}


def _resolve_principal(finding: dict[str, Any], account: str) -> tuple[str, PrincipalType]:
    resource = finding.get("Resource", {}) or {}
    ak = resource.get("AccessKeyDetails", {}) or {}
    username = ak.get("UserName")
    if username:
        return f"arn:aws:iam::{account}:user/{username}", PrincipalType.user
    instance = resource.get("InstanceDetails", {}) or {}
    if instance.get("InstanceId"):
        return instance["InstanceId"], PrincipalType.unknown
    return ak.get("PrincipalId") or "unknown", PrincipalType.unknown


def _normalise_asn(asn: Any) -> Optional[str]:
    if asn is None or asn == "":
        return None
    text = str(asn)
    return text if text.upper().startswith("AS") else f"AS{text}"


def normalise_guardduty(raw: RawRecord) -> CloudEvent:
    f = raw.record
    account = f.get("AccountId", "unknown")
    principal, ptype = _resolve_principal(f, account)
    ip = _remote_ip_details(f)
    service = f.get("Service", {}) or {}

    ts = service.get("EventLastSeen") or f.get("UpdatedAt") or f.get("CreatedAt")

    return CloudEvent(
        ts=ts,
        account=account,
        region=f.get("Region", "unknown"),
        event=f.get("Type", "unknown"),
        principal=principal,
        principal_type=ptype,
        target=None,
        src_ip=ip.get("IpAddressV4"),
        asn=_normalise_asn((ip.get("Organization", {}) or {}).get("Asn")),
        geo=(ip.get("Country", {}) or {}).get("CountryName"),
        user_agent=None,
        mfa=False,
        resource_sensitivity=Sensitivity.unknown,
        severity=f.get("Severity"),
        event_id=f.get("Id", raw.raw_ref),
        source=Source.guardduty,
        raw_ref=raw.raw_ref,
    )
