"""CloudTrail record -> :class:`CloudEvent`.

The tricky parts of CloudTrail, and how we handle them:

* **Identity is polymorphic.** ``userIdentity.type`` may be IAMUser, AssumedRole,
  Root, AWSService, etc. For an assumed role the caller ARN is the *session*
  ARN, and the underlying role is in ``sessionContext.sessionIssuer`` — which we
  capture separately because chain reconstruction walks issuer links.
* **The target is not a single field.** We resolve it best-effort from the
  ``resources`` array (preferred, already an ARN) and fall back to well-known
  ``requestParameters`` keys (roleArn, policyArn, bucketName, ...).
* **MFA is a string.** ``sessionContext.attributes.mfaAuthenticated`` is the
  literal text ``"true"``/``"false"``, not a bool.
"""

from __future__ import annotations

from typing import Any, Optional

from cloudhunt.ingest.base import RawRecord
from cloudhunt.models.events import (
    CloudEvent,
    PrincipalType,
    Sensitivity,
    SessionContext,
    Source,
)

# CloudTrail userIdentity.type -> our normalised enum.
_PRINCIPAL_TYPE = {
    "IAMUser": PrincipalType.user,
    "Root": PrincipalType.root,
    "AssumedRole": PrincipalType.assumed_role,
    "Role": PrincipalType.role,
    "AWSService": PrincipalType.service,
    "AWSAccount": PrincipalType.account,
    "FederatedUser": PrincipalType.federated,
}

# requestParameters keys that name the acted-on resource, in priority order.
_TARGET_PARAM_KEYS = (
    "roleArn",
    "policyArn",
    "userName",
    "roleName",
    "functionName",
    "bucketName",
    "instanceId",
    "groupId",
    "trailARN",
    "name",
)


def _str_to_bool(val: Any) -> Optional[bool]:
    if isinstance(val, bool):
        return val
    if isinstance(val, str):
        return val.strip().lower() == "true"
    return None


def _resolve_principal(identity: dict[str, Any]) -> tuple[str, PrincipalType]:
    ptype = _PRINCIPAL_TYPE.get(identity.get("type", ""), PrincipalType.unknown)
    arn = identity.get("arn")
    if not arn:  # AWSService events carry invokedBy, not an ARN
        arn = identity.get("invokedBy") or identity.get("accountId") or "unknown"
    return arn, ptype


def _resolve_session(identity: dict[str, Any]) -> Optional[SessionContext]:
    ctx = identity.get("sessionContext")
    if not ctx:
        return None
    issuer = ctx.get("sessionIssuer", {})
    attrs = ctx.get("attributes", {})
    return SessionContext(
        issuer_arn=issuer.get("arn"),
        issuer_type=issuer.get("type"),
        session_name=issuer.get("userName"),
        mfa_authenticated=_str_to_bool(attrs.get("mfaAuthenticated")),
    )


def _resolve_target(record: dict[str, Any]) -> Optional[str]:
    resources = record.get("resources") or []
    for res in resources:
        if res.get("ARN"):
            return res["ARN"]
    params = record.get("requestParameters") or {}
    for key in _TARGET_PARAM_KEYS:
        if key in params and isinstance(params[key], str):
            return params[key]
    return None


def normalise_cloudtrail(raw: RawRecord) -> CloudEvent:
    rec = raw.record
    identity = rec.get("userIdentity", {})
    principal, ptype = _resolve_principal(identity)
    session = _resolve_session(identity)

    # Prefer the session-level MFA flag; fall back to false.
    mfa = bool(session.mfa_authenticated) if session and session.mfa_authenticated else False

    account = rec.get("recipientAccountId") or identity.get("accountId") or "unknown"

    return CloudEvent(
        ts=rec["eventTime"],
        account=account,
        region=rec.get("awsRegion", "unknown"),
        event=rec.get("eventName", "unknown"),
        principal=principal,
        principal_type=ptype,
        session=session,
        target=_resolve_target(rec),
        src_ip=rec.get("sourceIPAddress"),
        user_agent=rec.get("userAgent"),
        mfa=mfa,
        resource_sensitivity=Sensitivity.unknown,  # filled by the enricher
        read_only=rec.get("readOnly"),
        error_code=rec.get("errorCode"),
        event_id=rec.get("eventID", raw.raw_ref),
        source=Source.cloudtrail,
        raw_ref=raw.raw_ref,
        params={
            **(rec.get("requestParameters") or {}),
            "__event_source": rec.get("eventSource"),
            **({"bytesTransferred": rec.get("additionalEventData", {}).get("bytesTransferred")}
               if rec.get("additionalEventData", {}).get("bytesTransferred") is not None else {}),
        },
    )
