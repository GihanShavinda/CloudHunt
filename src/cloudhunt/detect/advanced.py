"""Milestone 8 advanced cloud detections.

These detectors operate on configuration/graph snapshots plus normalised CloudTrail
history.  They deliberately emit the same :class:`Detection` type as Milestone 4,
so the existing correlation engine can consume them without UI changes.

The module is offline and deterministic: callers provide snapshots/events and no AWS
write is ever performed here.
"""

from __future__ import annotations

import json
import math
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from fnmatch import fnmatchcase
from statistics import mean, pstdev
from typing import Any, Iterable, Mapping, Optional
from urllib.parse import unquote

from cloudhunt.detect.base import Detection, Layer
from cloudhunt.graph.policy_eval import EffectivePermissions, ResolvedGrant
from cloudhunt.models.events import CloudEvent
from cloudhunt.privesc.pathfind import PrivEscPath


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _normalise_action(event: CloudEvent) -> str:
    """Return ``service:Action`` when CloudTrail source metadata is available.

    Milestone 8 stores ``__event_source`` during CloudTrail normalisation.  The
    fallback keeps hand-built fixtures/backwards-compatible events useful.
    """
    source = event.params.get("__event_source") or event.params.get("eventSource")
    if isinstance(source, str) and source:
        service = source.split(".", 1)[0].lower()
        return f"{service}:{event.event}"
    if ":" in event.event:
        return event.event
    # Conservative service inference for the APIs used by M8. Unknown actions are
    # kept bare and therefore will not accidentally satisfy a service-prefixed grant.
    if event.event in {
        "GetObject", "PutObject", "ListBucket", "PutBucketPolicy", "PutBucketAcl",
        "PutPublicAccessBlock", "DeletePublicAccessBlock",
    }:
        return f"s3:{event.event}"
    if event.event in {
        "CreateRole", "UpdateAssumeRolePolicy", "AttachRolePolicy", "AttachUserPolicy",
        "PutRolePolicy", "PutUserPolicy", "CreatePolicyVersion", "PassRole",
    }:
        return f"iam:{event.event}"
    if event.event == "AssumeRole":
        return "sts:AssumeRole"
    return event.event


def _grant_is_used(grant: ResolvedGrant, observed_actions: set[str]) -> bool:
    for pattern in grant.actions:
        if pattern.startswith("NOT "):
            # NotAction grants are too broad to prove unused safely from an allow-list
            # of observed calls. Keep them out of least-privilege auto-findings.
            return True
        p = pattern.lower()
        if any(fnmatchcase(action.lower(), p) for action in observed_actions):
            return True
    return False


def _event_anchor(event: Optional[CloudEvent], **kwargs) -> Detection:
    if event is not None:
        return Detection.from_event(event, **kwargs)
    return Detection(**kwargs)


# ---------------------------------------------------------------------------
# 1A. Least-privilege drift: granted-but-unused permissions
# ---------------------------------------------------------------------------


def detect_granted_but_unused(
    effective_permissions: Mapping[str, EffectivePermissions],
    usage_events: Iterable[CloudEvent],
    *,
    lookback_days: int = 30,
    as_of: Optional[datetime] = None,
    ignore_conditional: bool = True,
) -> list[Detection]:
    """Find effective Allow grants with no matching CloudTrail use in the window.

    A finding is grouped per principal.  This is a least-privilege *drift/exposure*
    signal, not proof of malicious activity. Conditional grants default to excluded
    because their runtime satisfiability is unknown to the offline policy evaluator.
    """
    if lookback_days <= 0:
        raise ValueError("lookback_days must be > 0")
    events = list(usage_events)
    if as_of is None:
        as_of = max((e.ts for e in events), default=_utc_now())
    start = as_of - timedelta(days=lookback_days)

    observed: dict[str, set[str]] = defaultdict(set)
    for e in events:
        if start <= e.ts <= as_of:
            observed[e.principal].add(_normalise_action(e))

    out: list[Detection] = []
    for principal, ep in effective_permissions.items():
        unused: list[dict[str, Any]] = []
        for grant in ep.allows:
            if grant.effect.lower() != "allow":
                continue
            if ignore_conditional and grant.conditional:
                continue
            if not _grant_is_used(grant, observed.get(principal, set())):
                unused.append({
                    "actions": list(grant.actions),
                    "resources": list(grant.resources),
                    "source": grant.source,
                    "conditional": grant.conditional,
                })
        if not unused:
            continue
        out.append(Detection(
            key="m8-least-privilege-unused",
            title="Granted permissions unused in CloudTrail lookback",
            layer=Layer.behavioural,
            attack_ids=["T1548"],
            confidence=0.45,
            principal=principal,
            ts=as_of,
            message=(f"{principal} has {len(unused)} effective grant(s) with no "
                     f"matching use in the last {lookback_days} days"),
            evidence={
                "lookback_days": lookback_days,
                "observed_actions": sorted(observed.get(principal, set())),
                "unused_grants": unused,
            },
            false_positive_notes=[
                "Break-glass or disaster-recovery permissions may be intentionally dormant",
                "CloudTrail data events may be disabled or the lookback may be incomplete",
                "Seasonal/month-end jobs can be inactive during a short lookback",
            ],
        ))
    return out


# ---------------------------------------------------------------------------
# 1B. Least-privilege drift: newly created privilege-escalation paths
# ---------------------------------------------------------------------------


def _path_fingerprint(path: PrivEscPath) -> tuple:
    return (
        path.principal,
        path.target,
        path.target_priv,
        tuple((h.src, h.technique, h.dst, h.attack_id, h.conditional) for h in path.path),
    )


def detect_new_privesc_paths(
    before_paths: Iterable[PrivEscPath],
    after_paths: Iterable[PrivEscPath],
    *,
    observed_at: Optional[datetime] = None,
) -> list[Detection]:
    """Diff successive Milestone-3 graph/path snapshots and emit only new paths."""
    observed_at = observed_at or _utc_now()
    old = {_path_fingerprint(p) for p in before_paths}
    out: list[Detection] = []
    for path in after_paths:
        fp = _path_fingerprint(path)
        if fp in old:
            continue
        out.append(Detection(
            key="m8-new-privesc-path",
            title="New IAM privilege-escalation path created",
            layer=Layer.correlation,
            attack_ids=["T1548"],
            confidence=0.8 if not path.conditional else 0.65,
            principal=path.principal,
            ts=observed_at,
            message=f"new path from {path.principal} to {path.target_priv}",
            evidence={
                "target": path.target,
                "target_priv": path.target_priv,
                "conditional": path.conditional,
                "techniques": list(path.techniques),
                "hops": [
                    {"src": h.src, "technique": h.technique, "dst": h.dst,
                     "attack_id": h.attack_id, "conditional": h.conditional}
                    for h in path.path
                ],
            },
            false_positive_notes=[
                "Approved IAM rollout or new workload role may intentionally create a path",
                "Snapshot incompleteness can make an old path appear newly created",
                "Condition-dependent edges need request-context validation before response",
            ],
        ))
    return out


# ---------------------------------------------------------------------------
# 2. Backdoor trust-policy diffing
# ---------------------------------------------------------------------------


def _policy_doc(value: Any) -> dict[str, Any]:
    if value is None:
        return {}
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        text = unquote(value)
        try:
            parsed = json.loads(text)
            return parsed if isinstance(parsed, dict) else {}
        except json.JSONDecodeError:
            return {}
    return {}


def _statements(doc: Any) -> list[dict[str, Any]]:
    raw = _policy_doc(doc).get("Statement", [])
    if isinstance(raw, dict):
        raw = [raw]
    return [s for s in raw if isinstance(s, dict)]


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _aws_principals(stmt: Mapping[str, Any]) -> set[str]:
    p = stmt.get("Principal")
    if isinstance(p, str):
        return {p}
    if not isinstance(p, Mapping):
        return set()
    return {str(v) for v in _as_list(p.get("AWS"))}


def _account_from_principal(principal: str) -> Optional[str]:
    if principal.isdigit() and len(principal) == 12:
        return principal
    parts = principal.split(":")
    if len(parts) > 4 and parts[4].isdigit():
        return parts[4]
    return None


def _condition_atoms(condition: Any) -> set[tuple[str, str, str]]:
    atoms: set[tuple[str, str, str]] = set()
    if not isinstance(condition, Mapping):
        return atoms
    for op, body in condition.items():
        if not isinstance(body, Mapping):
            continue
        for key, value in body.items():
            values = _as_list(value)
            for item in values:
                atoms.add((str(op), str(key), json.dumps(item, sort_keys=True)))
    return atoms


def _stmt_subject(stmt: Mapping[str, Any]) -> tuple:
    actions = tuple(sorted(str(x) for x in _as_list(stmt.get("Action"))))
    principals = tuple(sorted(_aws_principals(stmt)))
    return (str(stmt.get("Effect", "")), actions, principals)


def detect_backdoor_trust_policy(
    *,
    account_id: str,
    role_arn: str,
    before_policy: Any,
    after_policy: Any,
    event: Optional[CloudEvent] = None,
    allowed_external_accounts: Optional[set[str]] = None,
) -> list[Detection]:
    """Flag newly-added external/wildcard trust and dropped trust conditions."""
    allowed_external_accounts = allowed_external_accounts or set()
    before = _statements(before_policy)
    after = _statements(after_policy)

    old_principals = set().union(*(_aws_principals(s) for s in before)) if before else set()
    new_principals = set().union(*(_aws_principals(s) for s in after)) if after else set()
    added = new_principals - old_principals

    reasons: list[dict[str, Any]] = []
    for principal in sorted(added):
        if principal == "*":
            reasons.append({"type": "wildcard_principal", "principal": principal})
            continue
        acct = _account_from_principal(principal)
        if acct and acct != account_id and acct not in allowed_external_accounts:
            reasons.append({"type": "external_account", "principal": principal, "account": acct})

    old_by_subject: dict[tuple, set[tuple[str, str, str]]] = {}
    for stmt in before:
        old_by_subject[_stmt_subject(stmt)] = _condition_atoms(stmt.get("Condition"))
    for stmt in after:
        subject = _stmt_subject(stmt)
        if subject not in old_by_subject:
            continue
        old_cond = old_by_subject[subject]
        new_cond = _condition_atoms(stmt.get("Condition"))
        dropped = old_cond - new_cond
        if dropped:
            reasons.append({
                "type": "condition_dropped",
                "principal": list(subject[2]),
                "dropped": [list(x) for x in sorted(dropped)],
            })

    if not reasons:
        return []

    d = _event_anchor(
        event,
        key="m8-backdoor-trust-policy",
        title="Role trust policy weakened or opened externally",
        layer=Layer.signature,
        attack_ids=["T1098"],
        confidence=0.9,
        principal=event.principal if event else None,
        account=account_id if event is None else event.account,
        ts=event.ts if event else _utc_now(),
        message=f"trust policy for {role_arn} introduced {len(reasons)} risky change(s)",
        evidence={"role_arn": role_arn, "changes": reasons},
        false_positive_notes=[
            "Approved cross-account access for a known partner/vendor",
            "Federation patterns can intentionally trust another account with strong conditions",
            "Condition changes during IAM refactoring may preserve equivalent controls elsewhere",
        ],
    )
    return [d]


# ---------------------------------------------------------------------------
# 3. S3 exfiltration analytics
# ---------------------------------------------------------------------------


def _bytes_from_event(event: CloudEvent) -> int:
    for key in ("bytesTransferred", "bytes_transferred", "objectSize", "bytesSent"):
        value = event.params.get(key)
        if isinstance(value, (int, float)) and value >= 0:
            return int(value)
        if isinstance(value, str) and value.isdigit():
            return int(value)
    return 0


def _bucket_from_event(event: CloudEvent) -> Optional[str]:
    name = event.params.get("bucketName")
    if isinstance(name, str) and name:
        return name
    if event.target:
        target = event.target
        if target.startswith("arn:aws:s3:::"):
            return target[len("arn:aws:s3:::"):].split("/", 1)[0]
        if "/" in target:
            return target.split("/", 1)[0]
        return target
    return None


def _policy_is_public(policy: Any) -> bool:
    for stmt in _statements(policy):
        if str(stmt.get("Effect", "")).lower() != "allow":
            continue
        p = stmt.get("Principal")
        wildcard = p == "*" or (isinstance(p, Mapping) and "*" in _as_list(p.get("AWS")))
        if wildcard:
            return True
    return False


def _weakens_public_access(event: CloudEvent) -> bool:
    if event.event == "DeletePublicAccessBlock":
        return True
    p = event.params
    if event.event == "PutPublicAccessBlock":
        cfg = p.get("PublicAccessBlockConfiguration") or p.get("publicAccessBlockConfiguration") or p
        if isinstance(cfg, Mapping):
            keys = ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets",
                    "blockPublicAcls", "ignorePublicAcls", "blockPublicPolicy", "restrictPublicBuckets")
            return any(k in cfg and cfg[k] is False for k in keys)
    if event.event == "PutBucketAcl":
        canned = p.get("ACL") or p.get("acl") or p.get("x-amz-acl")
        if str(canned).lower() in {"public-read", "public-read-write", "authenticated-read"}:
            return True
        blob = json.dumps(p, sort_keys=True)
        return "AllUsers" in blob or "AuthenticatedUsers" in blob
    if event.event == "PutBucketPolicy":
        return _policy_is_public(p.get("bucketPolicy") or p.get("policy"))
    return False


@dataclass
class S3PrincipalBaseline:
    principal: str
    daily_get_mean: float = 0.0
    daily_get_std: float = 0.0
    daily_bytes_mean: float = 0.0
    daily_bytes_std: float = 0.0
    regions: set[str] = field(default_factory=set)
    samples: int = 0


@dataclass
class S3BaselineModel:
    profiles: dict[str, S3PrincipalBaseline] = field(default_factory=dict)

    @classmethod
    def fit(cls, events: Iterable[CloudEvent]) -> "S3BaselineModel":
        buckets: dict[str, dict[Any, list[int]]] = defaultdict(lambda: defaultdict(lambda: [0, 0]))
        regions: dict[str, set[str]] = defaultdict(set)
        principals: set[str] = set()
        for e in events:
            if e.event != "GetObject":
                continue
            principals.add(e.principal)
            day = e.ts.astimezone(timezone.utc).date()
            buckets[e.principal][day][0] += 1
            buckets[e.principal][day][1] += _bytes_from_event(e)
            if e.region:
                regions[e.principal].add(e.region)

        profiles: dict[str, S3PrincipalBaseline] = {}
        for principal in principals:
            vals = list(buckets[principal].values())
            counts = [v[0] for v in vals]
            volumes = [v[1] for v in vals]
            profiles[principal] = S3PrincipalBaseline(
                principal=principal,
                daily_get_mean=mean(counts) if counts else 0.0,
                daily_get_std=pstdev(counts) if len(counts) > 1 else 0.0,
                daily_bytes_mean=mean(volumes) if volumes else 0.0,
                daily_bytes_std=pstdev(volumes) if len(volumes) > 1 else 0.0,
                regions=set(regions[principal]),
                samples=len(vals),
            )
        return cls(profiles)


def detect_s3_exfiltration(
    events: Iterable[CloudEvent],
    model: S3BaselineModel,
    *,
    sensitive_buckets: Optional[set[str]] = None,
    sigma: float = 3.0,
    minimum_get_delta: int = 20,
    minimum_byte_delta: int = 50 * 1024 * 1024,
) -> list[Detection]:
    """Flag per-principal S3 count/volume/region anomalies and public exposure.

    Count/volume thresholds use ``mean + sigma*std`` with an absolute delta floor,
    preventing tiny baselines (e.g. 1 -> 2 requests) from firing as an exfil alert.
    """
    sensitive_buckets = sensitive_buckets or set()
    events = list(events)
    current: dict[str, list[CloudEvent]] = defaultdict(list)
    out: list[Detection] = []

    # Public access changes are event-driven and do not require a learned profile.
    for e in events:
        bucket = _bucket_from_event(e)
        if bucket and bucket in sensitive_buckets and _weakens_public_access(e):
            out.append(Detection.from_event(
                e,
                key="m8-s3-sensitive-public-access",
                title="Sensitive S3 bucket public-access controls weakened",
                layer=Layer.signature,
                attack_ids=["T1537"],
                confidence=0.9,
                message=f"{e.event} may expose sensitive bucket {bucket}",
                evidence={"bucket": bucket, "action": e.event},
                false_positive_notes=[
                    "Intentional public dataset/static-site publication",
                    "A compensating bucket policy/control may still prevent anonymous reads",
                ],
            ))
        if e.event == "GetObject":
            current[e.principal].append(e)

    for principal, pevents in current.items():
        prof = model.profiles.get(principal)
        if prof is None:
            continue  # no historical envelope: avoid calling first-seen activity anomalous
        count = len(pevents)
        volume = sum(_bytes_from_event(e) for e in pevents)
        regions = {e.region for e in pevents if e.region}
        anchor = max(pevents, key=lambda e: e.ts)

        count_threshold = max(prof.daily_get_mean + sigma * prof.daily_get_std,
                              prof.daily_get_mean + minimum_get_delta)
        volume_threshold = max(prof.daily_bytes_mean + sigma * prof.daily_bytes_std,
                               prof.daily_bytes_mean + minimum_byte_delta)

        reasons: list[dict[str, Any]] = []
        if count > count_threshold:
            reasons.append({
                "type": "getobject_volume_anomaly",
                "observed": count,
                "baseline_mean": prof.daily_get_mean,
                "threshold": count_threshold,
            })
        if volume > volume_threshold:
            reasons.append({
                "type": "byte_volume_anomaly",
                "observed_bytes": volume,
                "baseline_mean_bytes": prof.daily_bytes_mean,
                "threshold_bytes": volume_threshold,
            })
        new_regions = sorted(regions - prof.regions)
        if new_regions and prof.regions:
            reasons.append({
                "type": "cross_region_access",
                "new_regions": new_regions,
                "known_regions": sorted(prof.regions),
            })

        if reasons:
            out.append(Detection.from_event(
                anchor,
                key="m8-s3-exfil-anomaly",
                title="S3 access deviates from principal exfiltration baseline",
                layer=Layer.behavioural,
                attack_ids=["T1530", "T1537"],
                confidence=0.8,
                message=f"{principal} showed {len(reasons)} S3 exfiltration indicator(s)",
                evidence={"reasons": reasons, "get_count": count, "bytes": volume},
                false_positive_notes=[
                    "Backups, analytics exports, incident-response collection and migrations can spike volume",
                    "Failover/DR or newly enabled AWS regions can create legitimate cross-region reads",
                    "Byte-volume detection depends on enriched object-size/transfer telemetry",
                ],
            ))

    return out
