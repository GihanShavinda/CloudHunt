"""Layer 2 — per-principal behavioural baselines and anomaly detectors.

Signatures catch *known-bad actions*; baselines catch *known-good principals
behaving oddly*. We learn each principal's normal envelope from a training
window — regions, source countries, ASNs, the set of APIs it calls — then flag
departures:

* **new-geo credential use** — a known principal suddenly acting from a country
  it has never used (stolen long-term key).
* **impossible travel** — the same principal acting from two different countries
  closer together in time than anyone could travel.
* **automation doing IAM writes** — a CI/service principal, which should only
  touch a narrow API set, performing identity mutations.
* **enumeration burst** — a spray of Describe*/List*/Get* calls in a short
  window (Cloud discovery / recon).

The baseline resolver is offline and deterministic: fit on events, score events.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import timedelta
from typing import Iterable, Optional

from cloudhunt.detect.base import Detection, Layer
from cloudhunt.models.events import CloudEvent

# IAM mutating actions an automation principal should almost never call.
IAM_WRITE_ACTIONS = {
    "CreateUser", "DeleteUser", "CreateAccessKey", "UpdateAccessKey",
    "CreateLoginProfile", "UpdateLoginProfile", "AttachUserPolicy",
    "DetachUserPolicy", "PutUserPolicy", "AttachRolePolicy", "PutRolePolicy",
    "CreatePolicy", "CreatePolicyVersion", "SetDefaultPolicyVersion",
    "CreateRole", "DeleteRole", "UpdateAssumeRolePolicy", "AddUserToGroup",
    "CreateGroup", "PutGroupPolicy", "AddRoleToInstanceProfile", "PassRole",
}

# Tokens that mark a principal as automation (case-insensitive substring match).
_AUTOMATION_TOKENS = ("bot", "ci-", "-ci", "jenkins", "terraform", "svc",
                      "service-account", "automation", "runner", "pipeline")


def is_read_action(event_name: str) -> bool:
    return event_name.startswith(("Describe", "List", "Get"))


def is_automation_principal(event: CloudEvent, extra: Optional[set[str]] = None) -> bool:
    haystacks = [event.principal or ""]
    if event.session:
        haystacks += [event.session.issuer_arn or "", event.session.session_name or ""]
    text = " ".join(haystacks).lower()
    if any(tok in text for tok in _AUTOMATION_TOKENS):
        return True
    if extra and (event.principal in extra or
                  (event.session and event.session.issuer_arn in extra)):
        return True
    return False


@dataclass
class PrincipalBaseline:
    regions: set = field(default_factory=set)
    countries: set = field(default_factory=set)
    asns: set = field(default_factory=set)
    src_ips: set = field(default_factory=set)
    actions: set = field(default_factory=set)
    event_count: int = 0


@dataclass
class BaselineModel:
    profiles: dict = field(default_factory=dict)  # principal -> PrincipalBaseline

    @classmethod
    def fit(cls, events: Iterable[CloudEvent]) -> "BaselineModel":
        profiles: dict[str, PrincipalBaseline] = defaultdict(PrincipalBaseline)
        for e in events:
            p = profiles[e.principal]
            p.event_count += 1
            if e.region:
                p.regions.add(e.region)
            if e.geo:
                p.countries.add(e.geo)
            if e.asn:
                p.asns.add(e.asn)
            if e.src_ip:
                p.src_ips.add(e.src_ip)
            p.actions.add(e.event)
        return cls(dict(profiles))

    def knows(self, principal: str) -> bool:
        return principal in self.profiles


# ---------------------------------------------------------------------------
# Per-event detectors
# ---------------------------------------------------------------------------

def detect_new_geo(event: CloudEvent, model: BaselineModel) -> Optional[Detection]:
    """A *known* principal acting from a country absent from its baseline."""
    prof = model.profiles.get(event.principal)
    if prof is None or not prof.countries or not event.geo:
        return None
    if event.geo in prof.countries:
        return None
    return Detection.from_event(
        event, key="bhv-new-geo", title="Principal active from new geography",
        layer=Layer.behavioural, attack_ids=["T1078.004"], confidence=0.6,
        message=f"{event.principal} first seen from {event.geo}",
        evidence={"new_geo": event.geo, "known_geos": sorted(prof.countries)},
        false_positive_notes=["Travel / VPN / new office location"],
    )


def detect_automation_iam_write(
    event: CloudEvent, automation_principals: Optional[set[str]] = None,
) -> Optional[Detection]:
    if event.event not in IAM_WRITE_ACTIONS:
        return None
    if not is_automation_principal(event, automation_principals):
        return None
    return Detection.from_event(
        event, key="bhv-automation-iam-write",
        title="Automation principal performed an IAM write",
        layer=Layer.behavioural, attack_ids=["T1098"], confidence=0.7,
        message=f"automation {event.principal} called {event.event}",
        evidence={"action": event.event},
        false_positive_notes=["A CI/CD role that legitimately manages IAM (scope it out)"],
    )


# ---------------------------------------------------------------------------
# Streaming detectors (need time-ordered events)
# ---------------------------------------------------------------------------

def detect_impossible_travel(
    events: Iterable[CloudEvent], max_gap_minutes: int = 60,
) -> list[Detection]:
    """Country change for one principal within an implausibly short window.

    A country-level approximation of the classic speed test: without lat/long we
    treat *any* change of country inside ``max_gap_minutes`` as impossible.
    """
    last: dict[str, tuple] = {}   # principal -> (geo, ts)
    out: list[Detection] = []
    for e in sorted(events, key=lambda x: x.ts):
        if not e.geo:
            continue
        prev = last.get(e.principal)
        if prev is not None:
            prev_geo, prev_ts = prev
            if prev_geo != e.geo and (e.ts - prev_ts) <= timedelta(minutes=max_gap_minutes):
                out.append(Detection.from_event(
                    e, key="bhv-impossible-travel",
                    title="Impossible travel for principal",
                    layer=Layer.behavioural, attack_ids=["T1078"], confidence=0.75,
                    message=f"{e.principal} moved {prev_geo} -> {e.geo} in "
                            f"{int((e.ts - prev_ts).total_seconds() // 60)} min",
                    evidence={"from": prev_geo, "to": e.geo,
                              "minutes": int((e.ts - prev_ts).total_seconds() // 60)},
                    false_positive_notes=["VPN / proxy egress hopping between regions"],
                ))
        last[e.principal] = (e.geo, e.ts)
    return out


def detect_enumeration_bursts(
    events: Iterable[CloudEvent], window_minutes: int = 5, distinct_threshold: int = 8,
) -> list[Detection]:
    """>= N distinct read (Describe/List/Get) actions by one principal in a window."""
    windows: dict[str, deque] = defaultdict(deque)
    firing: set[str] = set()
    out: list[Detection] = []
    for e in sorted(events, key=lambda x: x.ts):
        if not is_read_action(e.event):
            continue
        dq = windows[e.principal]
        dq.append((e.ts, e.event))
        while dq and (e.ts - dq[0][0]) > timedelta(minutes=window_minutes):
            dq.popleft()
        distinct = {name for _, name in dq}
        if len(distinct) >= distinct_threshold:
            if e.principal not in firing:
                firing.add(e.principal)
                out.append(Detection.from_event(
                    e, key="bhv-enumeration-burst",
                    title="Enumeration / discovery burst",
                    layer=Layer.behavioural, attack_ids=["T1580"], confidence=0.6,
                    message=f"{e.principal} issued {len(distinct)} distinct read "
                            f"APIs in <= {window_minutes} min",
                    evidence={"distinct_actions": sorted(distinct)},
                    false_positive_notes=["Inventory tools / CSPM scanners / the console"],
                ))
        else:
            firing.discard(e.principal)
    return out


@dataclass
class BehaviouralEngine:
    model: Optional[BaselineModel] = None
    automation_principals: set = field(default_factory=set)
    impossible_travel_minutes: int = 60
    burst_window_minutes: int = 5
    burst_threshold: int = 8

    def run(self, events: Iterable[CloudEvent]) -> list[Detection]:
        events = list(events)
        out: list[Detection] = []
        seen_new_geo: set[tuple] = set()  # (principal, geo) — flag once, not per event
        for e in events:
            if self.model is not None:
                d = detect_new_geo(e, self.model)
                if d and (e.principal, e.geo) not in seen_new_geo:
                    seen_new_geo.add((e.principal, e.geo))
                    out.append(d)
            d = detect_automation_iam_write(e, self.automation_principals)
            if d:
                out.append(d)
        out += detect_impossible_travel(events, self.impossible_travel_minutes)
        out += detect_enumeration_bursts(events, self.burst_window_minutes, self.burst_threshold)
        return out
