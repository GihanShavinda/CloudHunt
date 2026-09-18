"""Attack-chain reconstruction — one ordered story from a cluster of detections.

Milestone 4 groups detections into a :class:`CloudCase` (who / where / when).
This turns that cluster into a single *ordered chain*:

    key-abuse -> AssumeRole -> privesc -> discovery -> S3 exfil -> StopLogging

Reconstruction runs over the **events** behind the case, not just the detections,
because pivotal steps (the AssumeRole itself, the object reads) are often not
detections on their own yet are essential to the narrative. Events are selected
by the case's principals / IPs / time span, attributed to the acting identity
(assumed-role sessions resolved back to their issuer via ``session.issuer_arn``),
ordered chronologically, and discovery sprays collapsed into one step.
Chronology *is* the causal order; ATT&CK tactic rank only breaks ties.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

from cloudhunt.detect import attack
from cloudhunt.detect.base import Detection
from cloudhunt.detect.correlate import CloudCase
from cloudhunt.graph.model import IdentityGraph
from cloudhunt.models.events import CloudEvent, PrincipalType

# Event name -> ATT&CK id for events that carry the story. Checked before the
# generic Describe/List/Get -> discovery fallback (so GetObject stays exfil).
_EVENT_ATTACK: dict[str, str] = {
    "AssumeRole": "T1548", "AssumeRoleWithSAML": "T1548",
    "AssumeRoleWithWebIdentity": "T1548",
    "CreatePolicyVersion": "T1098.003", "SetDefaultPolicyVersion": "T1098.003",
    "AttachUserPolicy": "T1098.003", "PutUserPolicy": "T1098.003",
    "AttachRolePolicy": "T1098.003", "PutRolePolicy": "T1098.003",
    "UpdateAssumeRolePolicy": "T1098.003",
    "CreateAccessKey": "T1098.001", "CreateLoginProfile": "T1098.001",
    "CreateUser": "T1136.003",
    "RunInstances": "T1496",
    "AuthorizeSecurityGroupIngress": "T1562.007",
    "AuthorizeSecurityGroupEgress": "T1562.007",
    "GetObject": "T1530", "PutObject": "T1530", "CopyObject": "T1530",
    "SelectObjectContent": "T1530",
    "StopLogging": "T1562.008", "DeleteTrail": "T1562.008",
    "UpdateTrail": "T1562.008", "DeleteDetector": "T1562.008",
}


def _classify(event_name: str) -> Optional[str]:
    if event_name in _EVENT_ATTACK:
        return _EVENT_ATTACK[event_name]
    if event_name.startswith(("Describe", "List", "Get")):
        return "T1580"          # discovery
    return None


def _actor(ev: CloudEvent) -> str:
    """Resolve an assumed-role session back to the role that issued it."""
    if ev.principal_type == PrincipalType.assumed_role and ev.session and ev.session.issuer_arn:
        return ev.session.issuer_arn
    return ev.principal


@dataclass
class ChainStep:
    order: int
    ts: datetime
    actor: str                       # resolved identity (issuer for sessions)
    raw_principal: str
    action: str
    attack_id: Optional[str]
    target: Optional[str] = None
    event_ids: list[str] = field(default_factory=list)
    detection_keys: list[str] = field(default_factory=list)
    via_edge: Optional[str] = None   # graph edge that realises this step
    read_count: int = 1

    @property
    def tactic(self) -> str:
        return attack.tactic_for(self.attack_id) if self.attack_id else "Unknown"


@dataclass
class AttackChain:
    case_id: str
    steps: list[ChainStep] = field(default_factory=list)
    actors: set = field(default_factory=set)

    def summary(self) -> str:
        return "  ->  ".join(s.action for s in self.steps)

    def tactic_sequence(self) -> list[str]:
        return [s.tactic for s in self.steps]


def _select_events(case: CloudCase, events: list[CloudEvent],
                   pad_minutes: int) -> list[CloudEvent]:
    ids = set(case.principals)
    lo = (case.ts_start - timedelta(minutes=pad_minutes)) if case.ts_start else None
    hi = (case.ts_end + timedelta(minutes=pad_minutes)) if case.ts_end else None
    out = []
    for ev in events:
        if lo and ev.ts < lo:
            continue
        if hi and ev.ts > hi:
            continue
        if ev.principal in ids or _actor(ev) in ids or (ev.src_ip and ev.src_ip in case.src_ips):
            out.append(ev)
    return out


def _annotate_graph_edge(step: ChainStep, graph: IdentityGraph) -> None:
    """Tie a step to the graph edge that makes it possible (explainability)."""
    if step.attack_id == "T1548" and step.target:            # AssumeRole
        for e in graph.edges_of("CAN_ASSUME"):
            if e.src == step.actor and e.dst == step.target:
                step.via_edge = f"CAN_ASSUME {step.actor.split('/')[-1]} -> {step.target.split('/')[-1]}"
                return
    if step.attack_id == "T1530" and step.target:            # S3 access
        for e in graph.edges_of("CAN_ACCESS"):
            if e.src == step.actor and e.dst == step.target:
                step.via_edge = f"CAN_ACCESS -> {step.target.split('/')[-1]}"
                return
    if step.attack_id == "T1098.003":                        # privesc self-grant
        for e in graph.edges_of("CAN_ESCALATE_VIA"):
            if e.src == step.actor:
                step.via_edge = f"CAN_ESCALATE_VIA {e.props.get('technique', '')}"
                return


def reconstruct_chain(
    case: CloudCase,
    events: list[CloudEvent],
    graph: Optional[IdentityGraph] = None,
    collapse_gap_minutes: int = 10,
    pad_minutes: int = 5,
) -> AttackChain:
    selected = _select_events(case, events, pad_minutes)
    det_by_event: dict[str, list[Detection]] = {}
    for d in case.detections:
        if d.event_id:
            det_by_event.setdefault(d.event_id, []).append(d)

    # Chronological order; ATT&CK tactic rank only breaks exact-time ties.
    from cloudhunt.detect.correlate import _TACTIC_ORDER
    trank = {t: i for i, t in enumerate(_TACTIC_ORDER)}

    def sort_key(ev: CloudEvent):
        aid = _classify(ev.event)
        tac = attack.tactic_for(aid) if aid else "Unknown"
        return (ev.ts, trank.get(tac, 99))

    raw_steps: list[ChainStep] = []
    for ev in sorted(selected, key=sort_key):
        aid = _classify(ev.event)
        raw_steps.append(ChainStep(
            order=0, ts=ev.ts, actor=_actor(ev), raw_principal=ev.principal,
            action=ev.event, attack_id=aid, target=ev.target,
            event_ids=[ev.event_id],
            detection_keys=[d.key for d in det_by_event.get(ev.event_id, [])],
        ))

    # Collapse consecutive same-actor discovery reads into one step.
    collapsed: list[ChainStep] = []
    gap = timedelta(minutes=collapse_gap_minutes)
    for s in raw_steps:
        if (collapsed and s.attack_id == "T1580" and collapsed[-1].attack_id == "T1580"
                and collapsed[-1].actor == s.actor and (s.ts - collapsed[-1].ts) <= gap):
            prev = collapsed[-1]
            prev.read_count += 1
            prev.event_ids += s.event_ids
            prev.detection_keys += s.detection_keys
            prev.action = f"Discovery ({prev.read_count} reads)"
        else:
            collapsed.append(s)

    for i, s in enumerate(collapsed, start=1):
        s.order = i
        if graph is not None:
            _annotate_graph_edge(s, graph)

    return AttackChain(
        case_id=case.case_id, steps=collapsed,
        actors={s.actor for s in collapsed},
    )
