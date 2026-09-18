"""Layer 3 — correlation.

Individual detections are noisy; an incident is a *cluster*. We link detections
that share a principal or a source IP and fall within a time window, then treat
each connected component as one candidate :class:`CloudCase`. A case aggregates
the ATT&CK techniques/tactics seen, so a scatter of low-confidence signals that
together trace initial-access -> defense-evasion -> exfiltration surfaces as a
single, higher-confidence story.

Scoring is a noisy-OR of member confidences with a small boost per *distinct
tactic* (breadth across the kill chain is itself evidence). An optional pass
folds in Milestone 3 privilege-escalation reachability.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Optional

from cloudhunt.detect import attack
from cloudhunt.detect.base import Detection

# Kill-chain order used only to render a readable case title.
_TACTIC_ORDER = [
    "Initial Access", "Execution", "Persistence", "Privilege Escalation",
    "Defense Evasion", "Credential Access", "Discovery", "Lateral Movement",
    "Collection", "Exfiltration", "Impact",
]


@dataclass
class CloudCase:
    case_id: str
    detections: list[Detection]
    principals: set = field(default_factory=set)
    src_ips: set = field(default_factory=set)
    techniques: set = field(default_factory=set)
    tactics: set = field(default_factory=set)
    ts_start: Optional[datetime] = None
    ts_end: Optional[datetime] = None
    score: float = 0.0
    title: str = ""
    notes: list[str] = field(default_factory=list)

    def ordered_tactics(self) -> list[str]:
        idx = {t: i for i, t in enumerate(_TACTIC_ORDER)}
        return sorted(self.tactics, key=lambda t: idx.get(t, 99))


class _UnionFind:
    def __init__(self, n: int):
        self.parent = list(range(n))

    def find(self, x: int) -> int:
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: int, b: int) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[ra] = rb


def _linked(a: Detection, b: Detection, window: timedelta) -> bool:
    if a.ts is None or b.ts is None or abs(a.ts - b.ts) > window:
        return False
    if a.principal and a.principal == b.principal:
        return True
    if a.src_ip and a.src_ip == b.src_ip:
        return True
    return False


def _score(detections: list[Detection], tactics: set) -> float:
    prod = 1.0
    for d in detections:
        prod *= (1.0 - max(0.0, min(1.0, d.confidence)))
    noisy_or = 1.0 - prod
    boost = 0.05 * max(0, len(tactics) - 1)
    return round(min(0.99, noisy_or + boost), 3)


def correlate(detections: list[Detection], window_minutes: int = 60) -> list[CloudCase]:
    if not detections:
        return []
    window = timedelta(minutes=window_minutes)
    n = len(detections)
    uf = _UnionFind(n)
    for i in range(n):
        for j in range(i + 1, n):
            if _linked(detections[i], detections[j], window):
                uf.union(i, j)

    groups: dict[int, list[int]] = {}
    for i in range(n):
        groups.setdefault(uf.find(i), []).append(i)

    cases: list[CloudCase] = []
    for gi, (_, idxs) in enumerate(sorted(groups.items(),
                                          key=lambda kv: min(detections[i].ts or datetime.max
                                                             for i in kv[1])), start=1):
        members = [detections[i] for i in idxs]
        techniques = {t for d in members for t in d.attack_ids}
        tactics = {attack.tactic_for(t) for t in techniques}
        times = [d.ts for d in members if d.ts]
        case = CloudCase(
            case_id=f"case-{gi}", detections=members,
            principals={d.principal for d in members if d.principal},
            src_ips={d.src_ip for d in members if d.src_ip},
            techniques=techniques, tactics=tactics,
            ts_start=min(times) if times else None,
            ts_end=max(times) if times else None,
            score=_score(members, tactics),
        )
        case.title = " -> ".join(case.ordered_tactics()) or "Uncategorised activity"
        cases.append(case)

    cases.sort(key=lambda c: c.score, reverse=True)
    return cases


def enrich_with_privesc(case: CloudCase, paths_by_principal: dict) -> None:
    """If a case principal has a known privilege-escalation path, fold it in.

    ``paths_by_principal`` maps principal ARN -> a Milestone-3 PrivEscPath (any
    object with ``.target_priv`` and ``.techniques``). Adds T1548, boosts score,
    and annotates — a detected foothold on a principal that is *already one step
    from admin* is materially more urgent.
    """
    hit = False
    for p in case.principals:
        path = paths_by_principal.get(p)
        if path is None:
            continue
        hit = True
        case.techniques.add("T1548")
        case.tactics.add(attack.tactic_for("T1548"))
        case.notes.append(
            f"{p} has a privesc path to {path.target_priv} "
            f"via {' -> '.join(path.techniques)}"
        )
    if hit:
        case.score = round(min(0.99, case.score + 0.1), 3)
        case.title = " -> ".join(case.ordered_tactics())
