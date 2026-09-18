"""Case assembly — bind a correlated cluster, its reconstructed chain, and its
blast radius into one ranked :class:`Case` for the triage queue.

    rank = alpha * (blast / 100) + beta * detection_confidence

``blast`` is the worst-case radius across the identities in the case (a foothold
is as dangerous as the most dangerous identity it touches); ``detection_confidence``
is the Milestone-4 correlated case score. Ranking blends *how bad it could be*
with *how sure we are it is happening*.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional

from cloudhunt.correlate.blast import BlastRadius, Weights, score_blast
from cloudhunt.correlate.chain import AttackChain, reconstruct_chain
from cloudhunt.detect.correlate import CloudCase
from cloudhunt.graph.authorization import IamAuthorization
from cloudhunt.graph.model import IdentityGraph, build_graph
from cloudhunt.graph.policy_eval import PolicyEvaluator
from cloudhunt.models.events import CloudEvent
from cloudhunt.privesc.detector import detect_escalations
from cloudhunt.privesc.pathfind import find_privesc_paths


@dataclass
class RankWeights:
    alpha: float = 0.6      # weight on blast radius (impact)
    beta: float = 0.4       # weight on detection confidence (certainty)


@dataclass
class Case:
    case_id: str
    cloud_case: CloudCase
    chain: AttackChain
    blast: BlastRadius                       # worst-case identity
    blast_by_principal: dict = field(default_factory=dict)
    detection_confidence: float = 0.0
    rank: float = 0.0
    title: str = ""

    def summary(self) -> str:
        return (f"[{self.rank:.3f}] {self.case_id}  {self.title}\n"
                f"  chain: {self.chain.summary()}\n"
                f"  {self.blast.explanation()}")


def prepare_graph(auth: IamAuthorization):
    """Build the identity graph, evaluator, escalation edges and privesc paths."""
    graph = build_graph(auth)
    evaluator = PolicyEvaluator(auth)
    detect_escalations(auth, graph, evaluator)          # adds CAN_ESCALATE_VIA / CAN_ACCESS
    paths = {p.principal: p for p in find_privesc_paths(auth, graph, evaluator)}
    return graph, evaluator, paths


def build_case(
    cloud_case: CloudCase,
    events: list[CloudEvent],
    auth: IamAuthorization,
    graph: IdentityGraph,
    evaluator: PolicyEvaluator,
    weights: Optional[Weights] = None,
    rank_weights: Optional[RankWeights] = None,
) -> Case:
    rw = rank_weights or RankWeights()
    chain = reconstruct_chain(cloud_case, events, graph)

    # Score every real identity the case touches; the case inherits the worst.
    candidates = (set(chain.actors) | set(cloud_case.principals)) & set(auth.principals)
    blast_by = {p: score_blast(p, auth, graph, evaluator, weights) for p in candidates}
    if blast_by:
        primary = max(blast_by.values(), key=lambda b: b.score)
    else:
        primary = BlastRadius(principal="(none)", score=0.0)

    rank = round(rw.alpha * (primary.score / 100.0) + rw.beta * cloud_case.score, 4)
    return Case(
        case_id=cloud_case.case_id, cloud_case=cloud_case, chain=chain,
        blast=primary, blast_by_principal=blast_by,
        detection_confidence=cloud_case.score, rank=rank, title=cloud_case.title,
    )


def build_cases(
    cloud_cases: list[CloudCase],
    events: list[CloudEvent],
    auth: IamAuthorization,
    graph: IdentityGraph,
    evaluator: PolicyEvaluator,
    weights: Optional[Weights] = None,
    rank_weights: Optional[RankWeights] = None,
) -> list[Case]:
    cases = [build_case(cc, events, auth, graph, evaluator, weights, rank_weights)
             for cc in cloud_cases]
    return rank_cases(cases)


def rank_cases(cases: list[Case]) -> list[Case]:
    return sorted(cases, key=lambda c: c.rank, reverse=True)
