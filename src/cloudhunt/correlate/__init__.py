"""Cross-event correlation into ranked cases (Milestone 5 / P5).

Takes the Milestone-4 correlated clusters (:class:`CloudCase`) and turns each
into one ordered attack chain with an explainable blast-radius score and a queue
rank.

    AttackChain, reconstruct_chain     chain reconstruction over the graph
    BlastRadius, score_blast, Weights  blast-radius scorer (0-100), explainable
    Case, build_cases, rank_cases      assembled + ranked triage cases
    prepare_graph                      graph + evaluator + escalation edges + paths
"""

from cloudhunt.correlate.blast import BlastRadius, Weights, score_blast
from cloudhunt.correlate.chain import AttackChain, ChainStep, reconstruct_chain
from cloudhunt.correlate.case import (
    Case,
    RankWeights,
    build_case,
    build_cases,
    prepare_graph,
    rank_cases,
)

__all__ = [
    "AttackChain", "ChainStep", "reconstruct_chain",
    "BlastRadius", "Weights", "score_blast",
    "Case", "RankWeights", "build_case", "build_cases", "rank_cases",
    "prepare_graph",
]
