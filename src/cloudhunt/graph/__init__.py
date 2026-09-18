"""IAM identity graph + offline policy evaluation (Milestone 2 / P2).

Public surface:
    IamAuthorization        parsed IAM/Config snapshot (the substrate)
    build_graph             IamAuthorization -> IdentityGraph (nodes + edges)
    PolicyEvaluator         offline effective-permission evaluator
    what_can_principal_do   query: a principal's capabilities
    who_can_do              query: principals able to act on a resource
    cypher_statements       pure Neo4j projection of the graph
"""

from cloudhunt.graph.authorization import IamAuthorization
from cloudhunt.graph.model import IdentityGraph, build_graph
from cloudhunt.graph.neo4j_writer import Neo4jGraphWriter, cypher_statements
from cloudhunt.graph.policy_eval import Decision, Effect, PolicyEvaluator
from cloudhunt.graph.query import (
    PrincipalCapabilities,
    WhoCanResult,
    what_can_principal_do,
    who_can_do,
)

__all__ = [
    "IamAuthorization",
    "IdentityGraph",
    "build_graph",
    "PolicyEvaluator",
    "Decision",
    "Effect",
    "what_can_principal_do",
    "who_can_do",
    "PrincipalCapabilities",
    "WhoCanResult",
    "cypher_statements",
    "Neo4jGraphWriter",
]
