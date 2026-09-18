"""Project the in-memory :class:`IdentityGraph` into Neo4j.

The graph is the source of truth; Neo4j is a queryable/visualisable projection.
To keep this testable without a running database, statement *generation* is a
pure function (:func:`cypher_statements`) that returns ``(cypher, params)`` pairs
— unit-tested directly — while :meth:`Neo4jGraphWriter.write` is the thin I/O
wrapper that runs them (lazy ``neo4j`` import, exercised only against a live DB).
"""

from __future__ import annotations

from typing import Any, Optional

from cloudhunt.graph.model import IdentityGraph


def cypher_statements(graph: IdentityGraph) -> list[tuple[str, dict[str, Any]]]:
    """Idempotent MERGE statements that materialise the graph in Neo4j."""
    stmts: list[tuple[str, dict[str, Any]]] = []

    for node in graph.nodes.values():
        stmts.append((
            f"MERGE (n:{node.kind} {{id: $id}}) "
            f"SET n.label = $label, n += $props",
            {"id": node.id, "label": node.label, "props": dict(node.props)},
        ))

    for e in graph.edges:
        stmts.append((
            "MATCH (a {id: $src}), (b {id: $dst}) "
            f"MERGE (a)-[r:{e.kind}]->(b) SET r += $props",
            {"src": e.src, "dst": e.dst, "props": e.props},
        ))
    return stmts


class Neo4jGraphWriter:
    """Live writer. Needs a running Neo4j (see docker-compose); not in unit tests."""

    def __init__(self, uri: str, user: str, password: str, driver: Optional[Any] = None):
        if driver is None:
            from neo4j import GraphDatabase  # lazy: offline tests never import neo4j

            driver = GraphDatabase.driver(uri, auth=(user, password))
        self._driver = driver

    def write(self, graph: IdentityGraph) -> int:
        count = 0
        with self._driver.session() as session:
            for cypher, params in cypher_statements(graph):
                session.run(cypher, **params)
                count += 1
        return count

    def close(self) -> None:
        self._driver.close()
