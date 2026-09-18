"""Privilege-escalation edge detection + path search (Milestone 3 / P3).

Public surface:
    detect_escalations      probe preconditions, emit CAN_ESCALATE_VIA / CAN_ACCESS
    is_admin_equivalent     does a principal already hold admin?
    find_privesc_paths      shortest escalation chain per principal
    shortest_path           BFS to the nearest admin/sensitive goal
    PrivEscPath, Hop        the output records
    neo4j_shortest_path_query   equivalent Cypher for the persisted graph
    catalogue               the technique catalogue (with ATT&CK tags)
"""

from cloudhunt.privesc import catalogue
from cloudhunt.privesc.detector import (
    admin_node_id,
    detect_escalations,
    is_admin_equivalent,
)
from cloudhunt.privesc.pathfind import (
    Hop,
    PrivEscPath,
    find_privesc_paths,
    neo4j_shortest_path_query,
    shortest_path,
)

__all__ = [
    "detect_escalations",
    "is_admin_equivalent",
    "admin_node_id",
    "find_privesc_paths",
    "shortest_path",
    "PrivEscPath",
    "Hop",
    "neo4j_shortest_path_query",
    "catalogue",
]
