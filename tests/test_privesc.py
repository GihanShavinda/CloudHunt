"""Validate computed privilege-escalation paths against known ground truth.

The fixture ``sample_data/iam_auth/cloudgoat_privesc_01.json`` is a
known-vulnerable config mirroring CloudGoat privesc scenarios. Every path
asserted below was worked out by hand from that config.
"""

from __future__ import annotations

import pytest

from cloudhunt.graph.authorization import IamAuthorization
from cloudhunt.graph.model import build_graph
from cloudhunt.graph.neo4j_writer import cypher_statements
from cloudhunt.graph.policy_eval import PolicyEvaluator
from cloudhunt.privesc import (
    detect_escalations,
    find_privesc_paths,
    is_admin_equivalent,
    neo4j_shortest_path_query,
    shortest_path,
)
from cloudhunt.privesc.catalogue import CREATE_POLICY_VERSION
from cloudhunt.privesc.pathfind import _compute_goals

ACCT = "111122223333"


def arn(kind: str, name: str) -> str:
    return f"arn:aws:iam::{ACCT}:{kind}/{name}"


@pytest.fixture(scope="module")
def cg(sample_dir):
    auth = IamAuthorization.from_file(sample_dir / "iam_auth" / "cloudgoat_privesc_01.json")
    graph = build_graph(auth)
    ev = PolicyEvaluator(auth)
    detect_escalations(auth, graph, ev)  # mutates graph with escalation edges
    paths = {p.principal: p for p in find_privesc_paths(auth, graph, ev)}
    return {"auth": auth, "graph": graph, "ev": ev, "paths": paths}


# --- single-technique, self-escalation to admin ---
def test_bilbo_create_policy_version(cg):
    p = cg["paths"][arn("user", "cg-bilbo")]
    assert p.techniques == ["CreatePolicyVersion"]
    assert p.length == 1
    assert p.target_priv == "admin-equivalent"


def test_selfadmin_attach_user_policy(cg):
    p = cg["paths"][arn("user", "selfadmin")]
    assert p.techniques == ["AttachUserPolicy"] and p.length == 1


def test_inliner_put_user_policy(cg):
    p = cg["paths"][arn("user", "inliner")]
    assert p.techniques == ["PutUserPolicy"] and p.length == 1


def test_dev_lambda_passrole_to_admin_role(cg):
    p = cg["paths"][arn("user", "dev-lambda")]
    assert p.techniques == ["PassRole:lambda"]
    assert p.target == arn("role", "lambda-admin")
    assert p.target_priv == "admin-equivalent"


# --- multi-hop chains ---
def test_analyst_assume_then_attach(cg):
    p = cg["paths"][arn("user", "analyst")]
    assert p.techniques == ["AssumeRole", "AttachRolePolicy"]
    assert p.length == 2 and p.target_priv == "admin-equivalent"
    # provenance: first hop lands on the ci-deployer role
    assert p.path[0].dst == arn("role", "ci-deployer")


def test_pivot_role_chaining(cg):
    p = cg["paths"][arn("user", "pivot")]
    assert p.techniques == ["AssumeRole", "AssumeRole"]
    assert p.path[0].dst == arn("role", "mid")
    assert p.path[1].dst == arn("role", "high")
    assert p.target_priv == "admin-equivalent"


def test_courier_reaches_sensitive_data(cg):
    p = cg["paths"][arn("user", "courier")]
    assert p.techniques == ["AssumeRole", "s3:GetObject"]
    assert p.target == "arn:aws:s3:::cg-secret"
    assert p.target_priv == "sensitive-resource:high"


# --- negative: a genuinely low-privilege user has no path ---
def test_readonly_has_no_path(cg):
    assert arn("user", "readonly") not in cg["paths"]
    goals = _compute_goals(cg["auth"], cg["ev"])
    assert shortest_path(cg["graph"], goals, arn("user", "readonly")) is None


# --- admin detection ---
def test_admin_roles_flagged_admin_equivalent(cg):
    ev = cg["ev"]
    assert is_admin_equivalent(ev, arn("role", "lambda-admin"))
    assert is_admin_equivalent(ev, arn("role", "high"))
    assert not is_admin_equivalent(ev, arn("user", "cg-bilbo"))


# --- edges are persisted + carry ATT&CK ids; Cypher parity exists ---
def test_escalation_edges_persisted_with_attack_ids(cg):
    edges = cg["graph"].edges_of("CAN_ESCALATE_VIA")
    assert edges, "expected CAN_ESCALATE_VIA edges in the graph"
    cpv = [e for e in edges if e.props.get("technique") == "CreatePolicyVersion"]
    assert cpv and cpv[0].props["attack_id"] == CREATE_POLICY_VERSION.attack_id
    # the projection serialises them too
    assert any("CAN_ESCALATE_VIA" in c for c, _ in cypher_statements(cg["graph"]))


def test_neo4j_shortest_path_query_is_available():
    q = neo4j_shortest_path_query()
    assert "shortestPath" in q and "CAN_ESCALATE_VIA" in q


# --- cross-check on the Milestone 2 fixture: assume-role -> sensitive data ---
def test_m2_fixture_cibot_reaches_crown_jewels(sample_dir):
    auth = IamAuthorization.from_file(sample_dir / "iam_auth" / "authz_snapshot_01.json")
    graph = build_graph(auth)
    ev = PolicyEvaluator(auth)
    detect_escalations(auth, graph, ev)
    paths = {p.principal: p for p in find_privesc_paths(auth, graph, ev)}
    p = paths[arn("user", "ci-bot")]
    assert p.techniques == ["AssumeRole", "s3:GetObject"]
    assert p.target == "arn:aws:s3:::acme-crown-jewels"
    assert p.target_priv == "sensitive-resource:high"
