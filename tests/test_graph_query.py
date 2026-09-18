"""Graph construction + the two query-API questions, against the answer key."""

from __future__ import annotations

from cloudhunt.graph.neo4j_writer import cypher_statements
from cloudhunt.graph.query import what_can_principal_do, who_can_do

# ARNs for the fixture (defined locally so the module needs no test-package import).
ACCT = "111122223333"
CROWN_OBJ = "arn:aws:s3:::acme-crown-jewels/customers.csv"
DEPLOY_POLICY = f"arn:aws:iam::{ACCT}:policy/deploy-policy"
TRAIL = f"arn:aws:cloudtrail:us-east-1:{ACCT}:trail/org-trail"


def arn(kind: str, name: str) -> str:
    return f"arn:aws:iam::{ACCT}:{kind}/{name}"


# --- graph structure ---
def test_graph_has_expected_edge_types(graph):
    kinds = {e.kind for e in graph.edges}
    assert {"HAS_POLICY", "MEMBER_OF", "CAN_ASSUME", "OWNS_RESOURCE", "PERMISSION_BOUNDARY"} <= kinds


def test_member_of_edge(graph):
    edges = graph.edges_of("MEMBER_OF")
    assert any(e.src == arn("user", "alice") and e.dst == arn("group", "developers") for e in edges)


def test_can_assume_internal_vs_external(graph):
    assume = {(e.src, e.dst): e.props.get("external") for e in graph.edges_of("CAN_ASSUME")}
    # ci-bot -> deploy is in-account
    assert assume[(arn("user", "ci-bot"), arn("role", "deploy"))] is False
    # 999988887777:root -> external-backup is cross-account (backdoor trust)
    ext_key = ("arn:aws:iam::999988887777:root", arn("role", "external-backup"))
    assert assume[ext_key] is True


def test_resource_sensitivity_tagged_on_nodes(graph):
    crown = graph.nodes["arn:aws:s3:::acme-crown-jewels"]
    assert crown.prop("sensitivity") == "high"


# --- "what can principal X do?" ---
def test_what_can_deploy_do_includes_privesc_and_read(evaluator):
    caps = what_can_principal_do(evaluator, arn("role", "deploy"))
    pairs = {(d.action, d.resource) for d in caps.concrete}
    assert ("iam:CreatePolicyVersion", DEPLOY_POLICY) in pairs
    assert any(a == "iam:CreatePolicyVersion" for a, _ in pairs)


def test_what_can_viewer_style_user_do_is_limited(evaluator):
    caps = what_can_principal_do(evaluator, arn("user", "ci-bot"))
    # ci-bot can only assume a role; it has no direct data/iam capability
    assert all(d.action == "sts:AssumeRole" for d in caps.concrete) or not caps.concrete


# --- "who can perform action Y on resource Z?" ---
def test_who_can_create_policy_version(evaluator):
    res = who_can_do(evaluator, "iam:CreatePolicyVersion", DEPLOY_POLICY)
    allowed = {d.principal for d in res.allowed}
    assert allowed == {arn("user", "carol"), arn("role", "deploy")}
    # bob is boundary-blocked -> neither allowed nor explicitly denied
    assert arn("user", "bob") not in allowed


def test_who_can_read_crown_jewels_includes_conditional(evaluator):
    res = who_can_do(evaluator, "s3:GetObject", CROWN_OBJ)
    allowed = {d.principal for d in res.allowed}
    assert {arn("user", "alice"), arn("user", "bob"), arn("user", "carol"),
            arn("user", "erin"), arn("role", "deploy")} <= allowed
    # erin's inclusion must be flagged conditional
    erin = next(d for d in res.allowed if d.principal == arn("user", "erin"))
    assert erin.conditional is True


def test_who_can_stop_logging_is_nobody_even_admin(evaluator):
    res = who_can_do(evaluator, "cloudtrail:StopLogging", TRAIL)
    assert res.allowed == []
    # carol (admin) shows up as an explicit denial, not an allow
    assert arn("user", "carol") in {d.principal for d in res.denied}


def test_who_can_with_assume_paths_finds_indirect_reach(evaluator, graph):
    res = who_can_do(evaluator, "iam:CreatePolicyVersion", DEPLOY_POLICY,
                     graph=graph, include_assume_paths=True)
    # ci-bot can assume deploy, which can create policy versions -> indirect reach
    assert (arn("user", "ci-bot"), arn("role", "deploy")) in res.via_assume


# --- Neo4j projection is pure + covers the graph ---
def test_cypher_projection_covers_nodes_and_edges(graph):
    stmts = cypher_statements(graph)
    assert len(stmts) == len(graph.nodes) + len(graph.edges)
    assert all(isinstance(c, str) and isinstance(p, dict) for c, p in stmts)
    assert any("CAN_ASSUME" in c for c, _ in stmts)