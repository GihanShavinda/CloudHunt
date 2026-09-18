"""Answer-key tests for the offline policy evaluator.

Each assertion below is a hand-verified expected outcome over
``sample_data/iam_auth/authz_snapshot_01.json``. Together they cover: attached
vs inline vs group-inherited policies, Deny > Allow, permission boundaries in
both directions, NotAction, unevaluated conditions, and wildcards.
"""

from __future__ import annotations

from cloudhunt.graph.policy_eval import Effect

# ARNs for the fixture (defined locally so the module needs no test-package import).
ACCT = "111122223333"
CROWN_OBJ = "arn:aws:s3:::acme-crown-jewels/customers.csv"
PUBLIC_OBJ = "arn:aws:s3:::acme-public-assets/report.pdf"
DEPLOY_POLICY = f"arn:aws:iam::{ACCT}:policy/deploy-policy"
TRAIL = f"arn:aws:cloudtrail:us-east-1:{ACCT}:trail/org-trail"


def arn(kind: str, name: str) -> str:
    return f"arn:aws:iam::{ACCT}:{kind}/{name}"


# --- alice: attached ReadOnlyS3 + group PutObject on public assets ---
def test_alice_can_read_crown_jewels(evaluator):
    d = evaluator.evaluate(arn("user", "alice"), "s3:GetObject", CROWN_OBJ)
    assert d.effect is Effect.ALLOW and not d.conditional


def test_alice_inherits_group_putobject(evaluator):
    d = evaluator.evaluate(arn("user", "alice"), "s3:PutObject", PUBLIC_OBJ)
    assert d.allowed
    assert any("group:developers" in m for m in d.matched)


def test_alice_cannot_put_to_crown_jewels(evaluator):
    d = evaluator.evaluate(arn("user", "alice"), "s3:PutObject", CROWN_OBJ)
    assert d.effect is Effect.IMPLICIT_DENY


def test_alice_cannot_escalate(evaluator):
    d = evaluator.evaluate(arn("user", "alice"), "iam:CreatePolicyVersion", DEPLOY_POLICY)
    assert d.effect is Effect.IMPLICIT_DENY


# --- bob: identity allows iam + s3, but boundary caps to s3 only ---
def test_bob_s3_allowed_within_boundary(evaluator):
    d = evaluator.evaluate(arn("user", "bob"), "s3:GetObject", CROWN_OBJ)
    assert d.allowed and d.boundary_limited


def test_bob_iam_blocked_by_boundary(evaluator):
    d = evaluator.evaluate(arn("user", "bob"), "iam:CreatePolicyVersion", DEPLOY_POLICY)
    assert d.effect is Effect.IMPLICIT_DENY
    assert d.boundary_limited
    assert any("boundary" in r for r in d.reasons)


# --- carol: admin, but explicit Deny on StopLogging wins ---
def test_carol_admin_allows_delete(evaluator):
    d = evaluator.evaluate(arn("user", "carol"), "s3:DeleteObject", CROWN_OBJ)
    assert d.allowed


def test_carol_explicit_deny_beats_admin(evaluator):
    d = evaluator.evaluate(arn("user", "carol"), "cloudtrail:StopLogging", TRAIL)
    assert d.effect is Effect.EXPLICIT_DENY
    assert any("Deny" in r for r in d.reasons)


# --- dave: NotAction Allow (everything except DeleteObject on public assets) ---
def test_dave_notaction_allows_other_actions(evaluator):
    d = evaluator.evaluate(arn("user", "dave"), "s3:GetObject", PUBLIC_OBJ)
    assert d.allowed


def test_dave_notaction_excludes_delete(evaluator):
    d = evaluator.evaluate(arn("user", "dave"), "s3:DeleteObject", PUBLIC_OBJ)
    assert d.effect is Effect.IMPLICIT_DENY


# --- erin: allow gated by an MFA condition we can't evaluate offline ---
def test_erin_allow_is_flagged_conditional(evaluator):
    d = evaluator.evaluate(arn("user", "erin"), "s3:GetObject", CROWN_OBJ)
    assert d.effect is Effect.ALLOW
    assert d.conditional is True
    assert any("MultiFactorAuthPresent" in u for u in d.uncertainty)


# --- deploy role: the privesc + read grants ---
def test_deploy_role_can_create_policy_version(evaluator):
    d = evaluator.evaluate(arn("role", "deploy"), "iam:CreatePolicyVersion", DEPLOY_POLICY)
    assert d.allowed


def test_deploy_role_can_read_crown_jewels(evaluator):
    d = evaluator.evaluate(arn("role", "deploy"), "s3:GetObject", CROWN_OBJ)
    assert d.allowed


# --- unknown principal is flagged, not silently denied ---
def test_unknown_principal_flagged(evaluator):
    d = evaluator.evaluate(arn("user", "nobody"), "s3:GetObject", CROWN_OBJ)
    assert d.effect is Effect.IMPLICIT_DENY
    assert d.uncertainty  # explicitly uncertain rather than a confident deny


# --- symbolic effective-permissions view ---
def test_effective_permissions_lists_boundary_and_denies(evaluator):
    ep = evaluator.effective_permissions(arn("user", "carol"))
    assert any(g.effect.lower() == "allow" for g in ep.allows)
    assert any(g.effect.lower() == "deny" for g in ep.denies)

    ep_bob = evaluator.effective_permissions(arn("user", "bob"))
    assert ep_bob.boundary is not None