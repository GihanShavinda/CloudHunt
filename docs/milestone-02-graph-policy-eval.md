# Milestone 2 — IAM Identity Graph & Offline Policy Evaluation

## What this milestone establishes

Turn a static IAM/Config snapshot into two things a responder can interrogate
without touching AWS:

1. an **identity graph** (principals, policies, resources; `hasPolicy`,
   `memberOf`, `canAssume`, `ownsResource`, plus `permissionBoundary`), and
2. an **offline policy-evaluation engine** that answers *what can principal X
   do?* and *who can perform action Y on resource Z?* — with explicit,
   machine-readable uncertainty where offline reasoning is incomplete.

This is the most upstream piece of the critical path (M2 → M3 privesc → M5
chains + blast radius). Everything above it depends on effective-permission
resolution being both correct and honest about its limits.

## Architecture

```
IAM/Config snapshot (JSON)
        │  authorization.IamAuthorization.from_dict   (parse + index)
        ▼
IamAuthorization ──► model.build_graph ──► IdentityGraph ──► neo4j_writer (projection)
        │
        ▼  policy_eval.PolicyEvaluator (offline)
   Decision / EffectivePermissions
        │
        ▼  query.what_can_principal_do / who_can_do
```

Two deliberate separations keep the design testable and faithful:

* **The graph is not the evaluator.** Effective-permission resolution is
  set-algebra over policy documents (Deny > Allow, NotAction, boundaries), *not*
  a graph traversal. The graph handles *reachability* (assume-role chains, group
  membership); the evaluator handles *permission semantics*. Conflating them is
  the classic mistake that produces subtly wrong "who can do X" answers.
* **Neo4j is a projection, not the source of truth.** `cypher_statements()` is a
  pure function returning `(cypher, params)` pairs (unit-tested with no DB); the
  live writer just runs them. Same pattern as the LocalStack source in M1.

## Evaluator semantics (what we DO model)

* Merge of **inline + attached-managed + group-inherited** policies for a
  principal (roles have no groups).
* **Explicit `Deny` beats any `Allow`** — checked first, across identity,
  permission boundary, and resource policy.
* **Permission boundaries** — an `Allow` requires a matching `Allow` in *both*
  the identity policy and the boundary; an explicit `Deny` in the boundary
  denies. (`bob` in the fixture: identity allows `iam:CreatePolicyVersion`, the
  `s3:*` boundary strips it, so the effective answer is deny.)
* **`NotAction` / `NotResource`** negation.
* **Action/resource wildcards** (`*`, `?`), case-insensitive actions,
  case-sensitive ARNs.
* **`canAssume` trust edges** parsed from role trust policies, with an
  **external-trust flag** for cross-account or `Principal: "*"` grants (backdoor
  detection groundwork for M7).
* Basic **same-account resource-policy** handling: explicit `Deny` honoured, a
  matching `Allow` can grant on its own; presence always flagged.

## Where offline evaluation diverges from AWS — and how we flag it

The engine is built to **over-approximate on the "reachable" side and never
silently under-report**: for a detection/response tool it is safer to make a
responder review a flagged superset than to hide a real permission. Every
divergence below is either surfaced on the `Decision` (`conditional`,
`boundary_limited`, `uncertainty[]`, `reasons[]`) or documented as systemic.

1. **Conditions are not evaluated.** `Condition` blocks depend on request-time
   context we don't have (MFA, `aws:SourceIp`, `aws:PrincipalTag`, dates, …). An
   `Allow` gated by a condition is returned as `ALLOW` with `conditional=True`
   and the condition keys listed; a would-be `Deny` under a condition is surfaced
   as a *potential* deny in `uncertainty[]` rather than applied. → We may report
   an allow AWS would deny at runtime, or miss a conditional deny. Both are
   flagged. (`erin`: read allowed *conditional on MFA*.)

2. **No action↔resource-type binding (cross-product over-approximation).** IAM
   evaluates the `Action` and `Resource` lists of a statement independently, so a
   statement with N actions and M resources grants all N×M pairs. We reproduce
   this faithfully — but AWS *additionally* rejects, at request time, actions
   applied to a resource type they don't operate on (e.g. `s3:GetObject` on an
   IAM policy ARN). We do **not** model the Service Authorization Reference, so
   `what_can_principal_do` can list combinations AWS would reject. This is
   over-approximation (safe direction): we never miss a real grant, but the
   concrete list may contain artifacts. (Seen in the demo:
   `deploy` shows `s3:GetObject` on `policy/deploy-policy`.)

3. **Resource-based policies are simplified.** We handle same-account explicit
   `Deny` and a basic principal-agnostic `Allow` path and always flag presence,
   but do not fully model cross-account principal matching, S3 bucket ACLs, or
   service-specific grant systems (KMS grants, Lambda resource policies, …). →
   Cross-account access decisions are low-confidence and flagged.

4. **No SCPs / RCPs / Organizations.** Single-account MVP. A Service Control
   Policy could deny something we report as allowed. Out of scope by design;
   noted here so the gap is explicit.

5. **No session policies.** Policies passed inline at `AssumeRole` time further
   restrict a session; we evaluate the role's own policies only. → We may
   over-report what an assumed-role session can do.

6. **Trust-principal expansion is coarse.** `arn:aws:iam::ACCT:root` means "any
   principal in ACCT"; we keep it as a single node rather than expanding to every
   principal. Federated/service principals and `ExternalId`-gated trust are only
   partially modelled. `Principal: "*"` is flagged external/backdoor.

7. **Policy variables and tag conditions are not resolved.** `${aws:username}`,
   `aws:ResourceTag/...`, etc. are treated as opaque; when present they land in
   the condition-uncertainty flag.

8. **Snapshot staleness.** The whole analysis is only as fresh as the snapshot;
   an unknown principal/resource is returned as `IMPLICIT_DENY` *with an
   uncertainty note*, never as a confident deny.

## Confidence posture, in one line

A `Decision` is only ever presented as a clean `ALLOW`/`DENY` when nothing on the
path was condition-gated, boundary-ambiguous, resource-policy-dependent, or
missing from the snapshot; otherwise the caveat travels *with* the result so M3–M7
(and the human approver) can weight it.

## Test coverage (answer key)

`tests/test_policy_matching.py`, `tests/test_policy_eval.py`,
`tests/test_graph_query.py` assert hand-verified outcomes over
`sample_data/iam_auth/authz_snapshot_01.json`: Deny>Allow (`carol`), boundary in
both directions (`bob`), NotAction (`dave`), conditional allow (`erin`), group
inheritance (`alice`), internal vs external trust, and both query shapes
(including "nobody can StopLogging — even admin, due to an explicit deny", and
indirect reach to the `deploy` role via `ci-bot`'s assume path).
