# Milestone 3 — Privilege-Escalation Analysis

## What this milestone adds

The M2 graph says who *holds* what. This milestone answers the attacker's
question: *from where I am, how do I become admin — or reach the data?* It does
that by deriving two new edge types and searching over them.

```
IdentityGraph (M2: HAS_POLICY, MEMBER_OF, CAN_ASSUME, OWNS_RESOURCE, ...)
      │  privesc.detect_escalations  (probes preconditions via the M2 evaluator)
      ▼
+ CAN_ESCALATE_VIA  principal -> admin-node | role   {technique, attack_id, conditional}
+ CAN_ACCESS        principal -> resource            {action, sensitivity, conditional}
      │  privesc.find_privesc_paths  (BFS shortest path)
      ▼
PrivEscPath(principal, techniques[], path[], target_priv)
```

The key design choice: **escalation edges are derived, not ingested.** Every edge
is produced by asking the Milestone 2 evaluator whether a principal can actually
perform a technique's trigger action on the right resource. This means all of
M2's correctness — Deny-beats-Allow, permission boundaries, condition flags —
flows straight into privesc detection for free. A boundary-blocked
`iam:CreatePolicyVersion` never becomes an edge; a condition-gated trigger
becomes an edge marked `conditional`, and that flag rides all the way out to the
final `PrivEscPath`.

## The technique catalogue

`privesc/catalogue.py` encodes the well-known AWS IAM privesc set (the Rhino
Security Labs lineage), each with a MITRE ATT&CK mapping for Milestone 4:

| Technique | Trigger (probed) | Target | ATT&CK |
|---|---|---|---|
| CreatePolicyVersion | `iam:CreatePolicyVersion` on a **self-attached** managed policy | admin | T1098.003 |
| AttachUserPolicy / AttachRolePolicy | attach a managed admin policy to self | admin | T1098.003 |
| PutUserPolicy / PutRolePolicy | inline an admin policy on self | admin | T1098.003 |
| PassRole:lambda / :ec2 | `iam:PassRole` a role the service trusts **and** launch it | role | T1548 |
| AssumeRole | trusted by **and** permitted to `sts:AssumeRole` a role | role | T1548 |

Role-chaining is just `AssumeRole` edges composed by the path search
(`pivot → mid → high`).

Two correctness notes worth calling out:

* **AssumeRole needs both sides.** M2's `CAN_ASSUME` edge is built from the
  target's *trust* policy alone (who *may* assume). An escalation edge is only
  emitted when the source *also* has the identity permission `sts:AssumeRole` on
  that role — the evaluator check. Trust without identity permission (or vice
  versa) is not a usable path.
* **CreatePolicyVersion is scoped to self-attached policies.** Being able to
  version *some other* policy escalates whoever that policy is attached to, not
  necessarily you; we only emit the self-escalation edge. (See limitations.)

## Path search

`find_privesc_paths` runs a breadth-first search over
`CAN_ESCALATE_VIA ∪ CAN_ACCESS`, returning the **shortest chain (fewest hops)**
from each principal to the nearest *goal*: the synthetic admin node, any
admin-equivalent principal, or any high-sensitivity resource. A principal that is
already admin is excluded as a source (nothing to escalate) but remains a goal,
so chains that land on an admin role terminate correctly.

`neo4j_shortest_path_query()` returns the equivalent Cypher (`shortestPath` over
`CAN_ESCALATE_VIA|CAN_ACCESS` to the admin node or any `sensitivity = 'high'`
node) so the same answer can be computed on the persisted graph. Python BFS is
the offline source of truth; the Cypher is for the live projection.

## The PrivEscPath record

```
PrivEscPath(
  principal    = "arn:aws:iam::…:user/analyst",
  target       = "admin:111122223333",
  target_priv  = "admin-equivalent",           # or "sensitive-resource:high"
  techniques   = ["AssumeRole", "AttachRolePolicy"],
  path         = [Hop(analyst → ci-deployer, AssumeRole),
                  Hop(ci-deployer → admin, AttachRolePolicy)],
  conditional  = False,                          # True if any hop is condition-gated
)
```

## Validation against a known-vulnerable config

`sample_data/iam_auth/cloudgoat_privesc_01.json` mirrors CloudGoat privesc
scenarios; `tests/test_privesc.py` asserts a hand-derived ground-truth path for
each principal:

| Principal | Ground-truth path | Hops | Target |
|---|---|---|---|
| cg-bilbo | CreatePolicyVersion | 1 | admin |
| selfadmin | AttachUserPolicy | 1 | admin |
| inliner | PutUserPolicy | 1 | admin |
| dev-lambda | PassRole:lambda → lambda-admin | 1 | admin |
| analyst | AssumeRole → AttachRolePolicy | 2 | admin |
| pivot | AssumeRole → AssumeRole (role-chain) | 2 | admin |
| courier | AssumeRole → s3:GetObject | 2 | sensitive (high) |
| readonly | — (no path) | — | — |

A cross-check on the M2 fixture confirms `ci-bot → assume deploy → GetObject` on
the high-sensitivity crown-jewels bucket — the thin-slice attack path from the
project scenario, now computed rather than asserted by hand.

## Limitations & how uncertainty propagates

* **Catalogue completeness.** Detection is only as complete as the catalogue.
  Not yet modelled: `iam:SetDefaultPolicyVersion` rollback without
  CreatePolicyVersion, `UpdateAssumeRolePolicy`, `CreateAccessKey` /
  `CreateLoginProfile` against another principal, `PassRole` to
  CloudFormation/Glue/DataPipeline, `lambda:UpdateFunctionCode` on an existing
  privileged function, group-based paths. These are additive edges for later.
* **Escalating *other* principals.** We emit self-escalation edges. Rewriting a
  policy attached to someone else (then using them) is a real chain we don't yet
  compose.
* **PassRole fidelity.** We check the PassRole permission, the role's service
  trust, and the launch action; we don't verify the EC2 instance-profile linkage
  or that a Lambda role is otherwise usable. Slight over-approximation.
* **Admin-equivalence heuristic.** "Admin" = an unconditional `*`/`iam:*` on
  `*`. A principal that is *effectively* admin through a narrower set may not get
  the admin label (it can still surface via sensitive-resource reach). Under-
  approximation on the label, flagged here.
* **Cost model.** Shortest = fewest hops, not weighted by technique difficulty or
  detection likelihood. Good enough for triage; a weighted search is future work.
* **Uncertainty flag.** Every edge inherits the evaluator's `conditional` flag
  from its trigger decision; `PrivEscPath.conditional` is the OR across hops and
  the summary marks conditional hops with `?`. So a chain that depends on, say, an
  MFA-gated assume is presented as *conditional*, never asserted as a sure thing —
  the same confidence posture as Milestone 2.
