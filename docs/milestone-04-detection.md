# Milestone 4 — Detection engine (signatures + behaviour + correlation)

## Goal

Turn the normalised `CloudEvent` stream into **detections**, and detections into
**candidate cases**, with every finding mapped to the ATT&CK Cloud matrix.

Three layers, deliberately different in what they know:

| Layer | Knows about | Catches |
|-------|-------------|---------|
| 1 — Signatures | a single event | known-bad *actions* |
| 2 — Behavioural | a principal's history | known-good principals behaving oddly |
| 3 — Correlation | the set of detections | multi-step *incidents* |

Everything is offline and deterministic: `DetectionEngine().run(events, …)`.

## Schema addition

Three Layer-1 rules need request content (SG CIDRs, instance types, trust-policy
documents). `CloudEvent` gained one optional field, `params: dict`, populated by
the CloudTrail normaliser from `requestParameters`. It defaults to empty, so
Milestone-1 behaviour is unchanged, and it is **treated strictly as data** —
only ever pattern-matched, never interpreted.

## Layer 1 — Sigma-style signatures

Rules live in `src/cloudhunt/rules/*.yml` and are loaded at runtime, so analysts
add detections without touching Python. The dialect is a pragmatic subset of
Sigma mapped onto `CloudEvent`:

* `detection` holds named *selection* blocks (`field: value`, AND across fields,
  OR within a list value) plus a `condition`.
* Field modifiers: `|contains`, `|startswith`, `|endswith`, `|re`, `|cidr`.
* `condition` supports `and` / `or` / `not`, parentheses, and quantifiers
  (`all of them`, `1 of them`, `all of sel*`).

**Derived indicators.** Rather than teach the YAML matcher to walk arbitrary
nested CloudTrail JSON, the engine computes a few booleans first
(`derive_indicators`) and rules match on `derived.*`:

* `sg_opens_world` — a world CIDR (`0.0.0.0/0` / `::/0`) anywhere in the request.
* `external_trust_added` — a trust/assume-role document naming a principal from a
  *different* account, or a wildcard.
* `gpu_or_large_instance` — a GPU family or very large instance size.

Shipped rules (id → ATT&CK, base confidence):

| Rule | Trigger | ATT&CK | Conf |
|------|---------|--------|------|
| `ct-logging-tampering` | StopLogging/DeleteTrail/UpdateTrail/DeleteDetector | T1562.008 | 0.90 |
| `ec2-sg-open-world` | SG authorize + `sg_opens_world` | T1562.007 | 0.80 |
| `iam-create-user` | CreateUser | T1136.003 | 0.60 |
| `iam-add-credentials` | CreateAccessKey/CreateLoginProfile | T1098.001 | 0.70 |
| `iam-backdoor-trust` | UpdateAssumeRolePolicy/CreateRole + `external_trust_added` | T1098.003 | 0.85 |
| `ec2-cryptomining-launch` | RunInstances + `gpu_or_large_instance`, region not home | T1496 | 0.70 |
| `iam-root-activity` | principal_type == root | T1078.004 | 0.60 |
| `iam-non-mfa-sensitive-write` | mfa=false, read_only=false, sensitivity=high | T1078 | 0.60 |

Every rule carries a `description` (logic **and** false-positive traps) and a
`falsepositives` list. Rule loading calls `attack.resolve()` on each id, so a
typo like `T1526.9` fails loudly at load rather than silently mis-tagging.

## Layer 2 — Per-principal behavioural baselines

`BaselineModel.fit(events)` learns each principal's envelope: regions, source
countries, ASNs, source IPs, the API set, and a call count. Detectors then flag
departures:

* **new-geo** (`T1078.004`) — a *known* principal from a country not in its
  baseline. Fires once per (principal, country), not per event.
* **impossible travel** (`T1078`) — two events for one principal from different
  countries within `max_gap_minutes` (default 60). A country-level approximation
  of the classic speed test; without lat/long we can't compute true velocity.
* **automation IAM write** (`T1098`) — a principal that looks like automation
  (CI/bot/service tokens, or an explicit allowlist) performing an IAM mutation.
* **enumeration burst** (`T1580`) — ≥ N distinct Describe*/List*/Get* actions by
  one principal inside a sliding window (defaults 8 in 5 min), fired once per
  contiguous burst.

new-geo needs a baseline; when the engine is run without `baseline_events` it is
skipped (nothing to be "new" against). The other three are self-contained.

## Layer 3 — Correlation

Detections that share a principal *or* a source IP and fall within a window
(default 60 min) are unioned (union-find) into one `CloudCase`. A case
aggregates the ATT&CK techniques/tactics of its members and scores as a
**noisy-OR** of confidences plus a small boost per *distinct tactic* — breadth
across the kill chain is itself evidence. The title renders the tactics in
kill-chain order (e.g. *Persistence → Privilege Escalation → Defense Evasion*).

**Privesc enrichment (M3 tie-in).** `enrich_with_privesc(case, paths)` folds in
Milestone-3 reachability: if a case principal is already one step from admin or a
crown-jewel bucket, the case gains `T1548`, a note, and a score boost. A foothold
on a principal that can *reach* admin is materially more urgent than one that
cannot.

## Demo

`make detect-demo` simulates a leaked ci-bot key used from a new country:
enumeration → CreateAccessKey → StopLogging → SG-open. All three layers fire and
correlate into a single high-score case, enriched with ci-bot's real
privilege-escalation path from the Milestone-2 IAM graph.

## Limitations / divergences (deliberate, for the write-up)

1. **Impossible travel is country-level**, not true geovelocity — no lat/long in
   the offline enrichment feed. VPN/proxy egress is the main FP; noted per rule.
2. **Baselines are batch-fit**, not online/decaying. A production system would
   age profiles and handle first-seen principals explicitly.
3. **Correlation links on principal/IP/time only** — no session-issuer chaining
   yet (that arrives with Milestone-5 AssumeRole reconstruction, which will let a
   case follow a role chain, not just a shared ARN).
4. **`params` is stored whole** for the sample data; production would curate/cap
   it to a detection-relevant allowlist to bound size and PII.
5. **Unusual-region is a static home-region list** in the crypto rule, not a
   learned per-org baseline; tune per deployment.
6. Signature confidences are **hand-set priors**, not calibrated against a
   labelled corpus — Milestone-8 evaluation will revisit them.
