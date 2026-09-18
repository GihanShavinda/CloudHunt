# Milestone 5 — Correlated case: chain + blast radius + ranking

## Goal

Turn a Milestone-4 correlated *cluster* of detections into a single, ranked,
**explainable** case: one ordered attack chain, a blast-radius score, and a
triage-queue rank. This is the first end-to-end slice — `make case-demo`.

Everything lives in `cloudhunt.correlate` (distinct from `detect.correlate`,
which is the Layer-3 linker that produces the raw clusters).

## 1. Attack-chain reconstruction (`chain.py`)

Input is a `CloudCase` plus the events behind it. The reconstruction works over
**events, not detections**, because the pivotal steps of a chain — the
`AssumeRole` itself, the object reads — are frequently *not* detections on their
own but are the connective tissue of the story:

    key-abuse -> AssumeRole -> privesc -> discovery -> S3 exfil -> StopLogging

Steps:

1. **Select** events belonging to the case (principal ∈ case, or resolved actor
   ∈ case, or shared source IP) within the case time span (+pad).
2. **Attribute** each event to the acting identity, resolving an assumed-role
   session back to its issuing role via `session.issuer_arn`. This is what makes
   the pivot visible: `AssumeRole` is *by ci-bot*, everything after is *by deploy*.
3. **Order** chronologically. Chronology is the causal order here; ATT&CK tactic
   rank only breaks exact-time ties.
4. **Collapse** consecutive same-actor discovery reads (`Describe*/List*/Get*`,
   excluding `GetObject`) into one `Discovery (N reads)` step, so a recon spray is
   one line, not twenty.
5. **Explain over the graph** — annotate steps with the edge that realises them:
   `AssumeRole` → `CAN_ASSUME`, S3 access → `CAN_ACCESS`, self-grant → `CAN_ESCALATE_VIA`.

Each step also carries the detection keys that fired on its event, so the chain
links back to its evidence.

## 2. Blast-radius scorer (`blast.py`)

    blast(p) = w1*reach_sensitive + w2*reach_admin + w3*privesc_available
             + w4*current_privilege                          (scaled to 0..100)

Defaults `w1=w2=0.30`, `w3=w4=0.20`. Each term is in `[0,1]`:

* **reach_sensitive / reach_admin** — is a high-sensitivity resource / an
  admin-equivalent identity reachable from `p` over the escalation graph? Reuses
  the Milestone-3 BFS with goal-filtered searches.
* **privesc_available** — is reaching admin an *escalation* (≥ 1 hop), rather
  than already being admin?
* **current_privilege** — graded capability the principal already holds:
  admin ⇒ 1.0; otherwise `read_sensitive` (0.5) + `iam_write` (0.3) +
  `can_assume` (0.2), capped at 1.0.

**Explainability is a first-class output, not a log line.** The returned
`BlastRadius` carries the actual admin and sensitive **graph paths** (as
Milestone-3 `PrivEscPath`s) and the current-privilege capabilities that produced
the number, and `explanation()` prints the per-term contributions plus those
paths. An analyst sees *why* a score is 46, not just that it is.

## 3. Case assembly + queue ranking (`case.py`)

`build_case` binds cluster + chain + blast:

* Blast is scored for **every real identity the case touches** (chain actors ∪
  case principals, intersected with known principals); the case inherits the
  **worst-case** radius — a foothold is as dangerous as the most dangerous
  identity it reaches.
* Queue rank blends impact with certainty:

      rank = alpha * (blast / 100) + beta * detection_confidence      (alpha=0.6, beta=0.4)

  where `detection_confidence` is the Milestone-4 correlated case score.
  `rank_cases` sorts the queue descending.

`prepare_graph(auth)` is the one-call setup: build the graph, evaluator,
escalation edges, and privesc paths.

## Validation

`tests/test_correlate_case.py` drives the headline requirement: a multi-detection
scenario (new-geo on the key + logging-tampering on the session) collapses to
**one** case whose chain is exactly

    ListBuckets -> AssumeRole -> CreatePolicyVersion -> Discovery(2) -> GetObject -> StopLogging

with tactics Discovery → Privilege Escalation → Privilege Escalation → Discovery
→ Collection → Defense Evasion, session steps attributed to `role/deploy`, blast
components summing to the score, and rank matching the formula. A second test
runs the real `attack_chain_01.json` fixture end-to-end through the ingest
pipeline.

## Limitations / divergences (deliberate)

1. **Selection is principal/IP/time**, not yet a strict `session.issuer` walk —
   an attacker who deliberately changes source IP *and* assumes across a gap
   longer than the correlation window could split a chain. The issuer resolution
   is in place; tightening selection to follow issuer links across windows is a
   refinement.
2. **Chronology-as-causality** is a strong heuristic. Two truly independent
   actors sharing an IP (NAT/VPN) could be stitched together; the source-IP link
   is the main false-merge risk (same trap flagged in M4).
3. **Blast is unweighted by resource count** — one crown-jewel bucket and ten
   score the `reach_sensitive` term identically. A future version can scale by
   count/severity of reachable resources.
4. **current_privilege capabilities are coarse** (three flags). They are
   explainable by design; calibration against real environments is Milestone-8.
5. **Weights are hand-set priors.** Both `Weights` and `RankWeights` are
   dataclasses so an operator can tune them per environment.
