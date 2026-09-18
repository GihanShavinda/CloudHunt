# Milestone 1 — Ingestion, Normalisation & Platform Auth

## What this milestone establishes

The **spine** of CloudHunt: a source-agnostic path from raw AWS telemetry to a
single normalised `CloudEvent`, plus the authenticated, role-gated surface that
every later milestone's actions sit behind. No detection yet — this is the
foundation everything else reads from.

## Key design decisions

**One schema, read by everything.** Detection, the graph, correlation and
response all consume `CloudEvent` and never a source-specific record. That single
indirection is what makes the platform extensible to new sources (and later,
other clouds) without touching downstream logic.

**Sources are thin; parsing is pure.** Each source yields `RawRecord`
(native-parsed dict + provenance + source tag). For the SQS/EventBridge/S3 path,
the *transport* (polling, S3 fetch) is separated from the *parsing*
(`iter_records_from_message`), so the interesting logic is unit-tested with
fixtures and a fake S3 reader — zero infrastructure required.

**Never scrape text.** Every record is parsed as JSON. CloudTrail's
`lookup_events` returns the event as a JSON *string*; we `json.loads` it rather
than pattern-matching. This is both correct and a security posture: structured
parsing removes a class of injection/So-called "log confusion" bugs.

**Normalise then enrich.** Structural mapping (fields) is separate from derived
enrichment (geo/ASN, sensitivity). An enrichment outage degrades to `unknown`
instead of dropping events — a reliability requirement, not a nicety.

**Event content is data, never instructions.** `user_agent`, tags and request
parameters are attacker-controlled. They are only ever stored/compared, never
interpreted. (This becomes load-bearing for the thin AI assistant in M7.)

**Idempotency at the pipeline, not the source.** CloudTrail delivers
at-least-once; `run()` de-dups on `source:event_id` so the guarantee holds
regardless of how an event arrived.

**Auth: JWT + RBAC + step-up MFA.** A login session is not sufficient to approve
a high-impact action; `require_totp` demands a fresh second factor per approval
request. RBAC is enforced *before* MFA so a Viewer is rejected without ever
touching the TOTP path.

## Deliberate scope cuts (revisited later)

- **In-memory user store** behind a `UserStore` protocol — Postgres implements
  the same interface in M6. Auth logic is identical either way.
- **LocalStack source** is implemented but not covered by offline unit tests
  (needs a running endpoint); the folder + SQS-parser paths give full offline
  coverage of the normalisation logic.
- **IAM/Config** is parsed for enrichment only; graph construction is M2.

## Test coverage

- CloudTrail normalisation of the saved attack-chain fixture (identity types,
  session/issuer capture, MFA-string→bool, target resolution, enrichment).
- GuardDuty finding normalisation (remote-IP lift, ASN normalisation, severity).
- SQS parser across all four envelope shapes + the missing-reader error path.
- Pipeline de-duplication under doubled delivery.
- Auth: login/JWT, RBAC (viewer denied / admin allowed), and the MFA gate
  (missing / wrong / valid TOTP).
