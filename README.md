# CloudHunt

Agentless AWS Cloud Threat Detection & Response with IAM privilege-escalation
path analysis. Ingest CloudTrail / GuardDuty / IAM-Config, normalise into one
schema, model IAM as a graph, detect credential abuse and privilege escalation,
reconstruct AssumeRole chains, score blast radius, and contain with scoped,
reversible, human-approved actions.

## Status — implemented through Milestone 12 (P12)

CloudHunt now includes the complete single-account capstone pipeline: ingestion/normalisation, IAM graph + offline policy evaluation, privesc paths, three-layer detections, attack-chain reconstruction, blast-radius ranking, reversible response with human approval, Angular dashboard/case workspace, advanced drift/trust/S3 analytics, grounded retrieval, optional thin AI, mobile approval, deterministic JSON/CSV/PDF reporting, and optional Postgres/Redis/Neo4j production adapters. P13 is the remaining evaluation harness.

See `docs/requirements-status.md` for FR-1 through FR-25 traceability and `docs/milestone-12-final-integration.md` for P12 details.

### Milestone 1 (P1): ingestion + normalisation + platform auth

Implemented:

- **Unified `CloudEvent` schema** — the record every source normalises into.
- **Agentless CloudTrail ingestion, three sources behind one interface:**
  LocalStack (`boto3 lookup_events`), a folder of sample `Records[]` files, and
  the S3-delivery / EventBridge→SQS shape (native JSON parsing throughout).
- **GuardDuty** findings ingestion + normaliser; **IAM/Config** snapshot parsing
  (feeds enrichment now; builds the graph in M2).
- **Enrichment** — geo/ASN (pluggable, offline in dev) and resource sensitivity
  from tags.
- **Platform auth** — FastAPI + JWT, RBAC (Administrator / Cloud Analyst /
  Viewer), and a TOTP MFA gate on approval endpoints.

## Status — Milestone 2 (P2): IAM identity graph + offline policy evaluation

Implemented:

- **Identity graph builder** (`cloudhunt.graph.build_graph`) — principals,
  policies, resources; `HAS_POLICY`, `MEMBER_OF`, `CAN_ASSUME` (with an
  **external-trust** flag), `OWNS_RESOURCE`, `PERMISSION_BOUNDARY`. Sensitivity
  tags carried onto principal/resource nodes.
- **Offline policy evaluator** (`PolicyEvaluator`) — merges attached + inline +
  group policies, applies **explicit Deny > Allow**, honours **NotAction** and
  **permission boundaries**, and flags **conditions** it cannot evaluate offline.
- **Query API** — `what_can_principal_do(...)` and `who_can_do(...)` (with
  optional assume-role reach).
- **Neo4j projection** — pure `cypher_statements(graph)` + a lazy-driver writer.

Divergences from AWS and how uncertainty is flagged:
`docs/milestone-02-graph-policy-eval.md`. Try it: `make eval-demo`.

## Status — Milestone 3 (P3): privilege-escalation analysis

Implemented:

- **Escalation-edge detector** (`cloudhunt.privesc.detect_escalations`) for the
  known privesc catalogue — `iam:CreatePolicyVersion` (self-attached),
  `iam:AttachUserPolicy` / `iam:PutUserPolicy` (and role variants),
  `iam:PassRole` + Lambda/EC2 launch, and `sts:AssumeRole` role-chaining. Each
  precondition is probed through the M2 evaluator, so boundaries and conditions
  are honoured; firings become `CAN_ESCALATE_VIA` edges (with ATT&CK tags).
- **Sensitive-data reach** — `CAN_ACCESS` edges from principals to
  high-sensitivity resources.
- **Shortest-path search** (BFS) from any principal to admin-equivalent or a
  sensitive resource, plus the equivalent Neo4j `shortestPath` Cypher.
- **`PrivEscPath` record** — principal, technique[], path[], target_priv —
  validated against a CloudGoat-mirror fixture with hand-verified ground truth.

Design + limitations: `docs/milestone-03-privesc.md`. Try it: `make privesc-demo`.

## Status — Milestone 4 (P4): detection engine + ATT&CK mapping

Three layers over the normalised `CloudEvent` stream, every finding tagged to
ATT&CK Cloud:

- **Layer 1 — Sigma-style signatures** (`cloudhunt.detect.SignatureEngine`),
  loaded from `src/cloudhunt/rules/*.yml`: logging tampering, security-group
  opened to `0.0.0.0/0`, persistence (new user / credentials / backdoor trust),
  crypto-mining launches in unusual regions, root activity, non-MFA sensitive
  writes. Field modifiers (`contains/startswith/re/cidr`), a condition parser,
  and derived indicators for the deep-parameter rules.
- **Layer 2 — behavioural baselines** (`cloudhunt.detect.BehaviouralEngine`):
  per-principal region/geo/ASN/API profiles → new-geo credential use, impossible
  travel, automation principals doing IAM writes, Describe*/List* enumeration
  bursts.
- **Layer 3 — correlation** (`cloudhunt.detect.correlate`): links detections by
  shared principal / source IP / temporal proximity into scored `CloudCase`s,
  with an optional Milestone-3 privilege-escalation enrichment.

A one-line optional field (`CloudEvent.params`) was added to carry request
parameters for detection; it defaults to empty and is treated strictly as data.

Design + limitations: `docs/milestone-04-detection.md`. Try it: `make detect-demo`.

## Status — Milestone 5 (P5): correlated case — chain + blast radius + ranking

The first full end-to-end slice. Takes the Milestone-4 correlated clusters and
turns each into one ranked, explainable case (`cloudhunt.correlate`):

- **Attack-chain reconstruction** (`reconstruct_chain`): stitches the events
  behind a case into one ordered chain — key-abuse → AssumeRole → privesc →
  discovery → S3 exfil → StopLogging — resolving assumed-role sessions back to
  their issuing role, collapsing discovery sprays, and annotating each step with
  the graph edge (`CAN_ASSUME` / `CAN_ACCESS` / `CAN_ESCALATE_VIA`) that realises it.
- **Blast-radius scorer** (`score_blast`, 0–100):
  `w1*reach_sensitive + w2*reach_admin + w3*privesc_available + w4*current_privilege`.
  The returned `BlastRadius` carries the actual graph paths and capabilities
  behind the number (explainability is an output, not a log line).
- **Queue ranking** (`build_cases` / `rank_cases`):
  `rank = alpha*blast + beta*detection_confidence`, worst-case identity per case.

Design + limitations: `docs/milestone-05-correlation.md`. Try it: `make case-demo`.

## Status — Milestone 6 (P6): response layer — scoped, reversible, audited

Turns a ranked case into containment action (`cloudhunt.respond`):

- **Action catalogue** via a scoped executor (`Boto3ActionExecutor`, LocalStack-
  capable; `FakeActionExecutor` for offline tests): deactivate access key,
  quarantine principal (explicit deny), revoke sessions, isolate EC2 instance
  (quarantine SG), re-enable CloudTrail logging, snapshot for forensics. Every
  action implements `execute` + `undo` and returns before/after + undo_ref.
- **Decision engine**: `is_auto_eligible` + `decide` combine reversibility,
  impact, scope, confidence and sensitivity. Only reversible + low-impact +
  single-principal + high-confidence auto-runs (deactivate key); quarantine,
  isolation, re-enable-logging, and anything irreversible/org-wide always require
  human approval. A hard invariant in `ResponseEngine` makes auto-execution of
  anything else impossible even if the decision logic were buggy.
- **Human approval** is MFA-gated (M1 TOTP endpoint); **every** action — auto,
  approved, or undo — writes to an append-only audit log (in-memory / JSONL now,
  Postgres in prod).

Safety proofs: `tests/test_respond_decision.py` (nothing dangerous can auto-run)
and `tests/test_respond_actions.py` (every action reverses).

Design + limitations: `docs/milestone-06-response.md`. Try it: `make respond-demo`.

## Milestones 7-12 summary

- **P7:** Angular dashboard/case workspace, Cytoscape graph, WebSocket feed and web approval.
- **P8:** least-privilege drift, new-privesc-path, trust-policy backdoor and S3 exfiltration analytics.
- **P9:** provenance-complete case context, local versioned playbook retrieval, sanitisation boundary and deterministic fallback summary.
- **P10:** optional grounded assistant, kill switch and output validation; no AWS/write capability.
- **P11:** mobile push approval integrity, device registration/revocation and single-use action-scoped tokens.
- **P12:** summary UI integration, JSON/CSV/PDF reporting, mobile-friendly approval view, advanced-detection surfacing, account/profile closure and optional production persistence adapters.

**Next:** P13 evaluation harness (CloudGoat/stratus-red-team replay + quantitative metrics).

## Quickstart (no cloud, no cost)

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

pytest                              # run the test suite
python scripts/ingest_demo.py      # normalise the sample CloudTrail chain
python scripts/ingest_demo.py guardduty
uvicorn cloudhunt.api.main:app --reload   # API at http://localhost:8000/docs
```

Dev accounts (seeded only when `CLOUDHUNT_ENV=dev`): `admin`, `analyst`,
`viewer` — passwords in `src/cloudhunt/api/store.py`, for local use only.

## Layout

```
src/cloudhunt/
  core/        config + security (bcrypt, JWT, TOTP)
  ingest/      sources: folder, sqs, localstack, guardduty, iam_config
  normalise/   source -> CloudEvent, enrichment, pipeline
  models/      CloudEvent schema, User/RBAC
  api/         FastAPI auth, cases, dashboard, mobile, reports, account/profile APIs
  graph/ detect/ privesc/ correlate/ respond/ rules/   security pipeline
  retrieval/ assistant/ playbooks/                    grounded explanation layer
  mobile/ reporting.py persistence.py                  P11/P12 integration
sample_data/   cost-free fixtures: the leaked-key -> privesc -> S3 chain
tests/         normalisation + ingestion + auth
docs/          design notes
```


## Final Evaluation (P13)

Run the offline evaluation with `python evaluation/run_evaluation.py`. Run the reproducible final demo with `python scripts/run_final_demo.py`. Execute evaluation tests with `pytest tests/evaluation -v` and the full repository with `pytest -v`. P13 requires no real AWS credentials; generated reports are written to `evaluation/reports/`.
