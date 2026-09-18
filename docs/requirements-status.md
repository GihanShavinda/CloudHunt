# Functional Requirement Status (FR-1 - FR-25)

| FR | Status | Implementation |
|---|---|---|
| FR-1 registration/login/password reset/profile | Implemented for capstone scope | `api/auth.py`, `api/profile.py`, `api/store.py` |
| FR-2 TOTP MFA for approvals | Implemented | `api/deps.py`, `core/security.py`, case approval endpoint |
| FR-3 Administrator / Cloud Analyst / Viewer RBAC | Implemented | `models/user.py`, `api/deps.py` |
| FR-4 AWS account onboarding + ingestion health | Implemented, single-account MVP | `api/accounts.py` |
| FR-5 CloudTrail ingest/backfill | Implemented | `ingest/`, `normalise/cloudtrail.py` |
| FR-6 VPC/GuardDuty correlation | GuardDuty implemented; VPC-flow depth remains prototype-limited | `ingest/guardduty.py`, normalisers/detection pipeline |
| FR-7 IAM/Config snapshots | Implemented | `ingest/iam_config.py`, graph builder |
| FR-8 unified event schema/enrichment | Implemented | `models/events.py`, `normalise/` |
| FR-9 IAM graph | Implemented | `graph/model.py`, `graph/neo4j_writer.py` |
| FR-10 offline IAM policy evaluation | Implemented | `graph/policy_eval.py` |
| FR-11 privilege-escalation paths | Implemented | `privesc/` |
| FR-12 reconstructed attack/AssumeRole chain | Implemented | `correlate/chain.py`, Angular Cytoscape workspace |
| FR-13 ATT&CK Cloud mapping | Implemented | `detect/attack.py`, case ATT&CK view |
| FR-14 blast reachability | Implemented | `correlate/blast.py` |
| FR-15 0-100 blast score | Implemented | `correlate/blast.py` |
| FR-16 blast/confidence queue ranking | Implemented | `correlate/case.py`, dashboard |
| FR-17 grounded case assistant | Implemented, optional model injection | `retrieval/`, `assistant/`, case summary UI |
| FR-18 assistant never writes AWS + kill switch | Implemented/tested | isolated `assistant/`, `CLOUDHUNT_ASSISTANT_ENABLED` |
| FR-19 response catalogue | Implemented | `respond/catalogue.py`, `respond/executor.py` |
| FR-20 validated/risked recommendations | Implemented | response catalogue/decision + versioned playbooks |
| FR-21 Auto vs Human decision authority | Implemented | `respond/decision.py`, `respond/engine.py` |
| FR-22 reversible response + append-only audit | Implemented | `respond/`, Postgres/JSONL/in-memory audit paths |
| FR-23 real-time dashboard/WebSocket feed | Implemented | `api/dashboard.py`, `api/feed.py`, Angular dashboard |
| FR-24 case workspace | Implemented | Angular `case.component.ts`, graph renderer |
| FR-25 JSON/CSV/PDF reporting + mobile approval | Implemented at capstone/prototype level | `api/reports.py`, `reporting.py`, M11/P12 mobile view |

## Advanced scope already implemented

P8 implements granted-but-unused permission drift, new privesc path drift, trust-policy backdoors and S3 exfiltration analytics. P9-P10 provide a provenance-grounded retrieval/sanitisation layer and optional non-authoritative assistant. P11-P12 provide mobile approval integrity and presentation.
