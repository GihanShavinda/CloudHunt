# Milestone 7 — Analyst dashboard & case workspace

## Goal

Give an analyst somewhere to *look*. No new detection, scoring or response logic —
this milestone is pure surface area over what Milestones 1–6 already produce: a
FastAPI read/act layer and a thin Angular UI that renders it.

Scope note: advanced detections (drift/backdoor/exfil) and the AI assistant are
**deliberately not here** — they're a later milestone. This is the small,
analyst-facing dashboard the brief asked for.

## Design principle: the UI is thin

Every number, path, and label the UI shows is computed server-side and shipped as
JSON. Angular renders it and does two things of its own: it draws the graph the
API already laid out, and it POSTs an approval. There is no detection, scoring,
graph-building or ranking in TypeScript — if you can compute it, compute it in
Python where it's tested.

## API layer (`cloudhunt.api`)

A `CaseService` (`casestore.py`) holds the built cases, their response plans
(auto-executed + pending), the shared audit log and the response engine.
`build_demo_service()` runs the whole offline pipeline on the sample scenario, so
the API serves a real correlated case with **no AWS and no database**.

Endpoints:

| Route | Who | Returns |
|-------|-----|---------|
| `GET /dashboard/summary` | any authed | cases-by-blast, sensitive-resource exposure, logging health, open-case count |
| `GET /cases` | any authed | ranked case list |
| `GET /cases/{id}` | any authed | workspace payload: chain, **graph elements**, timeline, ATT&CK map, recommended actions, audit |
| `POST /cases/{id}/actions/{key}/approve` | analyst/admin **+ TOTP** | approves a pending action via the M6 engine |
| `WS /ws/cases` | — | snapshot on connect, `case_updated` on approvals |

`graphview.py` turns a case into Cytoscape.js elements: the AssumeRole/activity
chain (solid edges) overlaid with the privilege-escalation paths behind the blast
score (red dashed edges). Pure and deterministic, so it's unit-testable.

## RBAC + MFA

Reads are open to any authenticated role (viewer+). Approving a pending action
reuses the Milestone-1 gate exactly: `require_role(administrator, cloud_analyst)`
**and** `require_totp` (a fresh second factor), then runs through the Milestone-6
response engine — so every approval is reversible and audited. The Angular UI
mirrors this (`AuthService.canApprove`) by hiding the approve control from
viewers, but the UI check is cosmetic; the server is the enforcement point.

## Angular app (`web/`)

Standalone components, Angular 17, no state library. `ng build` is clean.

* **Dashboard** — four widgets: cases by blast radius (bars, linking into the
  workspace), sensitive-resource exposure, logging-health status, and a live
  case feed over WebSockets.
* **Case workspace** — the interactive identity graph (Cytoscape.js), the
  evidence timeline, the ATT&CK coverage map, the recommended actions (with an
  MFA-gated approve control for analysts/admins), and the audit history.
* **GraphRenderer** — the one place that touches cytoscape, injectable so it's
  swapped for a fake in the component test. It draws exactly `case.graph`.
* **authGuard** bounces unauthenticated users to `/login`.

Run it: `make api` (uvicorn on :8000) and `make web` (ng serve on :4200); sign in
as `analyst` / `ChangeMe!Analyst1`.

## Tests

* **End-to-end dashboard smoke** (`tests/test_api_dashboard.py`, Python, runs in
  CI): drives the real API over the seeded `build_demo_service` and asserts the
  dashboard reflects the case end-to-end — ranked list, blast, logging health
  degraded (attacker stopped the trail), sensitive exposure, workspace payloads,
  the RBAC/MFA approval flow (viewer 403, analyst-without-TOTP 401,
  analyst-with-TOTP re-enables logging and health recovers), and the WS snapshot.
* **Component test — graph render** (`web/src/app/case/case.component.spec.ts`):
  feeds a seeded case-detail fixture through the workspace component with a fake
  renderer and asserts it hands the *server-provided* graph elements straight to
  the renderer (proving the thin-UI contract), plus the ATT&CK/timeline render
  and the RBAC + TOTP approve wiring. Standard Angular TestBed/Jasmine; run with
  `npm test` (needs Chrome). Verified here by a clean `ng build` and a clean
  `tsc -p tsconfig.spec.json`.

## Limitations / divergences

1. **WebSocket auth isn't enforced.** The feed is a read-only broadcast of the
   same case list; the approval path (the only privileged action) stays behind
   HTTP + RBAC + TOTP. Token-authenticating the socket is a small follow-up.
2. **Single demo service, in-memory.** Cases come from `build_demo_service`, not a
   live ingest loop or Postgres. Everything is wired behind interfaces from
   earlier milestones, so swapping the source is contained.
3. **UI RBAC is cosmetic.** The server enforces roles + MFA; the Angular checks
   only tidy the view.
4. **Component test needs a browser to execute.** It compiles/typechecks in CI;
   full execution is `npm test` on a machine with Chrome.
