# Milestone 12 - Final Product Integration

P12 closes presentation, export, account/platform and production-adapter gaps without adding new detection algorithms.

## Integrated surfaces

- `GET /cases/{id}/summary` exposes the M10 grounded assistant result. If the assistant kill switch is off, no model is called and the M9 deterministic renderer is returned. If validation rejects AI output, the API returns `rejected=true`, the validation violations, and the deterministic fallback text.
- The Angular case workspace renders the returned summary and visibly marks rejected AI output. Angular never imports or invokes a model SDK.
- `GET /reports/cases/{id}.{json|csv|pdf}` produces deterministic case exports from existing case/context data only.
- `/mobile/case/:id` is a small mobile-friendly approval surface. It registers a device, resolves the case by authenticated API, requests a short-lived scoped token, and then calls the same `POST /cases/{case}/actions/{action}/approve` endpoint used by the web case view. `X-Approval-Channel: mobile`, TOTP and the M11 single-use token remain mandatory.
- Advanced M8 findings are returned in `advanced_detections` and surfaced by the dashboard/case workspace; no detection logic exists in Angular.

## Persistence hardening

Dev/tests deliberately remain deterministic and in-memory unless adapter URLs are configured. Docker Compose supplies production-style service URLs.

- PostgreSQL: `PostgresOperationalStore` creates and writes case snapshots, normalised event payloads and append-only audit projections when `CLOUDHUNT_DATABASE_URL` is set.
- Redis: `RedisApprovalTokenStore` stores short-lived approval tokens with TTL and consumes them atomically with `GETDEL`, providing replay protection across multiple API workers.
- Neo4j: the existing M2 `Neo4jWriter` remains the graph persistence adapter; P12 does not duplicate the IAM graph model or rewrite path logic.

In-memory stores remain valid test adapters and are intentionally preserved.

## Account/platform closure

- `POST /accounts` onboards the single MVP AWS account and role ARN; `PATCH /accounts/{id}/ingestion-health` exposes ingestion-health state.
- `/profile` returns the current profile, `/profile/password` provides authenticated password change, and the Administrator-only reset endpoint covers FR-1 without introducing email infrastructure.
- Multi-account AWS Organizations/SCP support remains explicitly out of scope.

## Running

Backend:

```bash
python -m venv .venv
# Windows: .venv\Scripts\activate
pip install -e ".[dev]"
python -m pytest
uvicorn cloudhunt.api.main:app --reload
```

Frontend:

```bash
cd web
npm ci
npm test -- --watch=false --browsers=ChromeHeadless
npm start
```

Full dev stack:

```bash
cp .env.example .env
docker compose up --build
```

For a host-run API using Docker backing services, use `localhost` in the Postgres/Redis/Neo4j URLs rather than the Compose service names.

## Prototype limitations before P13

The default seeded demo still builds one single-account scenario offline. Real push delivery uses the M11 gateway interface but no vendor FCM/APNs provider is bundled. The optional AI model implementation is deployment-injected and absent by default; therefore the safe deterministic summary is the normal out-of-box behavior. The project intentionally does not add AWS Organizations/SCP support in P12.
