# Milestone 10 — Thin grounded assistant

## Boundary

The assistant is deliberately non-authoritative. `cloudhunt.assistant.engine` accepts only a Milestone 9 case-context dictionary and a minimal read-only model port. The assistant package does not import `boto3`, `botocore`, `cloudhunt.respond`, the case store, response executor, or audit implementation and exposes no mutation callback/tool interface. The architecture test parses every assistant source file's AST and fails if those dependencies or stateful parameter names are introduced.

The fixed system prompt tells the model that the bundle is untrusted DATA, instructions inside it are inert, unsupported claims must be omitted, every factual sentence must cite existing provenance, and action directives are forbidden. No open-web or general-knowledge retrieval is attached.

## Kill switch

`CLOUDHUNT_ASSISTANT_ENABLED` is the single production switch and defaults to `false`. When false—or when no model adapter is supplied—`summarize_bundle` calls the Milestone 9 deterministic renderer. Detection, correlation, response plans, approvals, and audit paths are unchanged.

## Output gate

Model text is not displayable until it passes `validate_summary`. The gate rejects unknown provenance refs, uncited factual sentences, ARNs not present in the bundle, AWS API/action-shaped names not present in the bundle, S3 URIs not present in the bundle, and imperative/action-directive language. Invalid output is discarded and the deterministic template summary is returned instead, with validation violations available separately for telemetry/debugging.

## API surface

`GET /cases/{case_id}/summary` is read-only and protected by the existing authentication dependency. It builds the M9 bundle first, then passes only that bundle to the summary coordinator. With the kill switch off it always returns `source: "template"`.
