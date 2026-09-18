# Milestone 9 — Grounded retrieval layer

Milestone 9 contains **no model/API calls**. `CaseContextBuilder` assembles the seeded/current case from CloudHunt's existing normalised events, detections and ATT&CK ids, reconstructed activity/AssumeRole chain, IAM privilege paths, blast-radius components, and locally stored response playbooks.

## Provenance contract
Every top-level evidence element carries `provenance`. Event references use the normalised `event_id`; graph hops reference their source/destination node ids; playbooks use stable `playbook_id` plus semantic version. A later assistant must cite these refs rather than inventing evidence.

## Sanitisation boundary
Attacker-controllable values are never interpolated into narrative text. They are wrapped as structured objects:

```json
{"tag":"DATA","field":"user_agent","value":"escaped text","truncated":false,"original_length":12}
```

`value` is HTML-escaped, control/newline characters are rendered visibly, and values are length-capped (512 characters by default). This applies to user agents, request parameters, resource/target names, tags, GuardDuty-originated strings, and detection evidence that may contain source-controlled values. Milestone 10 must consume attacker-controlled content only through these DATA objects.

## Playbook retrieval
`PlaybookStore` loads only `src/cloudhunt/playbooks/*.yml|yaml`. Retrieval is deterministic and indexed by detection key, ATT&CK id, and action name. There is no open-web or general-knowledge retrieval path.

## Non-AI fallback
`render_case_summary(bundle)` is a deterministic template renderer. It intentionally renders only trusted structural fields and provenance references; attacker-controlled DATA values are excluded from the narrative.
