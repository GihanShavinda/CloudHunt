# Milestone 6 — Response layer: scoped, reversible, audited

## Goal

Turn a ranked case into **action** — but only action that is scoped, reversible,
and audited, and only *auto* when it is provably safe to do so. Everything lives
in `cloudhunt.respond`. Try it: `make respond-demo`.

## Action catalogue (`catalogue.py`, `executor.py`)

Six containment actions, each declaring safety metadata (`impact`, `scope`,
`reversible`, `always_human`) and implementing `execute` + `undo`:

| Action | impact | scope | reversible | always human |
|--------|--------|-------|------------|--------------|
| deactivate-access-key | low | principal | yes | **no** |
| quarantine-principal (deny-all) | high | principal | yes | yes |
| revoke-sessions | medium | principal | yes | yes |
| isolate-instance (quarantine SG) | high | resource | yes | yes |
| re-enable-logging (StartLogging) | medium | account | yes | yes |
| snapshot-forensics | low | resource | yes | yes |

Actions never call boto3 directly. They go through an `ActionExecutor` — a narrow,
semantic surface (deactivate a key, put/delete an inline policy, swap an
instance's SGs, start/stop a trail, create/delete a snapshot). Two
implementations behind that one interface:

* `Boto3ActionExecutor` — real AWS, or LocalStack via an `endpoint_url` override
  (cost-free dev). No `shell=True`, no credentials in code.
* `FakeActionExecutor` — in-memory state mirroring the same surface, so the whole
  layer is testable offline.

`execute` returns an `Outcome(before, after, undo_ref)`; `undo` consumes the
`undo_ref` to restore the prior state. Reversibility is therefore **exercised, not
asserted** — `test_respond_actions.py` executes then undoes every action and
checks the world is back.

## Decision engine (`decision.py`)

The rule: an action may auto-run *only if* it is low-impact AND reversible AND
single-principal AND high-confidence. That splits into two gates:

1. **Metadata gate** — `is_auto_eligible(action)` =
   `reversible and impact==LOW and scope==PRINCIPAL and not always_human`.
   A property of the action alone. This is what makes an irreversible or org-wide
   action impossible to auto-run *no matter what the situation looks like*.
2. **Dynamic gate** — only reached if (1) passes: confidence ≥ threshold (0.8),
   and the action must not touch a high-sensitivity resource.

Blast radius and resource sensitivity are folded in as inputs — recorded on the
decision and used for queue `priority` — but they can only make the engine *more*
cautious, never override a gate. By this definition exactly **one** catalogue
action (deactivate-access-key) is ever auto-eligible; the rest are human-gated by
construction.

`propose_actions(case)` maps the reconstructed chain to concrete proposals:
leaked-key use → deactivate key; privilege escalation → quarantine; `StopLogging`
→ re-enable logging; resource hijacking → isolate instance.

## Orchestration + audit (`engine.py`, `audit.py`)

`ResponseEngine.run(case)` plans, auto-executes the eligible actions, and holds
the rest in `plan.pending`. `approve(item, Approval(...))` executes a pending
action — but only with a **verified MFA second factor** and an authorised role
(the FastAPI endpoint from Milestone 1 supplies `mfa_verified` only after
validating TOTP). `undo(record, actor)` reverses an action from its `undo_ref`.

Every execution — auto, approved, or undo — writes an `AuditRecord`
(before/after/undo_ref, decision, approver, case) to an **append-only** log
(`InMemoryAuditLog` for dev/tests, `JsonlAuditLog` for a real append-only file;
Postgres in production behind the same interface). An undo is a new record
pointing back at the original via `parent_id` — history is never rewritten.

### The hard safety invariant

Beyond the decision engine, `ResponseEngine._execute` re-checks
`is_auto_eligible` on the auto path and raises `ResponseSafetyError` otherwise.
So even a bug in the decision logic cannot cause an irreversible or org-wide
action to auto-execute — `test_engine_refuses_forced_auto_of_human_action` forces
exactly that and asserts it raises.

## Safety tests (the milestone's point)

`test_respond_decision.py` proves:

* exactly one action is auto-eligible, and under *ideal* signals (confidence 1.0,
  blast 0, low sensitivity) only that one decides `auto`;
* a synthetic irreversible action is never auto-eligible and always decides human;
* org-wide / always-human actions stay human even under ideal signals;
* the one auto action still drops to human on low confidence or high-sensitivity;
* forcing an auto-exec of a human action raises `ResponseSafetyError`;
* approval requires MFA and an authorised role;
* `run()` auto-executes only the eligible action and leaves the rest pending.

`test_respond_actions.py` proves every action round-trips execute → undo.

## Limitations / divergences (deliberate)

1. **Access-key id resolution.** `CloudEvent` doesn't carry the CloudTrail
   `accessKeyId`, so deactivate-key falls back to disabling *all* active keys for
   the user. Threading the specific key id through ingest is a small future field.
2. **Approval state isn't persisted.** Pending items live in the returned plan;
   wiring them to the MFA-gated API endpoint + a Postgres case store is the
   Milestone-7 integration. The engine and audit interfaces are ready for it.
3. **Executor scope is enforced by convention + the deploy-time role.** The code
   only ever calls the narrow method set; the least-privilege cross-account IAM
   policy that backs it is an infra artifact, not in this repo.
4. **`revoke-sessions` targets roles** (token-issue-time deny). User-session
   revocation is out of scope for the MVP.
