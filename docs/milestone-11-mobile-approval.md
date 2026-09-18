# Milestone 11 — Mobile push approval

M11 changes where a human can approve an action; it does not change Milestone 6's decision authority. `ResponseEngine.run()` still decides `auto` versus `human`, and the hard `is_auto_eligible()` invariant remains the only auto-execution gate. M11 only observes `ResponsePlan.pending` and emits push notifications for those already-human-routed items.

## Flow

1. M6 produces a pending human action.
2. `CaseService` emits a push to active registered devices. The payload is exactly a notification type plus `case_id`; it contains no evidence, ARN, resource, action, user-agent, tags, request parameters, or summary text.
3. The authenticated mobile client resolves the case through the existing case and summary endpoints. `/cases/{case_id}/summary` therefore uses the M10 assistant when enabled and the M9 deterministic template when disabled.
4. An authorised analyst/admin requests a short-lived token for the pending action. The token is bound server-side to `case_id`, immutable `action_id`, and `action_key` and is stored only as a SHA-256 digest.
5. Mobile approve/deny calls the same `POST /cases/{case_id}/actions/{action_key}/approve` endpoint used by web. The existing RBAC and fresh `X-TOTP-Code` dependencies remain mandatory. Mobile additionally supplies `X-Approval-Channel: mobile` and `X-Approval-Token`.
6. Tokens are single-use and fail closed on expiry, replay, or scope mismatch. Approval, denial, and observed expiry are appended to the audit log with actor, channel, timestamp, and decision.

## API additions

- `POST /mobile/devices` — register the authenticated user's push device.
- `DELETE /mobile/devices/{device_id}` — revoke the authenticated user's device.
- `POST /cases/{case_id}/actions/{action_key}/approval-token` — obtain a scoped short-lived token for an already-pending M6 action.

There is deliberately no `/mobile/approve` endpoint and no mobile response executor.

## Approval endpoint

Existing web requests can continue to POST with RBAC + TOTP and no body. Mobile uses the same endpoint with `X-Approval-Channel: mobile` and a scoped token. An optional body `{ "decision": "deny" }` records denial without executing the action; omitted body defaults to approval for backward compatibility.
