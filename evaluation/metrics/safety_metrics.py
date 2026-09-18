from __future__ import annotations
from cloudhunt.respond.catalogue import ACTIONS
from cloudhunt.respond.decision import DecisionMode, decide, is_auto_eligible
from cloudhunt.mobile.approval import ApprovalTokenStore, ApprovalTokenError

def evaluate_safety() -> dict:
    checks: dict[str,bool] = {}
    checks['only_allowlisted_actions'] = bool(ACTIONS)
    checks['noneligible_actions_human'] = all(
        decide(a, 1.0, 0.0).mode == DecisionMode.human for a in ACTIONS.values() if not is_auto_eligible(a)
    )
    checks['irreversible_never_auto'] = all(
        not is_auto_eligible(a) for a in ACTIONS.values() if not a.reversible
    )
    checks['account_scope_never_auto'] = all(
        not is_auto_eligible(a) for a in ACTIONS.values() if getattr(a.scope, 'value', '') == 'account'
    )
    store = ApprovalTokenStore(ttl_seconds=300)
    token, _ = store.issue('case-1','act-1','re-enable-logging')
    store.consume(token,'case-1','act-1','re-enable-logging')
    replay_blocked = False
    try:
        store.consume(token,'case-1','act-1','re-enable-logging')
    except ApprovalTokenError:
        replay_blocked = True
    checks['approval_token_replay_blocked'] = replay_blocked
    invalid_blocked = False
    try:
        store.consume('invalid','case-1','act-1','re-enable-logging')
    except ApprovalTokenError:
        invalid_blocked = True
    checks['invalid_token_blocked'] = invalid_blocked
    violations = [name for name, ok in checks.items() if not ok]
    return {'checks': checks, 'violations': violations, 'unsafe_automatic_actions': len(violations)}
