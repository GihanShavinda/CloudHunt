"""The decision engine — Auto vs Human approval.

The rule the brief fixes: an action may auto-run *only* if it is low-impact AND
reversible AND single-principal AND high-confidence. Quarantine, isolation,
re-enable-logging, and anything irreversible or org-wide ALWAYS require a human.

That decomposes into two gates:

1. **Metadata gate** (:func:`is_auto_eligible`) — a property of the action alone:
   ``reversible and impact==LOW and scope==PRINCIPAL and not always_human``. This
   is what guarantees an irreversible or org-wide action can *never* auto-run,
   regardless of how confident or low-blast the situation looks.
2. **Dynamic gate** — only reached if the metadata gate passes: confidence must
   clear the threshold and the action must not touch a high-sensitivity resource.

Blast radius and resource sensitivity are folded in as inputs (recorded on the
decision and used for queue ``priority``); they can only ever make the engine
*more* cautious, never override a safety gate.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from cloudhunt.respond.catalogue import ACTIONS, Action, ActionTarget, Impact, Scope


class DecisionMode(str, Enum):
    auto = "auto"
    human = "human"


@dataclass
class DecisionPolicy:
    conf_threshold: float = 0.8
    high_sensitivity_blocks_auto: bool = True


@dataclass
class Decision:
    action_key: str
    mode: DecisionMode
    reasons: list[str] = field(default_factory=list)
    priority: float = 0.0


@dataclass
class ProposedAction:
    action_key: str
    target: ActionTarget
    resource_sensitivity: str = "low"
    rationale: str = ""
    techniques: list[str] = field(default_factory=list)


def is_auto_eligible(action: Action) -> bool:
    """Metadata-only gate. The single source of truth for 'may this auto-run?'."""
    return (action.reversible
            and action.impact == Impact.low
            and action.scope == Scope.principal
            and not action.always_human)


def decide(
    action: Action,
    confidence: float,
    blast: float,
    resource_sensitivity: str = "low",
    policy: Optional[DecisionPolicy] = None,
) -> Decision:
    policy = policy or DecisionPolicy()
    reasons: list[str] = []
    mode = DecisionMode.human

    if not is_auto_eligible(action):
        if action.always_human:
            reasons.append("action always requires human approval")
        if not action.reversible:
            reasons.append("action is irreversible")
        if action.scope != Scope.principal:
            reasons.append(f"scope '{action.scope.value}' is not single-principal")
        if action.impact != Impact.low:
            reasons.append(f"impact '{action.impact.value}' exceeds low")
    elif confidence < policy.conf_threshold:
        reasons.append(f"confidence {confidence:.2f} < threshold {policy.conf_threshold:.2f}")
    elif policy.high_sensitivity_blocks_auto and resource_sensitivity == "high":
        reasons.append("action would affect a high-sensitivity resource")
    else:
        mode = DecisionMode.auto
        reasons.append(
            f"reversible low-impact single-principal action with "
            f"confidence {confidence:.2f} >= {policy.conf_threshold:.2f}")

    priority = round(min(100.0, blast + (10 if resource_sensitivity == "high" else 0)), 1)
    reasons.append(f"inputs: blast={blast:.0f}, sensitivity={resource_sensitivity}")
    return Decision(action_key=action.key, mode=mode, reasons=reasons, priority=priority)


# --- planning: map a case's chain/techniques to concrete proposed actions ---

_PRIVESC_TIDS = {"T1098", "T1098.001", "T1098.003"}
_KEY_ABUSE_TIDS = {"T1548", "T1078", "T1078.004"}


def _name_from_arn(arn: str) -> str:
    return arn.split("/")[-1] if arn else ""


def _is_role(arn: str) -> bool:
    return ":role/" in (arn or "")


def _is_user(arn: str) -> bool:
    return ":user/" in (arn or "")


def propose_actions(case) -> list[ProposedAction]:
    """Best-effort remediation proposals from the reconstructed chain."""
    proposed: list[ProposedAction] = []
    seen: set = set()

    def add(pa: ProposedAction, dedup):
        if dedup in seen:
            return
        seen.add(dedup)
        proposed.append(pa)

    for step in case.chain.steps:
        actor, tid = step.actor, step.attack_id
        if tid in _KEY_ABUSE_TIDS and _is_user(actor):
            add(ProposedAction(
                "deactivate-access-key",
                ActionTarget(principal_arn=actor, user_name=_name_from_arn(actor)),
                "low", f"leaked-key use by {_name_from_arn(actor)}", [tid]),
                ("deactivate-access-key", actor))
        if tid in _PRIVESC_TIDS:
            add(ProposedAction(
                "quarantine-principal",
                ActionTarget(principal_arn=actor,
                             role_name=_name_from_arn(actor) if _is_role(actor) else None,
                             user_name=_name_from_arn(actor) if _is_user(actor) else None),
                "low", f"privilege escalation by {_name_from_arn(actor)}", [tid]),
                ("quarantine-principal", actor))
        if tid == "T1562.008" and step.target:
            add(ProposedAction(
                "re-enable-logging",
                ActionTarget(trail_name=_name_from_arn(step.target)),
                "high", "attacker disabled logging", [tid]),
                ("re-enable-logging", step.target))
        if tid == "T1496" and step.target:
            add(ProposedAction(
                "isolate-instance",
                ActionTarget(instance_id=step.target),
                "low", "resource hijacking on instance", [tid]),
                ("isolate-instance", step.target))

    return proposed
