"""Layer 1 — Sigma-style signature engine.

Rules are YAML (``src/cloudhunt/rules/*.yml``) loaded at runtime, so analysts add
detections without touching Python. The dialect is a pragmatic subset of Sigma
adapted to the :class:`CloudEvent` schema:

* ``detection`` holds one or more named *selection* blocks plus a ``condition``.
* A block is a map ``field: value`` (AND across fields); a value list is OR; and
  fields take Sigma modifiers ``|contains|startswith|endswith|re|cidr``.
* ``condition`` supports ``and/or/not``, parentheses, and ``all of them`` /
  ``1 of them`` / ``all of sel*`` style expressions.

Three rules need to look inside request parameters (security-group CIDRs, EC2
instance types, trust-policy documents). Rather than teach the matcher to walk
arbitrary nested CloudTrail JSON, we compute a few **derived indicators** first
(:func:`derive_indicators`) and let rules match on ``derived.*`` booleans. All
request content is treated strictly as data.
"""

from __future__ import annotations

import ipaddress
import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from cloudhunt.detect import attack
from cloudhunt.detect.base import Detection, Layer
from cloudhunt.models.events import CloudEvent

# ---------------------------------------------------------------------------
# Derived indicators (the deep-parameter bits YAML shouldn't have to walk)
# ---------------------------------------------------------------------------

_SG_OPEN_EVENTS = {"AuthorizeSecurityGroupIngress", "AuthorizeSecurityGroupEgress",
                   "ModifySecurityGroupRules"}
_WORLD_CIDRS = ("0.0.0.0/0", "::/0")
_TRUST_EVENTS = {"UpdateAssumeRolePolicy": "policyDocument",
                 "CreateRole": "assumeRolePolicyDocument"}
_GPU_LARGE_PREFIXES = ("p2.", "p3.", "p4", "p5", "g3", "g4", "g5", "g6",
                       "inf", "trn", "dl1", "f1", "x1", "x2")
_LARGE_SIZES = ("8xlarge", "12xlarge", "16xlarge", "24xlarge", "32xlarge",
                "48xlarge", "metal")


def _iter_strings(obj: Any):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _iter_strings(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _iter_strings(v)


def _account_of(arn: str):
    parts = arn.split(":")
    return parts[4] if len(parts) > 4 and parts[4] else None


def _trust_adds_external(doc: Any, account: str) -> bool:
    if isinstance(doc, str):
        try:
            doc = json.loads(doc)
        except (json.JSONDecodeError, TypeError):
            return "*" in doc  # unparseable; be conservative on wildcard
    stmts = doc.get("Statement", []) if isinstance(doc, dict) else []
    if isinstance(stmts, dict):
        stmts = [stmts]
    for s in stmts:
        if str(s.get("Effect", "")).lower() != "allow":
            continue
        principal = s.get("Principal", {})
        aws = principal.get("AWS") if isinstance(principal, dict) else None
        for val in (aws if isinstance(aws, list) else [aws] if aws else []):
            if val == "*":
                return True
            acct = _account_of(val)
            if acct and acct != account:
                return True
    return False


def derive_indicators(event: CloudEvent) -> dict[str, bool]:
    d: dict[str, bool] = {}

    if event.event in _SG_OPEN_EVENTS:
        strings = list(_iter_strings(event.params))
        d["sg_opens_world"] = any(c in s for s in strings for c in _WORLD_CIDRS)

    if event.event in _TRUST_EVENTS:
        doc = event.params.get(_TRUST_EVENTS[event.event])
        d["external_trust_added"] = _trust_adds_external(doc, event.account)

    if event.event == "RunInstances":
        itype = str(event.params.get("instanceType", "")).lower()
        d["gpu_or_large_instance"] = (
            itype.startswith(_GPU_LARGE_PREFIXES) or any(sz in itype for sz in _LARGE_SIZES)
        )
    return d


# ---------------------------------------------------------------------------
# Event flattening + field matching
# ---------------------------------------------------------------------------

def flatten_event(event: CloudEvent, derived: dict[str, bool]) -> dict[str, Any]:
    flat: dict[str, Any] = {
        "event": event.event, "principal": event.principal,
        "principal_type": event.principal_type.value, "region": event.region,
        "account": event.account, "src_ip": event.src_ip, "asn": event.asn,
        "geo": event.geo, "user_agent": event.user_agent, "mfa": event.mfa,
        "resource_sensitivity": event.resource_sensitivity.value,
        "read_only": event.read_only, "error_code": event.error_code,
        "severity": event.severity, "source": event.source.value,
        "target": event.target, "event_id": event.event_id,
        "params": json.dumps(event.params),  # for contains/re/deep matching
    }
    if event.session:
        flat["session.issuer_arn"] = event.session.issuer_arn
        flat["session.issuer_type"] = event.session.issuer_type
        flat["session.session_name"] = event.session.session_name
        flat["session.mfa_authenticated"] = event.session.mfa_authenticated
    for k, v in event.params.items():
        if isinstance(v, (str, int, float, bool)):
            flat[f"params.{k}"] = v
    for k, v in derived.items():
        flat[f"derived.{k}"] = v
    return flat


def _match_scalar(spec_value: Any, actual: Any, modifiers: list[str]) -> bool:
    if actual is None:
        return False
    a = actual
    if modifiers:
        mod = modifiers[0]
        s = a if isinstance(a, str) else json.dumps(a) if isinstance(a, (dict, list)) else str(a)
        sv = str(spec_value)
        if mod == "contains":
            return sv.lower() in s.lower()
        if mod == "startswith":
            return s.lower().startswith(sv.lower())
        if mod == "endswith":
            return s.lower().endswith(sv.lower())
        if mod == "re":
            return re.search(sv, s) is not None
        if mod == "cidr":
            try:
                return ipaddress.ip_address(s) in ipaddress.ip_network(sv, strict=False)
            except ValueError:
                return False
        raise ValueError(f"unknown field modifier {mod!r}")
    # plain equality
    if isinstance(a, bool) or isinstance(spec_value, bool):
        return bool(a) == bool(spec_value)
    if isinstance(a, str):
        return a.lower() == str(spec_value).lower()
    return a == spec_value


def _match_field(field_spec: str, spec_value: Any, flat: dict[str, Any]) -> bool:
    name, *modifiers = field_spec.split("|")
    actual = flat.get(name)
    values = spec_value if isinstance(spec_value, list) else [spec_value]
    return any(_match_scalar(v, actual, modifiers) for v in values)  # list = OR


def _match_block(block: Any, flat: dict[str, Any]) -> bool:
    if isinstance(block, list):  # list of maps = OR
        return any(_match_block(b, flat) for b in block)
    return all(_match_field(f, v, flat) for f, v in block.items())  # map = AND


# ---------------------------------------------------------------------------
# Condition parser
# ---------------------------------------------------------------------------

def _expand_quantifiers(condition: str, names: list[str]) -> str:
    def repl(match: re.Match) -> str:
        quant, target = match.group(1), match.group(2)
        if target == "them":
            chosen = names
        else:  # prefix* form
            prefix = target.rstrip("*")
            chosen = [n for n in names if n.startswith(prefix)]
        if not chosen:
            return "__false__"
        joiner = " and " if quant == "all" else " or "
        return "(" + joiner.join(chosen) + ")"

    return re.sub(r"\b(all|1|any)\s+of\s+(\w+\*|them)\b", repl, condition)


def _eval_condition(condition: str, results: dict[str, bool], names: list[str]) -> bool:
    expr = _expand_quantifiers(condition.strip(), names)
    tokens = re.findall(r"\(|\)|\band\b|\bor\b|\bnot\b|[\w.*]+", expr)
    pos = 0

    def peek():
        return tokens[pos] if pos < len(tokens) else None

    def eat():
        nonlocal pos
        tok = tokens[pos]
        pos += 1
        return tok

    def parse_or():
        val = parse_and()
        while peek() == "or":
            eat()
            val = parse_and() or val
        return val

    def parse_and():
        val = parse_not()
        while peek() == "and":
            eat()
            val = parse_not() and val
        return val

    def parse_not():
        if peek() == "not":
            eat()
            return not parse_not()
        return parse_atom()

    def parse_atom():
        tok = eat()
        if tok == "(":
            val = parse_or()
            if peek() == ")":
                eat()
            return val
        if tok == "__false__":
            return False
        return results.get(tok, False)

    return parse_or()


# ---------------------------------------------------------------------------
# Rules + engine
# ---------------------------------------------------------------------------

@dataclass
class Rule:
    key: str
    title: str
    attack_ids: list[str]
    confidence: float
    detection: dict
    condition: str
    level: str = "medium"
    description: str = ""
    false_positives: list[str] = field(default_factory=list)

    @property
    def _selection_names(self) -> list[str]:
        return [k for k in self.detection if k != "condition"]

    def matches(self, flat: dict[str, Any]) -> bool:
        results = {name: _match_block(self.detection[name], flat)
                   for name in self._selection_names}
        return _eval_condition(self.condition, results, self._selection_names)


def _parse_rule(doc: dict) -> Rule:
    detection = dict(doc["detection"])
    condition = str(detection.pop("condition", None)
                    or " and ".join(k for k in detection))
    attack_field = doc.get("attack") or doc.get("tags") or []
    attack_ids = [attack_field] if isinstance(attack_field, str) else list(attack_field)
    for aid in attack_ids:               # fail loudly on an unknown id
        attack.resolve(aid)
    return Rule(
        key=doc["id"], title=doc.get("title", doc["id"]),
        attack_ids=attack_ids, confidence=float(doc.get("confidence", 0.5)),
        detection=detection, condition=condition,
        level=doc.get("level", "medium"), description=doc.get("description", ""),
        false_positives=list(doc.get("falsepositives", []) or []),
    )


def default_rules_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "rules"


def load_rules(rules_dir: str | Path | None = None) -> list[Rule]:
    d = Path(rules_dir) if rules_dir else default_rules_dir()
    rules: list[Rule] = []
    for path in sorted(d.glob("*.y*ml")):
        docs = [doc for doc in yaml.safe_load_all(path.read_text(encoding="utf-8")) if doc]
        for doc in docs:
            if "detection" in doc:
                rules.append(_parse_rule(doc))
    return rules


class SignatureEngine:
    def __init__(self, rules: list[Rule] | None = None):
        self.rules = rules if rules is not None else load_rules()

    def match(self, event: CloudEvent) -> list[Detection]:
        derived = derive_indicators(event)
        flat = flatten_event(event, derived)
        out: list[Detection] = []
        for rule in self.rules:
            if rule.matches(flat):
                out.append(Detection.from_event(
                    event, key=rule.key, title=rule.title, layer=Layer.signature,
                    attack_ids=rule.attack_ids, confidence=rule.confidence,
                    message=rule.title, false_positive_notes=rule.false_positives,
                    evidence={"level": rule.level},
                ))
        return out
