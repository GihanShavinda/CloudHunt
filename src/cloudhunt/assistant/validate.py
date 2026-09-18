"""Validation gate for assistant output before it can be displayed."""
from __future__ import annotations

from dataclasses import dataclass
import html
import re
from typing import Any

_REF_RE = re.compile(r"\[\[ref:([^\]]+)\]\]")
_ARN_RE = re.compile(r"\barn:aws(?:-[a-z0-9-]+)?:[A-Za-z0-9_./:=+@,-]+")
_S3_URI_RE = re.compile(r"\bs3://[A-Za-z0-9][A-Za-z0-9._-]{1,62}(?:/[A-Za-z0-9._~!$&'()*+,;=:@%/-]*)?")
# Conservative AWS API-name shape.  We intentionally validate names that look
# like actual control/data-plane operations rather than every CamelCase word.
_API_RE = re.compile(
    r"\b(?:Get|Put|List|Create|Delete|Update|Assume|Stop|Start|Describe|Attach|Detach|"
    r"Pass|Revoke|Terminate|Disable|Enable|Set|Modify|Add|Remove|Tag|Untag|Copy|Head|"
    r"Batch|Invoke)[A-Z][A-Za-z0-9]+\b"
)
_DIRECTIVE_RE = re.compile(
    r"(?:^|(?<=[.!?])\s+)(?:please\s+)?(?:run|execute|delete|disable|enable|revoke|rotate|"
    r"terminate|block|isolate|attach|detach|create|update|put|remove|stop|start|assume|"
    r"modify|set|add|copy|invoke|remediate)\b",
    re.IGNORECASE,
)
_SENTENCE_RE = re.compile(r"[^\n.!?]+(?:[.!?](?=\s|$)|$)")


@dataclass(frozen=True)
class ValidationResult:
    valid: bool
    violations: tuple[str, ...]


def _walk(value: Any):
    if isinstance(value, dict):
        yield value
        for v in value.values():
            yield from _walk(v)
    elif isinstance(value, (list, tuple, set)):
        for v in value:
            yield from _walk(v)


def _strings(value: Any):
    if isinstance(value, str):
        yield html.unescape(value)
    elif isinstance(value, dict):
        for v in value.values():
            yield from _strings(v)
    elif isinstance(value, (list, tuple, set)):
        for v in value:
            yield from _strings(v)


def provenance_refs(bundle: dict) -> set[str]:
    refs: set[str] = set()
    for obj in _walk(bundle):
        p = obj.get("provenance") if isinstance(obj, dict) else None
        if isinstance(p, dict):
            ref = p.get("ref")
            if ref:
                refs.add(str(ref))
            for key in ("event_ref", "event_refs", "node_refs"):
                v = p.get(key)
                if isinstance(v, str) and v:
                    refs.add(v)
                elif isinstance(v, (list, tuple, set)):
                    refs.update(str(x) for x in v if x)
    return refs


def _allowed_entities(bundle: dict) -> tuple[set[str], set[str], set[str]]:
    strings = set(_strings(bundle))
    arns: set[str] = set()
    apis: set[str] = set()
    resources: set[str] = set()
    for text in strings:
        arns.update(_ARN_RE.findall(text))
        apis.update(_API_RE.findall(text))
        resources.update(_S3_URI_RE.findall(text))
    # Event/chain action names are authoritative even when they do not happen to
    # appear inside a long DATA string.
    for ev in bundle.get("events", []):
        if ev.get("event"):
            apis.add(str(ev["event"]))
    for path in bundle.get("graph_paths", []):
        for step in path.get("steps", []):
            if step.get("action"):
                apis.add(str(step["action"]))
    return arns, apis, resources


def validate_summary(text: str, bundle: dict) -> ValidationResult:
    violations: list[str] = []
    refs = provenance_refs(bundle)
    allowed_arns, allowed_apis, allowed_resources = _allowed_entities(bundle)

    for ref in _REF_RE.findall(text):
        if ref not in refs:
            violations.append(f"unsupported provenance ref: {ref}")

    # Every non-empty factual sentence must contain at least one provenance ref.
    for raw in _SENTENCE_RE.findall(text):
        sentence = raw.strip()
        if sentence and not _REF_RE.search(sentence):
            violations.append(f"uncited sentence: {sentence[:80]}")

    for arn in _ARN_RE.findall(text):
        if arn not in allowed_arns:
            violations.append(f"unsupported ARN: {arn}")
    for api in _API_RE.findall(text):
        if api not in allowed_apis:
            violations.append(f"unsupported API/action: {api}")
    for resource in _S3_URI_RE.findall(text):
        if resource not in allowed_resources:
            violations.append(f"unsupported resource: {resource}")

    if _DIRECTIVE_RE.search(_REF_RE.sub("", text)):
        violations.append("action directive detected")

    # Preserve order while de-duplicating for stable tests/UI.
    unique = tuple(dict.fromkeys(violations))
    return ValidationResult(valid=not unique, violations=unique)
