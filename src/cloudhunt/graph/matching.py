"""IAM wildcard matching — the primitive under every policy decision.

Two things must match correctly or the whole evaluator is wrong:

* **Actions** — case-insensitive, ``*`` = any run of chars, ``?`` = one char.
  ``s3:*`` matches ``s3:GetObject``; ``s3:Get*`` matches ``s3:GetObject`` but not
  ``s3:PutObject``; ``*`` matches everything.
* **Resource ARNs** — same wildcards, but case-sensitive (ARNs are). ``*`` alone
  matches any resource; ``arn:aws:s3:::b/*`` matches ``arn:aws:s3:::b/key.csv``.

We translate the IAM glob to a regex rather than using ``fnmatch`` because
``fnmatch`` treats ``[`` as a character class, which ARNs and some actions can
contain; IAM globs only special-case ``*`` and ``?``.
"""

from __future__ import annotations

import re
from functools import lru_cache


@lru_cache(maxsize=4096)
def _compile(pattern: str, ignore_case: bool) -> re.Pattern[str]:
    out = ["^"]
    for ch in pattern:
        if ch == "*":
            out.append(".*")
        elif ch == "?":
            out.append(".")
        else:
            out.append(re.escape(ch))
    out.append("$")
    flags = re.IGNORECASE if ignore_case else 0
    return re.compile("".join(out), flags)


def action_matches(pattern: str, action: str) -> bool:
    """IAM action glob match (case-insensitive)."""
    return _compile(pattern, True).match(action) is not None


def resource_matches(pattern: str, resource: str) -> bool:
    """IAM resource-ARN glob match (case-sensitive). ``*`` matches all."""
    if pattern == "*":
        return True
    return _compile(pattern, False).match(resource) is not None


def _as_list(value) -> list[str]:
    """IAM fields are 'string or list of string'. Normalise to a list."""
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return list(value)


def any_action_matches(patterns, action: str) -> bool:
    return any(action_matches(p, action) for p in _as_list(patterns))


def any_resource_matches(patterns, resource: str) -> bool:
    return any(resource_matches(p, resource) for p in _as_list(patterns))
