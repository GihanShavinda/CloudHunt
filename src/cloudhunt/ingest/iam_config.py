"""IAM & AWS Config snapshot ingestion.

In Milestone 2 these snapshots build the Neo4j identity graph. In Milestone 1
they already earn their keep as the *ground truth for enrichment*: they tell us
each principal's tags and each resource's sensitivity tag. So this module is a
"stub" only in the graph sense — the parsing into an :class:`IamSnapshot` is
real and feeds :class:`cloudhunt.normalise.enrich.Enricher`.

Expected snapshot shape (see ``sample_data/iam_config/``)::

    {
      "principals": [ {"arn": "...", "type": "user", "tags": {"Team": "ci"}} ],
      "resources":  [ {"arn": "...", "type": "AWS::S3::Bucket",
                       "tags": {"Sensitivity": "high"}} ]
    }
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from cloudhunt.models.events import Sensitivity


def _sensitivity_from_tags(tags: dict[str, str]) -> Sensitivity:
    raw = str(tags.get("Sensitivity", "")).lower()
    try:
        return Sensitivity(raw)
    except ValueError:
        return Sensitivity.unknown


@dataclass
class IamSnapshot:
    """Parsed IAM/Config snapshot, indexed for O(1) enrichment lookups."""

    principal_tags: dict[str, dict[str, str]] = field(default_factory=dict)
    resource_sensitivity: dict[str, Sensitivity] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "IamSnapshot":
        snap = cls()
        for p in payload.get("principals", []):
            snap.principal_tags[p["arn"]] = p.get("tags", {})
        for r in payload.get("resources", []):
            snap.resource_sensitivity[r["arn"]] = _sensitivity_from_tags(r.get("tags", {}))
        return snap

    @classmethod
    def from_dir(cls, directory: str | Path) -> "IamSnapshot":
        directory = Path(directory)
        merged = cls()
        if not directory.is_dir():
            return merged
        for path in sorted(directory.glob("*.json")):
            part = cls.from_dict(json.loads(path.read_text(encoding="utf-8")))
            merged.principal_tags.update(part.principal_tags)
            merged.resource_sensitivity.update(part.resource_sensitivity)
        return merged
