"""Enrichment runs *after* structural normalisation.

Separation of concerns: the normaliser maps a source record's fields onto
:class:`CloudEvent`; the enricher fills the *derived* fields — ``asn``, ``geo``,
``resource_sensitivity`` — from side data. Keeping them apart means an enrichment
outage (a dead GeoIP feed) degrades gracefully into ``unknown`` values instead
of dropping events, which the non-functional requirements demand.

The GeoIP/ASN resolver is an interface. In dev/tests we use a static map so runs
are deterministic and fully offline; production swaps in a MaxMind-backed
resolver behind the same protocol without touching anything else.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Optional, Protocol

from cloudhunt.ingest.iam_config import IamSnapshot
from cloudhunt.models.events import CloudEvent, Sensitivity


class GeoAsnResolver(Protocol):
    def resolve(self, ip: str) -> tuple[Optional[str], Optional[str]]:
        """Return ``(asn, geo)`` for an IP, either possibly ``None``."""
        ...


class StaticGeoAsnResolver:
    """Offline resolver backed by an ``{ip: {"asn": ..., "geo": ...}}`` map."""

    def __init__(self, table: dict[str, dict[str, str]]):
        self._table = table

    @classmethod
    def from_file(cls, path: str | Path) -> "StaticGeoAsnResolver":
        p = Path(path)
        return cls(json.loads(p.read_text(encoding="utf-8")) if p.is_file() else {})

    def resolve(self, ip: str) -> tuple[Optional[str], Optional[str]]:
        row = self._table.get(ip, {})
        return row.get("asn"), row.get("geo")


class NullGeoAsnResolver:
    def resolve(self, ip: str) -> tuple[Optional[str], Optional[str]]:
        return None, None


class Enricher:
    """Fills asn/geo (from IP) and resource_sensitivity (from tags snapshot)."""

    def __init__(
        self,
        geo_resolver: Optional[GeoAsnResolver] = None,
        snapshot: Optional[IamSnapshot] = None,
    ):
        self.geo = geo_resolver or NullGeoAsnResolver()
        self.snapshot = snapshot or IamSnapshot()

    def _sensitivity_for(self, target: Optional[str]) -> Sensitivity:
        if not target:
            return Sensitivity.unknown
        table = self.snapshot.resource_sensitivity
        # Exact ARN match first, then longest-prefix (e.g. object ARN -> bucket ARN).
        if target in table:
            return table[target]
        best: Optional[str] = None
        for arn in table:
            if target.startswith(arn) and (best is None or len(arn) > len(best)):
                best = arn
        return table[best] if best else Sensitivity.unknown

    def enrich(self, ev: CloudEvent) -> CloudEvent:
        # Only resolve geo/asn if the source didn't already supply them
        # (GuardDuty findings carry their own; CloudTrail does not).
        if ev.src_ip and (ev.asn is None or ev.geo is None):
            asn, geo = self.geo.resolve(ev.src_ip)
            ev.asn = ev.asn or asn
            ev.geo = ev.geo or geo
        if ev.resource_sensitivity == Sensitivity.unknown:
            ev.resource_sensitivity = self._sensitivity_for(ev.target)
        return ev
