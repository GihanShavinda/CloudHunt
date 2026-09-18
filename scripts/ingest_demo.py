"""Run the folder source through the full pipeline and print CloudEvents.

    python scripts/ingest_demo.py            # CloudTrail sample folder
    python scripts/ingest_demo.py guardduty  # GuardDuty sample folder

This is the offline, no-cloud demonstration of Milestone 1.
"""
from __future__ import annotations

import sys

from cloudhunt.core.config import settings
from cloudhunt.ingest.folder import FolderCloudTrailSource
from cloudhunt.ingest.guardduty import FolderGuardDutySource
from cloudhunt.ingest.iam_config import IamSnapshot
from cloudhunt.normalise.enrich import Enricher, StaticGeoAsnResolver
from cloudhunt.normalise.pipeline import run


def main() -> None:
    which = sys.argv[1] if len(sys.argv) > 1 else "cloudtrail"
    base = settings.sample_data_dir
    enricher = Enricher(
        geo_resolver=StaticGeoAsnResolver.from_file(base / "enrichment" / "geoip.json"),
        snapshot=IamSnapshot.from_dir(base / "iam_config"),
    )
    if which == "guardduty":
        source = FolderGuardDutySource(base / "guardduty")
    else:
        source = FolderCloudTrailSource(base / "cloudtrail")

    for ev in run(source, enricher):
        print(
            f"{ev.ts.isoformat():25} {ev.event:22} "
            f"principal={ev.principal:55} geo={ev.geo} sens={ev.resource_sensitivity.value}"
        )


if __name__ == "__main__":
    main()
