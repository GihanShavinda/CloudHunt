"""Normalise the saved GuardDuty fixtures into the unified schema."""

from __future__ import annotations

from pathlib import Path

from cloudhunt.ingest.guardduty import FolderGuardDutySource
from cloudhunt.models.events import PrincipalType, Source
from cloudhunt.normalise.enrich import Enricher
from cloudhunt.normalise.guardduty import normalise_guardduty
from cloudhunt.normalise.pipeline import run


def test_guardduty_finding_normalises(guardduty_dir: Path):
    raw = next(iter(FolderGuardDutySource(guardduty_dir).records()))
    ev = normalise_guardduty(raw)

    assert ev.source is Source.guardduty
    assert ev.event == "UnauthorizedAccess:IAMUser/MaliciousIPCaller.Custom"
    assert ev.account == "111122223333"
    assert ev.region == "us-east-1"
    assert ev.principal == "arn:aws:iam::111122223333:user/ci-bot"
    assert ev.principal_type is PrincipalType.user
    assert ev.src_ip == "185.220.101.5"
    assert ev.asn == "AS205100"           # "205100" gets the AS-prefix normalisation
    assert ev.geo == "Germany"
    assert ev.severity == 8.0
    assert ev.event_id == "finding-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"


def test_guardduty_geo_not_overwritten_by_enricher(guardduty_dir: Path):
    """The finding already carries geo/asn; the enricher must not clobber it."""
    events = list(run(FolderGuardDutySource(guardduty_dir), Enricher()))
    ev = events[0]
    assert ev.geo == "Germany"
    assert ev.asn == "AS205100"
