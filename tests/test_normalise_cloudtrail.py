"""Normalise the saved CloudTrail fixtures into the unified schema."""

from __future__ import annotations

from pathlib import Path

from cloudhunt.ingest.folder import FolderCloudTrailSource
from cloudhunt.ingest.iam_config import IamSnapshot
from cloudhunt.models.events import PrincipalType, Sensitivity, Source
from cloudhunt.normalise.cloudtrail import normalise_cloudtrail
from cloudhunt.normalise.enrich import Enricher, StaticGeoAsnResolver
from cloudhunt.normalise.pipeline import run


def _events(cloudtrail_dir: Path):
    return list(FolderCloudTrailSource(cloudtrail_dir).records())


def test_folder_source_yields_all_records(cloudtrail_dir: Path):
    raws = _events(cloudtrail_dir)
    assert len(raws) == 4
    assert all(r.source is Source.cloudtrail for r in raws)
    assert all(r.raw_ref.startswith("file://") for r in raws)


def test_assumed_role_getobject_normalises(cloudtrail_dir: Path):
    raws = _events(cloudtrail_dir)
    getobj = next(r for r in raws if r.record["eventName"] == "GetObject")
    ev = normalise_cloudtrail(getobj)

    assert ev.event == "GetObject"
    assert ev.source is Source.cloudtrail
    assert ev.principal == "arn:aws:sts::111122223333:assumed-role/deploy/sess1"
    assert ev.principal_type is PrincipalType.assumed_role
    assert ev.session is not None
    assert ev.session.issuer_arn == "arn:aws:iam::111122223333:role/deploy"
    assert ev.mfa is False
    assert ev.src_ip == "185.220.101.5"
    assert ev.target == "arn:aws:s3:::acme-crown-jewels/customers.csv"
    assert ev.read_only is True
    assert ev.account == "111122223333"
    assert ev.region == "us-east-1"
    assert ev.event_id == "33333333-3333-3333-3333-333333333333"


def test_iam_user_assumerole_target_from_requestparams(cloudtrail_dir: Path):
    raws = _events(cloudtrail_dir)
    assume = next(r for r in raws if r.record["eventName"] == "AssumeRole")
    ev = normalise_cloudtrail(assume)
    assert ev.principal == "arn:aws:iam::111122223333:user/ci-bot"
    assert ev.principal_type is PrincipalType.user
    assert ev.target == "arn:aws:iam::111122223333:role/deploy"


def test_pipeline_enriches_geo_asn_and_sensitivity(cloudtrail_dir: Path, sample_dir: Path):
    resolver = StaticGeoAsnResolver.from_file(sample_dir / "enrichment" / "geoip.json")
    snapshot = IamSnapshot.from_dir(sample_dir / "iam_config")
    enricher = Enricher(geo_resolver=resolver, snapshot=snapshot)

    events = list(run(FolderCloudTrailSource(cloudtrail_dir), enricher))
    by_name = {e.event: e for e in events}

    getobj = by_name["GetObject"]
    assert getobj.geo == "DE"
    assert getobj.asn == "AS205100"
    # object ARN resolves to the bucket's sensitivity via longest-prefix match
    assert getobj.resource_sensitivity is Sensitivity.high


def test_pipeline_dedups_repeated_event_ids(cloudtrail_dir: Path):
    """Same eventID delivered twice must yield exactly one CloudEvent."""

    class DoubledSource(FolderCloudTrailSource):
        def records(self):
            yield from super().records()
            yield from super().records()  # simulate CloudTrail at-least-once delivery

    events = list(run(DoubledSource(cloudtrail_dir), Enricher()))
    ids = [e.event_id for e in events]
    assert len(ids) == len(set(ids)) == 4
