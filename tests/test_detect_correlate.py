"""Layer 3 correlation + full-engine tests."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

import pytest

from cloudhunt.detect import attack
from cloudhunt.detect.base import Detection, Layer
from cloudhunt.detect.correlate import correlate, enrich_with_privesc
from cloudhunt.detect.engine import DetectionEngine
from cloudhunt.models.events import CloudEvent, Source

T0 = datetime(2026, 9, 10, 3, 0, tzinfo=timezone.utc)
ALICE = "arn:aws:iam::111122223333:user/alice"
BOB = "arn:aws:iam::111122223333:user/bob"


def det(key, principal=ALICE, src_ip="1.2.3.4", minutes=0, attack_ids=("T1562.008",),
        confidence=0.6) -> Detection:
    return Detection(key=key, title=key, layer=Layer.signature,
                     attack_ids=list(attack_ids), confidence=confidence,
                     principal=principal, src_ip=src_ip, ts=T0 + timedelta(minutes=minutes))


# --- correlation clustering ---
def test_same_principal_within_window_merges():
    cases = correlate([det("a", minutes=0), det("b", minutes=10)], window_minutes=60)
    assert len(cases) == 1 and len(cases[0].detections) == 2


def test_same_principal_far_apart_splits():
    cases = correlate([det("a", minutes=0), det("b", minutes=600)], window_minutes=60)
    assert len(cases) == 2


def test_shared_src_ip_links_different_principals():
    cases = correlate([det("a", principal=ALICE, src_ip="9.9.9.9"),
                       det("b", principal=BOB, src_ip="9.9.9.9", minutes=5)],
                      window_minutes=60)
    assert len(cases) == 1
    assert cases[0].principals == {ALICE, BOB}


def test_case_aggregates_tactics_and_scores_higher_with_breadth():
    # two different tactics -> noisy-or + breadth boost
    cases = correlate([det("a", attack_ids=["T1562.008"], confidence=0.6),
                       det("b", attack_ids=["T1496"], confidence=0.6, minutes=5)])
    c = cases[0]
    assert {"Defense Evasion", "Impact"} <= c.tactics
    # noisy-or of two 0.6s = 0.84, plus 0.05 breadth boost
    assert c.score >= 0.84


# --- privesc enrichment ---
@dataclass
class _FakePath:
    target_priv: str
    techniques: list


def test_enrich_with_privesc_adds_technique_and_boost():
    cases = correlate([det("a", confidence=0.6)])
    c = cases[0]
    before = c.score
    enrich_with_privesc(c, {ALICE: _FakePath("admin-equivalent", ["CreatePolicyVersion"])})
    assert "T1548" in c.techniques
    assert c.score > before
    assert any("privesc path" in n for n in c.notes)


# --- attack registry hygiene ---
def test_unknown_attack_id_raises():
    with pytest.raises(KeyError):
        attack.resolve("T9999")


# --- full engine over a small stream ---
def _ev(event, principal=ALICE, geo="US", minutes=0, **kw) -> CloudEvent:
    base = dict(ts=T0 + timedelta(minutes=minutes), account="111122223333",
                region="us-east-1", event=event, principal=principal, geo=geo,
                src_ip="1.2.3.4", raw_ref="r", event_id=f"e-{event}-{minutes}",
                source=Source.cloudtrail)
    base.update(kw)
    return CloudEvent(**base)


def test_engine_end_to_end_builds_a_case():
    baseline = [_ev("GetObject", geo="US"), _ev("GetObject", geo="US", minutes=1)]
    stream = [
        _ev("GetObject", geo="DE", minutes=0),           # new-geo (behavioural)
        _ev("StopLogging", geo="DE", minutes=5),         # logging tampering (signature)
    ]
    engine = DetectionEngine()
    result = engine.run(stream, baseline_events=baseline,
                        privesc_paths={ALICE: _FakePath("admin-equivalent", ["CreatePolicyVersion"])})

    keys = {d.key for d in result.detections}
    assert "ct-logging-tampering" in keys
    assert "bhv-new-geo" in keys
    assert len(result.cases) == 1
    case = result.cases[0]
    # signature + behavioural detections correlated onto one principal, privesc-enriched
    assert ALICE in case.principals
    assert "T1548" in case.techniques
    assert case.score > 0.6


def test_engine_without_baseline_skips_new_geo():
    stream = [_ev("GetObject", geo="DE")]
    result = DetectionEngine().run(stream)  # no baseline_events
    assert "bhv-new-geo" not in {d.key for d in result.detections}
