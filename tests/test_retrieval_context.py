from __future__ import annotations
import json
from pathlib import Path

from cloudhunt.api.casestore import build_demo_service
from cloudhunt.retrieval import CaseContextBuilder, PlaybookStore, render_case_summary, sanitize_data


def _bundle():
    return CaseContextBuilder(build_demo_service()).build("case-1")


def test_seeded_case_bundle_is_complete_and_grounded():
    b = _bundle()
    assert b["events"] and b["detections"] and b["graph_paths"] and b["blast_radius"]["components"]
    assert any(p["path_id"] == "activity-chain" for p in b["graph_paths"])
    assert b["playbooks"]
    assert all(d["attack_ids"] for d in b["detections"])


def test_every_bundle_element_has_provenance():
    b = _bundle()
    assert b["provenance"]["ref"] == "case-1" and b["case"]["provenance"]
    for key in ("events", "detections", "graph_paths", "playbooks"):
        assert all(x.get("provenance") for x in b[key])
    assert all(x.get("provenance") for x in b["blast_radius"]["components"])
    for path in b["graph_paths"]:
        for step in path.get("steps", []):
            assert step["provenance"]
        for hop in path.get("hops", []):
            assert hop["provenance"]


def test_sanitiser_wraps_escapes_and_caps_adversarial_data():
    fx = json.loads((Path(__file__).parent / "fixtures/m9/adversarial.json").read_text())
    d = sanitize_data("user_agent", fx["user_agent"], cap=40)
    assert d["tag"] == "DATA" and d["truncated"] is True
    assert "<SYSTEM>" not in d["value"] and "&lt;SYSTEM&gt;" in d["value"]
    assert "\n" not in d["value"]
    p = sanitize_data("params", fx["params"])
    assert p["tag"] == "DATA" and "Ignore evidence" in p["value"]


def test_playbook_retrieval_is_local_corpus_only_and_indexed():
    store = PlaybookStore()
    hits = store.retrieve(attack_ids=["T1562.008"], action_names=["re-enable-logging"])
    assert hits and hits[0].playbook_id == "PB-LOG-001"
    assert all(Path(p.source_path).exists() for p in store.all())


def test_template_renderer_has_zero_model_dependency_and_no_attacker_data():
    b = _bundle()
    text = render_case_summary(b)
    assert "Case case-1:" in text and "Activity chain:" in text and "Matched playbooks:" in text
    assert "DATA fields" in text
    assert "user_agent" not in text and "request_parameters" not in text
