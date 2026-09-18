"""Deterministic, non-AI case summary renderer."""
from __future__ import annotations


def render_case_summary(bundle: dict) -> str:
    c = bundle["case"]
    cref = c["provenance"]["ref"]
    bref = bundle["blast_radius"]["provenance"]["ref"]
    lines = [
        f"Case {bundle['case_id']}: {c['title']} [[ref:{cref}]].",
        f"Rank {c['rank']:.4f}; detection confidence {c['confidence']:.3f}; blast radius {bundle['blast_radius']['score']:.1f}/100 [[ref:{cref}]] [[ref:{bref}]].",
    ]
    if bundle["detections"]:
        parts = []
        for d in bundle["detections"]:
            parts.append(
                f"{d['key']} ({','.join(d['attack_ids']) or 'no ATT&CK id'}) [[ref:{d['provenance']['ref']}]]"
            )
        lines.append("Detections: " + "; ".join(parts) + ".")
    activity = next((p for p in bundle["graph_paths"] if p["path_id"] == "activity-chain"), None)
    if activity:
        lines.append(
            "Activity chain: " + " -> ".join(s["action"] for s in activity["steps"])
            + f" [[ref:{activity['provenance']['ref']}]]."
        )
    extra = [p for p in bundle["graph_paths"] if p["path_id"] != "activity-chain"]
    if extra:
        lines.append(
            "Graph paths: " + ", ".join(p["kind"] for p in extra)
            + " " + " ".join(f"[[ref:{p['provenance']['ref']}]]" for p in extra) + "."
        )
    if bundle["playbooks"]:
        lines.append(
            "Matched playbooks: "
            + ", ".join(
                f"{p['playbook_id']} v{p['version']} [[ref:{p['provenance']['ref']}]]"
                for p in bundle["playbooks"]
            )
            + "."
        )
    lines.append(
        f"All attacker-controlled values remain inside structured DATA fields and are not rendered into this narrative [[ref:{bundle['provenance']['ref']}]]."
    )
    return "\n".join(lines)
