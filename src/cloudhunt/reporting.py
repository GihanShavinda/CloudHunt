"""Deterministic case exports for Milestone 12.

Exports are derived only from existing case/context data.  No model or external
source is consulted.  The PDF renderer is deliberately simple and auditable.
"""
from __future__ import annotations

import csv
import io
import json
from typing import Any

from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from reportlab.lib import colors


def case_json(detail: dict[str, Any], summary: dict[str, Any]) -> bytes:
    payload = dict(detail)
    payload["summary"] = summary
    return json.dumps(payload, indent=2, default=str, sort_keys=True).encode("utf-8")


def case_csv(detail: dict[str, Any]) -> bytes:
    out = io.StringIO(newline="")
    w = csv.writer(out)
    w.writerow(["case_id", "event_ts", "principal", "action", "target", "detections", "attack_ids", "blast_score"])
    attack_ids = sorted({tid for tids in detail.get("attack_map", {}).values() for tid in tids})
    for ev in detail.get("timeline", []):
        w.writerow([
            detail.get("case_id", ""), ev.get("ts", ""), ev.get("principal", ""), ev.get("action", ""),
            ev.get("target", ""), ";".join(ev.get("detections", [])), ";".join(attack_ids),
            detail.get("blast", {}).get("score", ""),
        ])
    return out.getvalue().encode("utf-8")


def case_pdf(detail: dict[str, Any], summary: dict[str, Any]) -> bytes:
    buf = io.BytesIO()
    doc = SimpleDocTemplate(buf, pagesize=A4, rightMargin=16*mm, leftMargin=16*mm, topMargin=16*mm, bottomMargin=16*mm)
    styles = getSampleStyleSheet()
    story: list[Any] = []
    story += [Paragraph("CloudHunt Incident Report", styles["Title"]), Spacer(1, 6)]
    story.append(Paragraph(f"Case: {detail.get('title') or detail.get('case_id')}", styles["Heading2"]))
    story.append(Paragraph(
        f"Case ID: {detail.get('case_id')} | Rank: {detail.get('rank')} | Blast radius: {detail.get('blast', {}).get('score')}",
        styles["BodyText"],
    ))
    story += [Spacer(1, 8), Paragraph("Case summary", styles["Heading2"])]
    status = summary.get("source", "template")
    if summary.get("rejected"):
        status += " (AI summary rejected; deterministic fallback shown)"
    story.append(Paragraph(f"Source: {status}", styles["BodyText"]))
    story.append(Paragraph(_escape(summary.get("summary", "")), styles["BodyText"]))

    story += [Spacer(1, 8), Paragraph("Detection evidence", styles["Heading2"])]
    rows = [["Time", "Action", "Principal", "Target", "Detections"]]
    for ev in detail.get("timeline", []):
        rows.append([ev.get("ts", ""), ev.get("action", ""), ev.get("principal", ""), ev.get("target", ""), ", ".join(ev.get("detections", []))])
    story.append(_table(rows))

    story += [Spacer(1, 8), Paragraph("ATT&CK techniques", styles["Heading2"])]
    attack_rows = [["Tactic", "Techniques"]]
    for tactic, tids in detail.get("attack_map", {}).items():
        attack_rows.append([tactic, ", ".join(tids)])
    story.append(_table(attack_rows))

    story += [Spacer(1, 8), Paragraph("AssumeRole / privilege-escalation path", styles["Heading2"])]
    path_rows = [["#", "Actor", "Action", "Target", "ATT&CK"]]
    for step in detail.get("chain", []):
        path_rows.append([step.get("order", ""), step.get("actor", ""), step.get("action", ""), step.get("target", ""), step.get("attack_id", "")])
    story.append(_table(path_rows))

    story += [Spacer(1, 8), Paragraph("Blast radius", styles["Heading2"])]
    blast = detail.get("blast", {})
    story.append(Paragraph(_escape(blast.get("explanation", "")), styles["BodyText"]))
    comp_rows = [["Component", "Value"]]
    for name, value in blast.get("components", {}).items():
        comp_rows.append([name, json.dumps(value, default=str)])
    if len(comp_rows) > 1:
        story.append(_table(comp_rows))

    story += [Spacer(1, 8), Paragraph("Recommended / approved actions", styles["Heading2"])]
    act_rows = [["Action", "Mode", "Status", "Reason"]]
    for a in detail.get("recommended_actions", []):
        act_rows.append([a.get("action_key", ""), a.get("mode", ""), a.get("status", ""), "; ".join(a.get("reasons", []))])
    story.append(_table(act_rows))

    story += [Spacer(1, 8), Paragraph("Audit history", styles["Heading2"])]
    audit_rows = [["Time", "Action", "Decision", "Status", "Actor", "Channel"]]
    for r in detail.get("audit", []):
        audit_rows.append([r.get("ts", ""), r.get("action_key", ""), r.get("approval_decision") or r.get("decision", ""), r.get("status", ""), r.get("approver") or "system", r.get("channel", "")])
    story.append(_table(audit_rows))
    doc.build(story)
    return buf.getvalue()


def _table(rows: list[list[Any]]) -> Table:
    safe = [[Paragraph(_escape(str(v)), getSampleStyleSheet()["BodyText"]) for v in row] for row in rows]
    t = Table(safe, repeatRows=1, hAlign="LEFT")
    t.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#dfe8f3")),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.grey),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("LEFTPADDING", (0, 0), (-1, -1), 3),
        ("RIGHTPADDING", (0, 0), (-1, -1), 3),
    ]))
    return t


def _escape(value: str) -> str:
    return str(value).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
