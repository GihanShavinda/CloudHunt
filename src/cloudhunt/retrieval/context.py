"""Build a provenance-complete, sanitised context bundle for one case."""
from __future__ import annotations

from cloudhunt.api.graphview import case_to_elements
from cloudhunt.retrieval.playbooks import PlaybookStore
from cloudhunt.retrieval.sanitize import sanitize_data

_ATTACKER_FIELDS = {"user_agent", "params", "target", "resource_name", "tags", "guardduty_string"}

class CaseContextBuilder:
    def __init__(self, case_service, playbooks: PlaybookStore | None = None):
        self.case_service = case_service
        self.playbooks = playbooks or PlaybookStore()

    def build(self, case_id: str) -> dict:
        entry = self.case_service.entries.get(case_id)
        if entry is None:
            raise KeyError(f"unknown case: {case_id}")
        case = entry.case
        events = [self._event(ev) for ev in sorted(entry.events, key=lambda e: e.ts)]
        detections = [self._detection(d, i) for i, d in enumerate(case.cloud_case.detections, start=1)]
        chain = [self._chain_step(s) for s in case.chain.steps]
        graph = case_to_elements(case)
        graph_paths = self._paths(case, chain, graph)
        blast = self._blast(case)
        actions = [x["action_key"] for x in self.case_service._recommended(entry)]
        pbs = self.playbooks.retrieve(
            detection_types=[d.key for d in case.cloud_case.detections],
            attack_ids=sorted(case.cloud_case.techniques), action_names=actions,
        )
        return {
            "schema": "cloudhunt.case-context/v1", "case_id": case_id,
            "provenance": {"type": "case", "ref": case_id},
            "case": {"title": case.title, "rank": case.rank, "confidence": case.detection_confidence,
                     "provenance": {"type": "case", "ref": case_id}},
            "events": events, "detections": detections, "graph_paths": graph_paths,
            "blast_radius": blast, "playbooks": [p.as_context() for p in pbs],
        }

    def _event(self, ev):
        base = {
            "event_id": ev.event_id, "ts": ev.ts.isoformat(), "source": ev.source.value,
            "account": ev.account, "region": ev.region, "event": ev.event,
            "principal": ev.principal, "src_ip": ev.src_ip,
            "user_agent": sanitize_data("user_agent", ev.user_agent),
            "target": sanitize_data("target", ev.target),
            "request_parameters": sanitize_data("params", ev.params),
            "provenance": {"type": "event", "ref": ev.event_id},
        }
        return base

    def _detection(self, d, index):
        ref = f"{d.event_id or 'case'}:{d.key}:{index}"
        return {
            "detection_id": ref, "key": d.key, "title": d.title, "layer": d.layer.value,
            "attack_ids": list(d.attack_ids), "confidence": d.confidence,
            "event_id": d.event_id, "message": d.message,
            "evidence": sanitize_data("detection_evidence", d.evidence),
            "provenance": {"type": "detection", "ref": ref, "event_ref": d.event_id},
        }

    def _chain_step(self, s):
        ref = f"chain-step:{s.order}"
        return {"order": s.order, "action": s.action, "attack_id": s.attack_id,
                "actor": s.actor, "target": sanitize_data("target", s.target),
                "event_refs": list(s.event_ids), "via_edge": s.via_edge,
                "provenance": {"type": "graph_step", "ref": ref, "event_refs": list(s.event_ids)}}

    def _paths(self, case, chain, graph):
        paths = [{"path_id": "activity-chain", "kind": "activity_assumerole_chain", "steps": chain,
                  "provenance": {"type": "graph_path", "ref": "activity-chain"}}]
        for kind, p in (("privesc_admin", case.blast.reach_admin_path), ("sensitive_resource", case.blast.reach_sensitive_path)):
            if not p or not p.path:
                continue
            hops = []
            for i, h in enumerate(p.path, start=1):
                href = f"{kind}:{i}:{h.src}->{h.dst}"
                hops.append({"src": h.src, "dst": h.dst, "technique": h.technique,
                             "provenance": {"type": "node_edge", "ref": href, "node_refs": [h.src, h.dst]}})
            paths.append({"path_id": kind, "kind": kind, "hops": hops,
                          "provenance": {"type": "graph_path", "ref": kind}})
        return paths

    def _blast(self, case):
        comps = []
        for name, c in sorted(case.blast.components.items()):
            comps.append({"name": name, **c, "provenance": {"type": "blast_component", "ref": f"{case.case_id}:{name}"}})
        return {"score": case.blast.score, "principal": case.blast.principal, "components": comps,
                "provenance": {"type": "blast_radius", "ref": case.case_id}}
