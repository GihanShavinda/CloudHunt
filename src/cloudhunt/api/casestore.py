"""Case service — the read/act model behind the dashboard API.

Holds the built cases, their response plans (auto-executed + pending), the shared
audit log, and the response engine. Turns a case into the workspace payloads the
UI needs (chain, graph, timeline, ATT&CK map, recommended actions, audit) and
executes human-approved actions. All of it is computed here, server-side, so the
Angular UI can stay thin.

``build_demo_service`` runs the whole offline pipeline on the sample scenario so
the API has something real to serve with no AWS and no database.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Optional

from cloudhunt.api.graphview import case_to_elements
from cloudhunt.core.config import settings
from cloudhunt.correlate import build_cases, prepare_graph
from cloudhunt.detect import attack
from cloudhunt.detect.engine import DetectionEngine
from cloudhunt.graph.authorization import IamAuthorization
from cloudhunt.models.events import CloudEvent, PrincipalType, SessionContext, Source
from cloudhunt.respond import (
    Approval,
    AuditRecord,
    FakeActionExecutor,
    InMemoryAuditLog,
    ResponseEngine,
    ResponsePlan,
)
from cloudhunt.mobile import ApprovalTokenError, ApprovalTokenStore, PushService, RedisApprovalTokenStore
from cloudhunt.persistence import PostgresOperationalStore


@dataclass
class _Entry:
    case: object
    events: list
    plan: ResponsePlan


class CaseService:
    def __init__(self, engine: ResponseEngine, executor, *,
                 push_service: PushService | None = None,
                 approval_tokens: ApprovalTokenStore | None = None,
                 operational_store: PostgresOperationalStore | None = None):
        self.engine = engine
        self.executor = executor
        self.entries: dict[str, _Entry] = {}
        self.exposure: list[dict] = []      # sensitive-resource exposure (seeded)
        self.push = push_service or PushService()
        self.approval_tokens = approval_tokens or ApprovalTokenStore()
        self.operational_store = operational_store

    # -- ingest a case: auto-contain, keep the plan --
    def add_case(self, case, events) -> ResponsePlan:
        plan = self.engine.run(case)
        self.entries[case.case_id] = _Entry(case=case, events=list(events), plan=plan)
        # M6 remains the sole authority: push is emitted only for items M6 already
        # classified as human-required. M11 never creates or upgrades decisions.
        for _item in plan.pending:
            self.push.notify_human_required(case.case_id)
        if self.operational_store is not None:
            self.operational_store.save_case(case.case_id, self.get_case(case.case_id) or {}, list(events))
            for rec in plan.executed:
                self.operational_store.append_audit(rec)
        return plan

    # -- summaries / dashboard --
    def list_cases(self) -> list[dict]:
        out = []
        for e in self.entries.values():
            c = e.case
            out.append({
                "case_id": c.case_id, "title": c.title, "rank": c.rank,
                "blast": c.blast.score, "confidence": c.detection_confidence,
                "techniques": sorted(getattr(c.cloud_case, "techniques", set())),
                "sensitive_exposed": bool(getattr(c.blast, "reach_sensitive_path", None)),
                "pending_actions": len(e.plan.pending),
            })
        return sorted(out, key=lambda d: d["rank"], reverse=True)

    def dashboard_summary(self) -> dict:
        cases = self.list_cases()
        trails = getattr(self.executor, "trails", {})
        logging_health = {
            "trails": [{"trail": t, "logging": bool(v)} for t, v in trails.items()],
            "healthy": all(trails.values()) if trails else True,
        }
        return {
            "cases_by_blast": sorted(cases, key=lambda d: d["blast"], reverse=True),
            "sensitive_resource_exposure": self.exposure,
            "logging_health": logging_health,
            "open_cases": len(cases),
        }

    # -- case detail --
    def get_case(self, case_id: str) -> Optional[dict]:
        e = self.entries.get(case_id)
        if e is None:
            return None
        c = e.case
        det_by_event: dict[str, list] = {}
        for d in c.cloud_case.detections:
            if d.event_id:
                det_by_event.setdefault(d.event_id, []).append(d.key)

        timeline = [{
            "ts": ev.ts.isoformat() if ev.ts else None,
            "principal": ev.principal, "action": ev.event, "target": ev.target,
            "detections": det_by_event.get(ev.event_id, []),
        } for ev in sorted(e.events, key=lambda x: x.ts)]

        attack_map: dict[str, list[str]] = {}
        for tid in sorted(getattr(c.cloud_case, "techniques", set())):
            attack_map.setdefault(attack.tactic_for(tid), []).append(tid)

        recommended = self._recommended(e)
        audit = [self._audit_dict(r) for r in self.engine.audit.records()
                 if r.case_id == case_id]

        detection_rows = [{
            "key": d.key, "title": d.title, "layer": d.layer.value,
            "attack_ids": list(d.attack_ids), "confidence": d.confidence,
            "principal": d.principal, "resource": d.evidence.get("role_arn") or d.evidence.get("bucket") or d.evidence.get("target"),
            "message": d.message,
        } for d in c.cloud_case.detections]
        advanced = [d for d in detection_rows if d["key"].startswith("m8-")]

        return {
            "case_id": c.case_id, "title": c.title, "rank": c.rank,
            "blast": {"score": c.blast.score,
                      "components": c.blast.components,
                      "explanation": c.blast.explanation()},
            "chain": [{"order": s.order, "actor": s.actor, "action": s.action,
                       "tactic": s.tactic, "attack_id": s.attack_id,
                       "target": s.target, "via_edge": s.via_edge,
                       "detections": s.detection_keys} for s in c.chain.steps],
            "graph": case_to_elements(c),
            "timeline": timeline,
            "attack_map": attack_map,
            "detections": detection_rows,
            "advanced_detections": advanced,
            "recommended_actions": recommended,
            "audit": audit,
        }

    def _recommended(self, e: _Entry) -> list[dict]:
        out = []
        for rec in e.plan.executed:
            out.append({"action_key": rec.action_key, "mode": "auto",
                        "status": "executed", "reasons": [rec.reason]})
        for item in e.plan.pending:
            out.append({"action_id": item.action_id, "action_key": item.proposed.action_key,
                        "mode": "human", "status": "pending",
                        "reasons": item.decision.reasons})
        return out

    @staticmethod
    def _audit_dict(r) -> dict:
        return {"record_id": r.record_id, "ts": r.ts, "action_key": r.action_key,
                "decision": r.decision, "status": r.status, "approver": r.approver,
                "channel": r.channel, "approval_decision": r.approval_decision,
                "before": r.before, "after": r.after, "reason": r.reason}

    # -- human approval of a pending action --
    def _pending_item(self, case_id: str, action_key: str):
        e = self.entries.get(case_id)
        if e is None:
            raise KeyError("unknown case")
        item = next((i for i in e.plan.pending if i.proposed.action_key == action_key), None)
        if item is None:
            raise KeyError("no pending action with that key")
        return e, item

    def issue_approval_token(self, case_id: str, action_key: str) -> dict:
        _e, item = self._pending_item(case_id, action_key)
        token, rec = self.approval_tokens.issue(case_id, item.action_id, action_key)
        return {"token": token, "case_id": case_id, "action_id": item.action_id,
                "action_key": action_key, "expires_at": rec.expires_at.isoformat()}

    def _consume_mobile_token(self, case_id: str, action_key: str, item, token: str | None, actor: str):
        if not token:
            raise ApprovalTokenError("mobile approval requires an approval token")
        try:
            return self.approval_tokens.consume(token, case_id, item.action_id, action_key)
        except ApprovalTokenError as exc:
            if "expired" in str(exc):
                self.engine.audit.append(AuditRecord(
                    action_key=action_key, decision="human", status="expired",
                    approver=actor, case_id=case_id, channel="mobile",
                    approval_decision="expired", reason=str(exc)))
            raise

    def approve(self, case_id: str, action_key: str, approval: Approval, token: str | None = None):
        e, item = self._pending_item(case_id, action_key)
        if approval.channel == "mobile":
            self._consume_mobile_token(case_id, action_key, item, token, approval.approver)
        rec = self.engine.approve(item, approval, case_id=case_id)
        e.plan.pending.remove(item)
        e.plan.executed.append(rec)
        if self.operational_store is not None:
            self.operational_store.append_audit(rec)
            self.operational_store.save_case(case_id, self.get_case(case_id) or {}, e.events)
        return rec

    def deny(self, case_id: str, action_key: str, approval: Approval, token: str | None = None):
        e, item = self._pending_item(case_id, action_key)
        self.engine.validate_approval(approval)
        if approval.channel == "mobile":
            self._consume_mobile_token(case_id, action_key, item, token, approval.approver)
        rec = self.engine.audit.append(AuditRecord(
            action_key=action_key, decision="human", status="denied",
            target={}, approver=approval.approver, case_id=case_id,
            reason=f"denied by {approval.approver} ({approval.role})",
            channel=approval.channel, approval_decision="deny"))
        e.plan.pending.remove(item)
        if self.operational_store is not None:
            self.operational_store.append_audit(rec)
            self.operational_store.save_case(case_id, self.get_case(case_id) or {}, e.events)
        return rec


# ---------------------------------------------------------------------------
# Demo seeding (offline, no AWS)
# ---------------------------------------------------------------------------

def build_demo_service() -> CaseService:
    ACC, IP = "111122223333", "185.220.101.5"
    CIBOT = f"arn:aws:iam::{ACC}:user/ci-bot"
    DEPLOY = f"arn:aws:iam::{ACC}:role/deploy"
    SESS = f"arn:aws:sts::{ACC}:assumed-role/deploy/sess1"
    CROWN = "arn:aws:s3:::acme-crown-jewels"
    TRAIL = f"arn:aws:cloudtrail:us-east-1:{ACC}:trail/org-trail"
    POLICY = f"arn:aws:iam::{ACC}:policy/deploy-policy"
    T0 = datetime(2026, 9, 10, 3, 0, tzinfo=timezone.utc)

    def ci(evn, m, t=None, geo="DE"):
        return CloudEvent(ts=T0 + timedelta(minutes=m), account=ACC, region="us-east-1",
                          event=evn, principal=CIBOT, principal_type=PrincipalType.user,
                          geo=geo, src_ip=IP, target=t, raw_ref="r",
                          event_id=f"ci{m}", source=Source.cloudtrail)

    def dep(evn, m, t=None):
        return CloudEvent(ts=T0 + timedelta(minutes=m), account=ACC, region="us-east-1",
                          event=evn, principal=SESS, principal_type=PrincipalType.assumed_role,
                          session=SessionContext(issuer_arn=DEPLOY, issuer_type="Role"),
                          geo="DE", src_ip=IP, target=t, raw_ref="r",
                          event_id=f"dep{m}", source=Source.cloudtrail)

    baseline = [ci("ListBuckets", -120, geo="US")]
    stream = [ci("ListBuckets", 0), ci("AssumeRole", 1, DEPLOY),
              dep("CreatePolicyVersion", 2, POLICY), dep("DescribeInstances", 3),
              dep("ListRoles", 4), dep("GetObject", 5, CROWN), dep("StopLogging", 6, TRAIL)]

    res = DetectionEngine().run(stream, baseline_events=baseline)
    auth = IamAuthorization.from_file(
        settings.sample_data_dir / "iam_auth" / "authz_snapshot_01.json")
    graph, evaluator, _ = prepare_graph(auth)
    cases = build_cases(res.cases, stream, auth, graph, evaluator)

    executor = FakeActionExecutor()
    executor.add_user("ci-bot", {"AKIALEAKED0001": "Active"})
    executor.add_role("deploy")
    executor.add_trail("org-trail", False)          # attacker stopped it -> unhealthy
    engine = ResponseEngine(executor, audit_log=InMemoryAuditLog())
    operational = None
    if settings.database_url:
        operational = PostgresOperationalStore(settings.database_url)
        operational.ensure_schema()
    token_store = RedisApprovalTokenStore(settings.redis_url) if settings.redis_url else None
    svc = CaseService(engine, executor, approval_tokens=token_store, operational_store=operational)
    for c in cases:
        svc.add_case(c, stream)

    # sensitive-resource exposure (from reachable high-sensitivity resources)
    exposure: dict[str, set] = {}
    for c in cases:
        p = getattr(c.blast, "reach_sensitive_path", None)
        if p:
            exposure.setdefault(p.target, set()).add(c.blast.principal)
    svc.exposure = [{"resource": r, "sensitivity": "high",
                     "reachable_by": sorted(who)} for r, who in exposure.items()]
    return svc


# --- shared singleton (overridable in tests via dependency_overrides) ---
_service: Optional[CaseService] = None


def get_case_service() -> CaseService:
    global _service
    if _service is None:
        _service = build_demo_service()
    return _service
