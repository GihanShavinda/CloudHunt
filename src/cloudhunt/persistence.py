"""Optional production persistence adapters for P12.

The test/dev path remains in-memory.  When CLOUDHUNT_DATABASE_URL is configured,
PostgresOperationalStore can persist case projections, normalised events and audit
records without changing the detection/decision architecture.
"""
from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

class PostgresOperationalStore:
    def __init__(self, dsn: str):
        import psycopg
        self._psycopg = psycopg
        self.dsn = dsn

    def ensure_schema(self) -> None:
        ddl = """
        CREATE TABLE IF NOT EXISTS cloudhunt_case_snapshot (
          case_id text PRIMARY KEY, payload jsonb NOT NULL, updated_at timestamptz NOT NULL DEFAULT now());
        CREATE TABLE IF NOT EXISTS cloudhunt_event (
          event_id text PRIMARY KEY, case_id text NOT NULL, payload jsonb NOT NULL);
        CREATE TABLE IF NOT EXISTS cloudhunt_audit (
          record_id text PRIMARY KEY, case_id text, payload jsonb NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
        """
        with self._psycopg.connect(self.dsn) as conn:
            with conn.cursor() as cur: cur.execute(ddl)

    def save_case(self, case_id: str, detail: dict[str, Any], events: list[Any]) -> None:
        with self._psycopg.connect(self.dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("INSERT INTO cloudhunt_case_snapshot(case_id,payload) VALUES(%s,%s::jsonb) ON CONFLICT(case_id) DO UPDATE SET payload=excluded.payload, updated_at=now()", (case_id, json.dumps(detail, default=str)))
                for ev in events:
                    payload = ev.model_dump(mode="json") if hasattr(ev, "model_dump") else vars(ev)
                    cur.execute("INSERT INTO cloudhunt_event(event_id,case_id,payload) VALUES(%s,%s,%s::jsonb) ON CONFLICT(event_id) DO UPDATE SET payload=excluded.payload", (ev.event_id, case_id, json.dumps(payload, default=str)))

    def append_audit(self, record: Any) -> None:
        payload = asdict(record) if hasattr(record, "__dataclass_fields__") else dict(record)
        with self._psycopg.connect(self.dsn) as conn:
            with conn.cursor() as cur:
                cur.execute("INSERT INTO cloudhunt_audit(record_id,case_id,payload) VALUES(%s,%s,%s::jsonb) ON CONFLICT(record_id) DO NOTHING", (record.record_id, record.case_id, json.dumps(payload, default=str)))
