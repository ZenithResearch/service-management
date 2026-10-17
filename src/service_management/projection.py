"""Disposable redacted runtime progress views; never canonical lifecycle state."""

import json
from contextlib import closing
import sqlite3
import threading
import time
from pathlib import Path

from .contracts import canonical
from .errors import ServiceError
from .runtime_port import content_digest, query_data, runtime_id

APPLICATION_ID = 0x53565031
EVENT_FIELDS = {"schema", "event_id", "sequence", "kind", "resource", "resource_version", "request_id", "correlation_id", "recorded_at_ms", "data"}
KINDS = {"process.draft_updated", "process.published", "run.created", "run.cancelled", "run.retried", "run.succeeded", "run.failed", "run.blocked", "actor.registered", "actor.advertised", "attempt.claimed", "attempt.heartbeat", "attempt.completed", "attempt.failed", "attempt.released", "attempt.expired", "output.committed", "artifact.committed", "handoff.accepted", "effect.intent", "effect.dispatched", "effect.observed", "effect.resolved"}


class RuntimeProjection:
    def __init__(self, filename: str | Path, *, clock=time.time):
        self.filename, self.clock, self._lock = Path(filename).resolve(), clock, threading.RLock()
        self.filename.parent.mkdir(parents=True, exist_ok=True)
        with closing(self._connect()) as connection:
            app_id = connection.execute("PRAGMA application_id").fetchone()[0]
            tables = connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
            if app_id != APPLICATION_ID and (app_id != 0 or tables):
                raise ValueError("projection must use its own empty disposable database")
            connection.execute("PRAGMA journal_mode=WAL")
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(f"PRAGMA application_id={APPLICATION_ID}")
            connection.execute("CREATE TABLE IF NOT EXISTS metadata (id INTEGER PRIMARY KEY CHECK(id=1),cursor INTEGER NOT NULL,freshness TEXT NOT NULL,observed_at REAL)")
            connection.execute("INSERT OR IGNORE INTO metadata(id,cursor,freshness,observed_at) VALUES(1,0,'unavailable',NULL)")
            if "rebuild_json" not in {row[1] for row in connection.execute("PRAGMA table_info(metadata)")}:
                connection.execute("ALTER TABLE metadata ADD COLUMN rebuild_json TEXT")
            connection.execute("CREATE TABLE IF NOT EXISTS observed_events (sequence INTEGER PRIMARY KEY,event_id TEXT UNIQUE NOT NULL,digest TEXT NOT NULL)")
            connection.execute("CREATE TABLE IF NOT EXISTS run_summaries (run_id TEXT PRIMARY KEY,data_json TEXT NOT NULL)")
            connection.commit()
        self.filename.chmod(0o600)

    def _connect(self):
        return sqlite3.connect(self.filename, isolation_level=None, timeout=5)

    def _mark(self, state):
        with self._lock, closing(self._connect()) as connection:
            connection.execute("UPDATE metadata SET freshness=? WHERE id=1", (state,))

    def health(self) -> dict:
        with closing(self._connect()) as connection:
            cursor, freshness, observed_at, rebuild_json = connection.execute("SELECT cursor,freshness,observed_at,rebuild_json FROM metadata WHERE id=1").fetchone()
        age = max(0, self.clock() - observed_at) if observed_at is not None else None
        if freshness == "current" and age > 60: freshness = "stale"
        return {"cursor": cursor, "freshness": freshness, "observed_at": observed_at, "age_seconds": age, "last_rebuild": json.loads(rebuild_json) if rebuild_json else None}

    @staticmethod
    def _validate(event):
        if (not isinstance(event, dict) or set(event) != EVENT_FIELDS or event["schema"] != "runtime.event.v1"
                or not isinstance(event["kind"], str) or event["kind"] not in KINDS or not runtime_id(event["event_id"])
                or not runtime_id(event["request_id"]) or not runtime_id(event["correlation_id"])
                or any(type(event[field]) is not int or event[field] < 1 for field in ("sequence", "resource_version", "recorded_at_ms"))
                or not isinstance(event["resource"], str) or len(event["resource"]) > 4096
                or not isinstance(event["data"], dict) or len(event["data"]) > 128):
            raise ServiceError("runtime_contract")

    def apply_page(self, events: list[dict], *, caught_up=True):
        if not isinstance(events, list) or len(events) > 100: raise ServiceError("runtime_contract")
        with self._lock:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                cursor = connection.execute("SELECT cursor FROM metadata WHERE id=1").fetchone()[0]
                for event in events:
                    self._validate(event)
                    digest = content_digest(event)
                    if event["sequence"] <= cursor:
                        row = connection.execute("SELECT event_id,digest FROM observed_events WHERE sequence=?", (event["sequence"],)).fetchone()
                        if row != (event["event_id"], digest): raise ServiceError("projection_gap")
                        continue
                    if event["sequence"] != cursor + 1: raise ServiceError("projection_gap")
                    connection.execute("INSERT INTO observed_events VALUES(?,?,?)", (event["sequence"], event["event_id"], digest))
                    self._reduce(connection, event)
                    cursor = event["sequence"]
                connection.execute("UPDATE metadata SET cursor=?,freshness=?,observed_at=? WHERE id=1", (cursor, "current" if caught_up else "catching_up", self.clock()))
                connection.commit()
            except (ServiceError, sqlite3.IntegrityError, ValueError, TypeError):
                connection.rollback()
                self._mark("gap")
                raise ServiceError("projection_gap") from None
            finally:
                connection.close()

    @staticmethod
    def _reduce(connection, event):
        parts = event["resource"].split("/")
        resource_run = parts[1] if len(parts) in {2, 4} and parts[0] in {"run", "runs"} and runtime_id(parts[1]) else None
        run_id = event["data"].get("run_id", resource_run)
        if run_id is None: return
        if not runtime_id(run_id) or (resource_run is not None and resource_run != run_id): raise ServiceError("runtime_contract")
        resource_step = parts[3] if len(parts) == 4 and parts[2] in {"step", "steps"} and runtime_id(parts[3]) else None
        step_id = event["data"].get("step_id", resource_step)
        if step_id is not None and (not runtime_id(step_id) or (resource_step is not None and resource_step != step_id)): raise ServiceError("runtime_contract")
        row = connection.execute("SELECT data_json FROM run_summaries WHERE run_id=?", (run_id,)).fetchone()
        view = json.loads(row[0]) if row else {"run_id": run_id, "state": "unknown", "steps": {}, "source_version": 0, "source_sequence": 0, "source_resource": event["resource"]}
        kind = event["kind"]
        run_states = {"run.created": "pending", "run.cancelled": "cancelled", "run.retried": "running", "run.succeeded": "succeeded", "run.failed": "failed", "run.blocked": "blocked"}
        if kind in run_states: view["state"] = run_states[kind]
        run_state = event["data"].get("run_state")
        if run_state is None and kind in {"attempt.completed", "handoff.accepted", "run.created", "run.cancelled", "run.retried"}:
            run_state = event["data"].get("state")
        if run_state is not None:
            if run_state not in {"pending", "running", "blocked", "succeeded", "failed", "cancelled"}: raise ServiceError("runtime_contract")
            view["state"] = run_state
        states = {"attempt.claimed": "running", "attempt.completed": "succeeded", "attempt.failed": "failed", "attempt.released": "waiting", "attempt.expired": "waiting"}
        if step_id and kind in states:
            if step_id not in view["steps"] and len(view["steps"]) >= 1000: raise ServiceError("runtime_contract")
            step_state = event["data"].get("step_state", event["data"].get("state") if kind in {"attempt.failed", "attempt.released", "attempt.expired"} else states[kind])
            if step_state not in {"waiting", "ready", "running", "blocked", "succeeded", "failed", "cancelled"}: raise ServiceError("runtime_contract")
            view["steps"][step_id] = {"step_id": step_id, "state": step_state}
            if kind == "attempt.claimed" and view["state"] not in {"succeeded", "failed", "cancelled"}: view["state"] = "running"
        view.update(source_version=event["resource_version"], source_sequence=event["sequence"], source_resource=event["resource"])
        connection.execute("INSERT INTO run_summaries VALUES(?,?) ON CONFLICT(run_id) DO UPDATE SET data_json=excluded.data_json", (run_id, canonical(view)))

    def run(self, run_id: str) -> dict | None:
        if not runtime_id(run_id): raise ValueError("invalid run identity")
        with closing(self._connect()) as connection:
            row = connection.execute("SELECT data_json FROM run_summaries WHERE run_id=?", (run_id,)).fetchone()
        if row is None: return None
        view = json.loads(row[0])
        steps = sorted(view["steps"].values(), key=lambda step: step["step_id"])
        return {**view, "steps": steps, "completion": {"observed_steps": len(steps), "succeeded_steps": sum(step["state"] == "succeeded" for step in steps)},
                "blockers": {"run_blocked": view["state"] == "blocked", "observed_failed_steps": sum(step["state"] == "failed" for step in steps)}}

    def sync(self, runtime, *, limit=100):
        if type(limit) is not int or not 1 <= limit <= 100: raise ValueError("invalid event page size")
        try:
            cursor = self.health()["cursor"]
            data = query_data(runtime, "events.list", {"after": cursor, "limit": limit})
            events = data.get("events")
            if set(data) != {"events", "next_cursor", "high_watermark"} or not isinstance(events, list) or len(events) > limit: raise ServiceError("runtime_contract")
            for event in events: self._validate(event)
            next_cursor = events[-1]["sequence"] if events else cursor
            if type(data["next_cursor"]) is not int or data["next_cursor"] != next_cursor: raise ServiceError("runtime_contract")
            high_watermark = data.get("high_watermark")
            if type(high_watermark) is not int or high_watermark < next_cursor: raise ServiceError("runtime_contract")
            if (not events and cursor != high_watermark) or any(event["sequence"] != cursor + index + 1 for index, event in enumerate(events)):
                raise ServiceError("projection_gap")
            self.apply_page(events, caught_up=next_cursor >= high_watermark)
            return self.health()
        except ServiceError as error:
            self._mark("gap" if error.code == "projection_gap" else "unavailable")
            raise

    def reset_for_rebuild(self):
        """Deletes only derived view data; replay must start at retained cursor zero."""
        with self._lock, closing(self._connect()) as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DELETE FROM observed_events")
            connection.execute("DELETE FROM run_summaries")
            connection.execute("UPDATE metadata SET cursor=0,freshness='unavailable',observed_at=NULL WHERE id=1")
            connection.commit()

    def begin_rebuild(self):
        before = {"cursor": self.health()["cursor"], "fingerprint": self.fingerprint()}
        self.reset_for_rebuild()
        return before

    def finish_rebuild(self, before):
        health = self.health()
        if health["freshness"] != "current":
            raise ServiceError("projection_gap")
        hash_after = self.fingerprint()
        diagnostic = {"cursor_before": before["cursor"], "cursor_after": health["cursor"],
                      "hash_before": before["fingerprint"], "hash_after": hash_after,
                      "drift_detected": before["cursor"] == health["cursor"] and before["fingerprint"] != hash_after}
        with closing(self._connect()) as connection:
            connection.execute("UPDATE metadata SET rebuild_json=? WHERE id=1", (canonical(diagnostic),))
        return self.health()

    def rebuild(self, runtime, *, max_pages=1000):
        if type(max_pages) is not int or not 1 <= max_pages <= 10000: raise ValueError("invalid rebuild bound")
        before = self.begin_rebuild()
        for _ in range(max_pages):
            health = self.sync(runtime)
            if health["freshness"] == "current":
                return self.finish_rebuild(before)
        self._mark("gap")
        raise ServiceError("projection_gap")

    def fingerprint(self):
        with closing(self._connect()) as connection:
            rows = connection.execute("SELECT run_id,data_json FROM run_summaries ORDER BY run_id").fetchall()
        return content_digest(rows)
