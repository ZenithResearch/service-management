"""SQLite adapter: explicit one-writer transactions and atomic audit/results."""

import json
import os
import sqlite3
import threading
from pathlib import Path
from typing import Callable, TypeVar

from .contracts import canonical
from .domain import Case, ServiceRequest
from .errors import ServiceError

T = TypeVar("T")
SCHEMA_VERSION = 3
MIGRATION_1 = (
    """CREATE TABLE service_requests (
      id TEXT PRIMARY KEY, version INTEGER NOT NULL CHECK(version > 0),
      state TEXT NOT NULL CHECK(state IN ('intake','qualified','accepted','rejected')),
      data_json TEXT NOT NULL)""",
    """CREATE TABLE cases (
      id TEXT PRIMARY KEY, service_request_id TEXT NOT NULL UNIQUE REFERENCES service_requests(id),
      version INTEGER NOT NULL CHECK(version > 0),
      state TEXT NOT NULL CHECK(state IN ('open','planned','closed')), data_json TEXT NOT NULL)""",
    """CREATE TABLE command_results (
      actor TEXT NOT NULL, request_id TEXT NOT NULL, digest TEXT NOT NULL CHECK(length(digest) = 64),
      result_json TEXT NOT NULL, PRIMARY KEY(actor, request_id))""",
    """CREATE TABLE audit_events (
      sequence INTEGER PRIMARY KEY AUTOINCREMENT, event_id TEXT NOT NULL UNIQUE,
      resource_kind TEXT NOT NULL CHECK(resource_kind IN ('ServiceRequest','Case')),
      resource_id TEXT NOT NULL, event_json TEXT NOT NULL)""",
    "CREATE INDEX audit_by_resource ON audit_events(resource_kind, resource_id, sequence)",
)
MIGRATION_2 = (
    """CREATE TABLE case_plan_revisions (
      id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id),
      revision_number INTEGER NOT NULL CHECK(revision_number > 0),
      data_json TEXT NOT NULL, UNIQUE(case_id,revision_number))""",
    """CREATE TABLE service_outbox (
      event_id TEXT PRIMARY KEY, case_id TEXT NOT NULL REFERENCES cases(id),
      revision_id TEXT NOT NULL UNIQUE REFERENCES case_plan_revisions(id),
      state TEXT NOT NULL CHECK(state IN ('pending','started','failed')),
      version INTEGER NOT NULL CHECK(version > 0), data_json TEXT NOT NULL)""",
    "CREATE INDEX pending_service_outbox ON service_outbox(state,event_id)",
    """CREATE TABLE handoff_attempts (
      event_id TEXT NOT NULL REFERENCES service_outbox(event_id), attempt INTEGER NOT NULL,
      result_json TEXT NOT NULL, PRIMARY KEY(event_id,attempt))""",
)

MIGRATION_3 = (
    """CREATE TABLE authority_replays (
      actor TEXT NOT NULL, session TEXT NOT NULL, opcode INTEGER NOT NULL,
      nonce TEXT NOT NULL, digest TEXT NOT NULL CHECK(length(digest)=64),
      PRIMARY KEY(actor,session,opcode,nonce))""",
)


class SQLiteUnitOfWork:
    def __init__(self, database: str | Path, *, timeout: float = 5.0):
        if str(database) == ":memory:":
            raise ValueError("use an explicit file database for durable per-command connections")
        self.database = Path(database).resolve()
        self.timeout = timeout
        self._writer = threading.RLock()
        self.database.parent.mkdir(parents=True, exist_ok=True)
        self._migrate()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.database), timeout=self.timeout, isolation_level=None)
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def _migrate(self):
        with self._writer:
            connection = self._connect()
            try:
                connection.execute("PRAGMA journal_mode = WAL")
                connection.execute("BEGIN IMMEDIATE")
                version = connection.execute("PRAGMA user_version").fetchone()[0]
                if version > SCHEMA_VERSION:
                    raise ValueError("database schema is newer than this service")
                if version == 0:
                    for statement in MIGRATION_1:
                        connection.execute(statement)
                if version < 2:
                    for statement in MIGRATION_2:
                        connection.execute(statement)
                if version < 3:
                    for statement in MIGRATION_3:
                        connection.execute(statement)
                connection.execute("PRAGMA user_version = 3")
                connection.commit()
                os.chmod(self.database, 0o600)
            except BaseException:
                connection.rollback()
                raise
            finally:
                connection.close()

    def transact(self, action: Callable[["SQLiteTransaction"], T]) -> T:
        # RLock serializes this process; BEGIN IMMEDIATE serializes independent
        # processes/adapters. No read-check-write path exists outside this lock.
        with self._writer:
            connection = None
            try:
                connection = self._connect()
                connection.execute("BEGIN IMMEDIATE")
                result = action(SQLiteTransaction(connection))
                connection.commit()
                return result
            except sqlite3.IntegrityError:
                raise ServiceError("resource_conflict") from None
            except sqlite3.DatabaseError:
                raise ServiceError("storage_unavailable") from None
            finally:
                if connection is not None:
                    if connection.in_transaction:
                        connection.rollback()
                    connection.close()

    def health(self) -> bool:
        """Bounded metadata/writer check; no business rows or database creation."""
        connection = None
        try:
            connection = sqlite3.connect(self.database.as_uri() + "?mode=rw", uri=True,
                                         timeout=min(self.timeout, 0.25), isolation_level=None)
            connection.execute("BEGIN IMMEDIATE")
            if connection.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION:
                return False
            tables = {row[0] for row in connection.execute("SELECT name FROM sqlite_schema WHERE type='table'")}
            return {"service_requests", "cases", "command_results", "audit_events",
                    "case_plan_revisions", "service_outbox", "handoff_attempts", "authority_replays"} <= tables
        except (sqlite3.DatabaseError, OSError):
            return False
        finally:
            if connection is not None:
                if connection.in_transaction:
                    connection.rollback()
                connection.close()

    def audit_history(self, kind: str, identifier: str, *, limit: int = 100, after_sequence: int = 0) -> list[dict]:
        """Adapter diagnostics, not an unauthenticated public HTTP read route."""
        if kind not in {"ServiceRequest", "Case"} or type(limit) is not int or not 1 <= limit <= 100 or type(after_sequence) is not int or after_sequence < 0:
            raise ValueError("invalid bounded audit query")
        connection = self._connect()
        try:
            return [{"sequence": row[0], "event": json.loads(row[1])} for row in connection.execute(
                "SELECT sequence,event_json FROM audit_events WHERE resource_kind=? AND resource_id=? AND sequence>? ORDER BY sequence LIMIT ?",
                (kind, identifier, after_sequence, limit))]
        finally:
            connection.close()


class SQLiteTransaction:
    def __init__(self, connection: sqlite3.Connection):
        self._connection = connection

    def admit_replay(self, actor: str, session: str, opcode: int, nonce: str, digest: str):
        try:
            self._connection.execute("INSERT INTO authority_replays(actor,session,opcode,nonce,digest) VALUES(?,?,?,?,?)",
                                     (actor, session, opcode, nonce, digest))
        except sqlite3.IntegrityError:
            raise ServiceError("forbidden") from None

    def _get(self, table: str, model, identifier: str):
        row = self._connection.execute(f"SELECT version,state,data_json FROM {table} WHERE id=?", (identifier,)).fetchone()
        if row is None:
            return None
        try:
            item = model(**json.loads(row[2]))
            if item.id != identifier or item.version != row[0] or item.state != row[1]:
                raise ValueError("stored index/snapshot disagreement")
            return item
        except (ValueError, TypeError, KeyError):
            raise ServiceError("storage_unavailable") from None

    def get_request(self, identifier: str) -> ServiceRequest | None:
        return self._get("service_requests", ServiceRequest, identifier)

    def get_case(self, identifier: str) -> Case | None:
        item = self._get("cases", Case, identifier)
        if item is not None:
            parent = self._connection.execute("SELECT service_request_id FROM cases WHERE id=?", (identifier,)).fetchone()[0]
            if item.service_request_id != parent:
                raise ServiceError("storage_unavailable")
        return item

    def insert_request(self, item: ServiceRequest):
        self._connection.execute("INSERT INTO service_requests(id,version,state,data_json) VALUES(?,?,?,?)",
                                 (item.id, item.version, item.state, canonical(item.as_dict())))

    def insert_case(self, item: Case):
        self._connection.execute("INSERT INTO cases(id,service_request_id,version,state,data_json) VALUES(?,?,?,?,?)",
                                 (item.id, item.service_request_id, item.version, item.state, canonical(item.as_dict())))

    def _update(self, table: str, item, expected_version: int):
        if item.version != expected_version + 1:
            raise ValueError("aggregate update must increment version exactly once")
        changed = self._connection.execute(f"UPDATE {table} SET version=?,state=?,data_json=? WHERE id=? AND version=?",
                                           (item.version, item.state, canonical(item.as_dict()), item.id, expected_version)).rowcount
        if changed != 1:
            raise ServiceError("version_conflict")

    def update_request(self, item: ServiceRequest, expected_version: int):
        self._update("service_requests", item, expected_version)

    def update_case(self, item: Case, expected_version: int):
        self._update("cases", item, expected_version)

    def find_result(self, actor: str, request_id: str) -> tuple[str, dict] | None:
        row = self._connection.execute("SELECT digest,result_json FROM command_results WHERE actor=? AND request_id=?", (actor, request_id)).fetchone()
        if row is None:
            return None
        try:
            response = json.loads(row[1])
            if not isinstance(response, dict) or response.get("schema") != "service.result.v1" or response.get("request_id") != request_id:
                raise ValueError("invalid retained result")
            return row[0], response
        except (ValueError, TypeError):
            raise ServiceError("storage_unavailable") from None

    def save_result(self, actor: str, request_id: str, digest: str, result: dict):
        self._connection.execute("INSERT INTO command_results(actor,request_id,digest,result_json) VALUES(?,?,?,?)",
                                 (actor, request_id, digest, canonical(result)))

    def append_event(self, event: dict):
        self._connection.execute("INSERT INTO audit_events(event_id,resource_kind,resource_id,event_json) VALUES(?,?,?,?)",
                                 (event["event_id"], event["resource"]["kind"], event["resource"]["id"], canonical(event)))

    @staticmethod
    def _record(row):
        if row is None:
            return None
        try:
            value = json.loads(row[0])
            if not isinstance(value, dict): raise ValueError()
            return value
        except (ValueError, TypeError):
            raise ServiceError("storage_unavailable") from None

    def get_revision(self, identifier: str) -> dict | None:
        value = self._record(self._connection.execute("SELECT data_json FROM case_plan_revisions WHERE id=?", (identifier,)).fetchone())
        if value is not None and (value.get("schema") != "service.case-plan-revision.v1" or value.get("id") != identifier):
            raise ServiceError("storage_unavailable")
        return value

    def insert_revision(self, revision: dict):
        self._connection.execute("INSERT INTO case_plan_revisions(id,case_id,revision_number,data_json) VALUES(?,?,?,?)",
                                 (revision["id"], revision["case_id"], revision["revision_number"], canonical(revision)))

    def revision_history(self, case_id: str, after: int, limit: int) -> list[dict]:
        if type(limit) is not int or not 1 <= limit <= 100 or type(after) is not int or after < 0:
            raise ValueError("invalid bounded revision query")
        return [self._record(row) for row in self._connection.execute("SELECT data_json FROM case_plan_revisions WHERE case_id=? AND revision_number>? ORDER BY revision_number LIMIT ?", (case_id, after, limit))]

    def get_handoff(self, event_id: str) -> dict | None:
        row = self._connection.execute("SELECT data_json,state,version FROM service_outbox WHERE event_id=?", (event_id,)).fetchone()
        value = self._record(row)
        if value is not None and (value.get("event_id") != event_id or value.get("state") != row[1] or value.get("version") != row[2]):
            raise ServiceError("storage_unavailable")
        return value

    def handoff_for_revision(self, revision_id: str) -> dict | None:
        row = self._connection.execute("SELECT event_id FROM service_outbox WHERE revision_id=?", (revision_id,)).fetchone()
        return self.get_handoff(row[0]) if row else None

    def insert_handoff(self, handoff: dict):
        self._connection.execute("INSERT INTO service_outbox(event_id,case_id,revision_id,state,version,data_json) VALUES(?,?,?,?,?,?)",
                                 (handoff["event_id"], handoff["case_id"], handoff["revision_id"], handoff["state"], handoff["version"], canonical(handoff)))

    def update_handoff(self, handoff: dict, expected_version: int):
        before = self.get_handoff(handoff["event_id"])
        if before is None or before["version"] != expected_version or handoff["version"] != expected_version + 1:
            raise ServiceError("version_conflict")
        if any(handoff[key] != before[key] for key in ("event_id", "case_id", "revision_id", "command")):
            raise ValueError("retained handoff identity and command are immutable")
        changed = self._connection.execute("UPDATE service_outbox SET state=?,version=?,data_json=? WHERE event_id=? AND version=?",
                                           (handoff["state"], handoff["version"], canonical(handoff), handoff["event_id"], expected_version)).rowcount
        if changed != 1: raise ServiceError("version_conflict")

    def pending_handoffs(self, after: str = "", limit: int = 100) -> list[dict]:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("invalid bounded outbox query")
        rows = self._connection.execute("SELECT event_id FROM service_outbox WHERE state='pending' AND event_id>? ORDER BY event_id LIMIT ?", (after, limit))
        return [self.get_handoff(row[0]) for row in rows]

    def handoff_counts(self) -> dict:
        counts = {"pending": 0, "started": 0, "failed": 0}
        for state, count in self._connection.execute("SELECT state,count(*) FROM service_outbox GROUP BY state"):
            counts[state] = count
        row = self._connection.execute("SELECT data_json FROM service_outbox WHERE state='pending' AND json_extract(data_json,'$.last_error') IS NOT NULL ORDER BY event_id LIMIT 1").fetchone()
        counts["pending_error"] = json.loads(row[0])["last_error"] if row else None
        return counts

    def record_delivery_attempt(self, event_id: str, attempt: int, result: dict):
        self._connection.execute("INSERT INTO handoff_attempts(event_id,attempt,result_json) VALUES(?,?,?) ON CONFLICT(event_id,attempt) DO UPDATE SET result_json=excluded.result_json",
                                 (event_id, attempt, canonical(result)))
