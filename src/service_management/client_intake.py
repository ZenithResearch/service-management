"""Durable provider intake between a reachable inbox and Service Management.

Transport authentication and requester authority are deliberately independent:
an ``EnvelopeOpener`` authenticates/decrypts the transport envelope, while a
``RequesterVerifier`` verifies the included requester evidence.  Neither can
mint Service Management authority.  The admission worker receives that
authority through the existing command ingress port.
"""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import threading
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Callable, Protocol

from .contracts import MAX_VERSION, canonical, identifier, load_json
from .errors import ServiceError


MAX_INTAKE_BODY = 65_536
MAX_EVIDENCE_BODY = 262_144
SHA256 = set("0123456789abcdef")


def _digest(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _sha256(value: object) -> bool:
    return isinstance(value, str) and len(value) == 64 and set(value) <= SHA256


def _timestamp(value: object) -> bool:
    if not isinstance(value, str) or len(value) > 64 or not value.endswith("Z"):
        return False
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
        return parsed.tzinfo is not None
    except ValueError:
        return False


def _text(value: object, maximum: int, *, empty: bool = False) -> bool:
    return isinstance(value, str) and len(value) <= maximum and "\x00" not in value and (empty or bool(value.strip()))


@dataclass(frozen=True)
class Intake:
    request_id: str
    idempotency_key: str
    provider_id: str
    service_id: str
    service_version: str
    brief_revision: int
    brief_hash: str
    brief_values_json: str
    references_json: str
    submitted_at: str
    raw_json: str

    @classmethod
    def parse(cls, raw: bytes) -> "Intake":
        if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_INTAKE_BODY:
            raise ServiceError("invalid_json")
        value = load_json(raw)  # load_json also rejects duplicate keys/numbers.
        required = {"schema", "request_id", "idempotency_key", "service", "brief", "references", "submitted_at"}
        if set(value) != required or value["schema"] != "service.intake.v1":
            raise ServiceError("invalid_command")
        if not identifier(value["request_id"]) or not identifier(value["idempotency_key"]):
            raise ServiceError("invalid_command")

        service = value["service"]
        if (not isinstance(service, dict) or set(service) != {"provider_id", "service_id", "service_version"}
                or not identifier(service["provider_id"]) or not identifier(service["service_id"])
                or not _text(service["service_version"], 128)):
            raise ServiceError("invalid_command")

        brief = value["brief"]
        if (not isinstance(brief, dict) or set(brief) != {"schema", "revision", "content_hash", "values"}
                or brief["schema"] != "service.reviewed-brief.v1"
                or type(brief["revision"]) is not int or not 1 <= brief["revision"] <= MAX_VERSION
                or not _sha256(brief["content_hash"]) or not isinstance(brief["values"], dict)):
            raise ServiceError("invalid_command")
        try:
            values_json = canonical(brief["values"])
        except (TypeError, ValueError, RecursionError):
            raise ServiceError("invalid_command") from None
        if len(values_json.encode("utf-8")) > 131_072 or _digest(values_json.encode("utf-8")) != brief["content_hash"]:
            raise ServiceError("invalid_command")

        references = value["references"]
        if not isinstance(references, list) or len(references) > 128:
            raise ServiceError("invalid_command")
        seen = set()
        for artifact in references:
            fields = {"schema", "artifact_id", "content_hash", "byte_length", "media_type", "filename"}
            if (not isinstance(artifact, dict) or set(artifact) != fields
                    or artifact["schema"] != "service.artifact-manifest.v1"
                    or not identifier(artifact["artifact_id"]) or artifact["artifact_id"] in seen
                    or not _sha256(artifact["content_hash"])
                    or type(artifact["byte_length"]) is not int or not 0 <= artifact["byte_length"] <= 2**53 - 1
                    or not _text(artifact["media_type"], 255) or not _text(artifact["filename"], 1024)):
                raise ServiceError("invalid_command")
            seen.add(artifact["artifact_id"])
        if not _timestamp(value["submitted_at"]):
            raise ServiceError("invalid_command")
        try:
            raw_json = canonical(value)
            references_json = canonical(references)
        except (TypeError, ValueError, RecursionError):
            raise ServiceError("invalid_command") from None
        return cls(value["request_id"], value["idempotency_key"], service["provider_id"], service["service_id"],
                   service["service_version"], brief["revision"], brief["content_hash"], values_json,
                   references_json, value["submitted_at"], raw_json)

    @property
    def digest(self) -> str:
        return _digest(self.raw_json.encode("utf-8"))

    @property
    def values(self) -> dict:
        return json.loads(self.brief_values_json)


@dataclass(frozen=True)
class TransportReceipt:
    transport: str
    receipt_id: str
    recorded_at: str
    expires_at: str | None

    def as_dict(self) -> dict:
        return {"transport": self.transport, "receipt_id": self.receipt_id,
                "recorded_at": self.recorded_at, "expires_at": self.expires_at}

    def validate(self) -> None:
        if (not _text(self.transport, 64) or not identifier(self.receipt_id) or not _timestamp(self.recorded_at)
                or (self.expires_at is not None and not _timestamp(self.expires_at))):
            raise ValueError("invalid transport receipt")


@dataclass(frozen=True)
class OpenedEnvelope:
    intake: bytes
    requester_evidence: bytes


@dataclass(frozen=True)
class Delivery:
    handle: str
    payload: bytes
    receipt: TransportReceipt


class ReachableInbox(Protocol):
    def pull(self, limit: int) -> list[Delivery]: ...
    def acknowledge(self, handle: str) -> None: ...


class EnvelopeOpener(Protocol):
    def open(self, payload: bytes) -> OpenedEnvelope:
        """Authenticate/decrypt transport; never infer requester authority."""
        ...


@dataclass(frozen=True)
class VerifiedRequester:
    subject: str
    membership_credential_id: str

    def __post_init__(self):
        if not identifier(self.subject) or not identifier(self.membership_credential_id):
            raise ValueError("invalid requester binding")


class RequesterVerifier(Protocol):
    def verify(self, intake: Intake, evidence: bytes, receipt: TransportReceipt) -> VerifiedRequester:
        """Verify membership and exact-request authority at trusted receipt time."""
        ...


class ServiceCommandPort(Protocol):
    def submit(self, command: bytes) -> dict:
        """Submit using separately configured Service Management authority."""
        ...


class ExactAuthorityIssuer(Protocol):
    def issue(self, command: bytes) -> bytes:
        """Issue native evidence bound to these exact canonical command bytes."""
        ...

    def resume(self, command: bytes) -> bytes:
        """Recover only the exact previously started native issuance."""
        ...


class NativeAuthorizedServicePort:
    """Bind the retained command to native authority, then use canonical ingress.

    The issuer is trusted operator composition.  Intake/requester evidence is
    never passed to it as a substitute for Service Management authority.
    """

    def __init__(self, ingress, issuer: ExactAuthorityIssuer):
        if not callable(getattr(ingress, "submit", None)):
            raise ValueError("Service ingress submit port required")
        self.ingress, self.issuer = ingress, issuer

    def submit(self, command: bytes) -> dict:
        # Parsing here closes accidental/noncanonical worker inputs before a
        # native signer is invoked. Ingress repeats the authoritative parse.
        parsed = load_json(command)
        if canonical(parsed).encode("utf-8") != command:
            raise ServiceError("invalid_command")
        evidence = self.issuer.issue(command)
        return self._submit(command, evidence)

    def resume(self, command: bytes) -> dict:
        parsed = load_json(command)
        if canonical(parsed).encode("utf-8") != command:
            raise ServiceError("invalid_command")
        recover = getattr(self.issuer, "resume", None)
        if not callable(recover):
            raise ServiceError("forbidden")
        evidence = recover(command)
        return self._submit(command, evidence)

    def _submit(self, command: bytes, evidence: bytes) -> dict:
        if not isinstance(evidence, bytes) or not evidence or len(evidence) > 1_048_576:
            raise ServiceError("forbidden")
        return self.ingress.submit(command, authority_evidence=evidence)


class UnknownAdmissionOutcome(Exception):
    """The caller cannot know whether the stable command committed."""


class IntakeStore:
    """Separate durable inbox state; the canonical service DB remains authoritative."""

    SCHEMA_VERSION = 3

    def __init__(self, database: str | Path, *, timeout: float = 5.0):
        if str(database) == ":memory:":
            raise ValueError("durable intake requires a file database")
        self.database = Path(database).resolve()
        self.timeout = timeout
        self._writer = threading.RLock()
        self.database.parent.mkdir(parents=True, exist_ok=True)
        self._migrate()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(str(self.database), timeout=self.timeout, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA synchronous = FULL")
        return connection

    def _migrate(self) -> None:
        with self._writer:
            connection = self._connect()
            try:
                connection.execute("PRAGMA journal_mode = WAL")
                connection.execute("BEGIN IMMEDIATE")
                version = connection.execute("PRAGMA user_version").fetchone()[0]
                if version > self.SCHEMA_VERSION:
                    raise ValueError("intake database schema is newer than this service")
                if version == 0:
                    connection.execute("""CREATE TABLE client_intake (
                        request_id TEXT PRIMARY KEY, idempotency_key TEXT NOT NULL UNIQUE,
                        intake_digest TEXT NOT NULL CHECK(length(intake_digest)=64), intake_json TEXT NOT NULL,
                        requester_evidence BLOB NOT NULL, transport_receipt_json TEXT NOT NULL,
                        state TEXT NOT NULL CHECK(state IN ('pending','admitted','rejected')),
                        command_digest TEXT, command_json TEXT,
                        requester_subject TEXT, membership_credential_id TEXT,
                        service_result_json TEXT, rejection_code TEXT)""")
                    connection.execute("CREATE INDEX client_intake_pending ON client_intake(state,request_id)")
                if version < 2:
                    connection.execute("""ALTER TABLE client_intake ADD COLUMN authority_state TEXT NOT NULL
                        DEFAULT 'fresh' CHECK(authority_state IN ('fresh','resume_required'))""")
                    connection.execute("CREATE INDEX client_intake_authority ON client_intake(state,authority_state,request_id)")
                if version < 3:
                    connection.execute("""CREATE TABLE provider_lifecycle (
                        request_id TEXT PRIMARY KEY REFERENCES client_intake(request_id),
                        stage TEXT NOT NULL CHECK(stage IN (
                            'request_admitted','qualified','accepted','converted','planned',
                            'brief_stored','references_stored','approved')),
                        command_target TEXT CHECK(command_target IN ('service','runtime')),
                        command_digest TEXT, command_json TEXT,
                        authority_state TEXT NOT NULL DEFAULT 'fresh'
                            CHECK(authority_state IN ('fresh','resume_required')),
                        last_result_json TEXT,
                        CHECK((command_target IS NULL AND command_digest IS NULL AND command_json IS NULL)
                           OR (command_target IS NOT NULL AND command_digest IS NOT NULL AND command_json IS NOT NULL)))""")
                    connection.execute("""INSERT INTO provider_lifecycle(request_id,stage)
                        SELECT request_id,'request_admitted' FROM client_intake WHERE state='admitted'""")
                    connection.execute("CREATE INDEX provider_lifecycle_pending ON provider_lifecycle(stage,authority_state,request_id)")
                connection.execute("PRAGMA user_version = 3")
                connection.commit()
                os.chmod(self.database, 0o600)
            except BaseException:
                connection.rollback()
                raise
            finally:
                connection.close()

    def ingest(self, opened: OpenedEnvelope, receipt: TransportReceipt) -> dict:
        if not isinstance(opened.requester_evidence, bytes) or not 0 < len(opened.requester_evidence) <= MAX_EVIDENCE_BODY:
            raise ServiceError("invalid_command")
        receipt.validate()
        intake = Intake.parse(opened.intake)
        intake_json = intake.raw_json
        receipt_json = canonical(receipt.as_dict())
        with self._writer:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                rows = connection.execute(
                    "SELECT * FROM client_intake WHERE request_id=? OR idempotency_key=?",
                    (intake.request_id, intake.idempotency_key)).fetchall()
                if rows:
                    if (len(rows) != 1 or rows[0]["request_id"] != intake.request_id
                            or rows[0]["idempotency_key"] != intake.idempotency_key
                            or rows[0]["intake_digest"] != intake.digest
                            or bytes(rows[0]["requester_evidence"]) != opened.requester_evidence):
                        raise ServiceError("idempotency_conflict")
                    result = self._result(rows[0])
                else:
                    connection.execute("""INSERT INTO client_intake(
                        request_id,idempotency_key,intake_digest,intake_json,requester_evidence,
                        transport_receipt_json,state) VALUES(?,?,?,?,?,?, 'pending')""",
                        (intake.request_id, intake.idempotency_key, intake.digest, intake_json,
                         opened.requester_evidence, receipt_json))
                    result = self._result(connection.execute(
                        "SELECT * FROM client_intake WHERE request_id=?", (intake.request_id,)).fetchone())
                connection.commit()
                return result
            except sqlite3.DatabaseError:
                connection.rollback()
                raise ServiceError("storage_unavailable") from None
            finally:
                connection.close()

    @staticmethod
    def _result(row: sqlite3.Row) -> dict:
        result = json.loads(row["service_result_json"]) if row["service_result_json"] else None
        request = result.get("service_request") if result else None
        return {"schema": "service.intake-result.v1", "request_id": row["request_id"],
                "idempotency_key": row["idempotency_key"], "state": row["state"],
                "transport_receipt": json.loads(row["transport_receipt_json"]),
                "service_request_id": request.get("id") if request else None,
                "service_request_version": request.get("version") if request else None,
                "status_url": f"/v1/client/requests/{row['request_id']}"}

    def pending(self, *, limit: int = 16, recovery: bool = False) -> list[dict]:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("invalid intake batch")
        connection = self._connect()
        try:
            authority_state = "resume_required" if recovery else "fresh"
            return [dict(row) for row in connection.execute(
                "SELECT * FROM client_intake WHERE state='pending' AND authority_state=? ORDER BY request_id LIMIT ?",
                (authority_state, limit))]
        finally:
            connection.close()

    def get(self, request_id: str) -> dict | None:
        if not identifier(request_id):
            raise ValueError("invalid request id")
        connection = self._connect()
        try:
            row = connection.execute("SELECT * FROM client_intake WHERE request_id=?", (request_id,)).fetchone()
            return self._result(row) if row else None
        finally:
            connection.close()

    def retain_command(self, request_id: str, command: bytes, requester: VerifiedRequester) -> None:
        digest = _digest(command)
        with self._writer:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute("SELECT state,command_digest FROM client_intake WHERE request_id=?", (request_id,)).fetchone()
                if row is None:
                    raise ServiceError("not_found")
                if row["state"] != "pending":
                    connection.commit(); return
                if row["command_digest"] is not None and row["command_digest"] != digest:
                    raise ServiceError("idempotency_conflict")
                connection.execute("""UPDATE client_intake SET command_digest=?,command_json=?,
                    requester_subject=?,membership_credential_id=? WHERE request_id=?""",
                    (digest, command.decode("utf-8"), requester.subject, requester.membership_credential_id, request_id))
                connection.commit()
            except sqlite3.DatabaseError:
                connection.rollback()
                raise ServiceError("storage_unavailable") from None
            finally:
                connection.close()

    def begin_authority(self, request_id: str, command_digest: str) -> None:
        """Durably require explicit native resume before starting issuance.

        The marker is committed before the Wallet process is launched. A host
        crash can therefore hold a command that never reached Wallet, but it can
        never make restart silently repeat ``issue`` after Wallet did receive it.
        """
        if not _sha256(command_digest):
            raise ValueError("invalid command digest")
        with self._writer:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT state,command_digest,authority_state FROM client_intake WHERE request_id=?",
                    (request_id,)).fetchone()
                if row is None:
                    raise ServiceError("not_found")
                if row["state"] != "pending":
                    connection.commit(); return
                if row["command_digest"] != command_digest:
                    raise ServiceError("idempotency_conflict")
                connection.execute(
                    "UPDATE client_intake SET authority_state='resume_required' "
                    "WHERE request_id=? AND state='pending' AND authority_state='fresh'",
                    (request_id,))
                connection.commit()
            except sqlite3.DatabaseError:
                connection.rollback()
                raise ServiceError("storage_unavailable") from None
            finally:
                connection.close()

    def admit(self, request_id: str, command_digest: str, result: dict) -> None:
        if (not isinstance(result, dict) or result.get("schema") != "service.result.v1"
                or result.get("operation") != "request.create"):
            raise ServiceError("internal_error")
        with self._writer:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute(
                    "SELECT state,idempotency_key,command_digest,service_result_json "
                    "FROM client_intake WHERE request_id=?", (request_id,)).fetchone()
                service_request = result.get("service_request")
                if (row is None or result.get("request_id") != row["idempotency_key"]
                        or not isinstance(service_request, dict)
                        or service_request.get("id") != request_id
                        or type(service_request.get("version")) is not int
                        or service_request["version"] < 1):
                    raise ServiceError("internal_error")
                changed = connection.execute("""UPDATE client_intake SET state='admitted',service_result_json=?
                    WHERE request_id=? AND state='pending' AND command_digest=?""",
                    (canonical(result), request_id, command_digest)).rowcount
                if changed != 1:
                    if (row["state"] != "admitted" or row["command_digest"] != command_digest
                            or row["service_result_json"] != canonical(result)):
                        raise ServiceError("idempotency_conflict")
                connection.execute("""INSERT INTO provider_lifecycle(request_id,stage)
                    VALUES(?,'request_admitted') ON CONFLICT(request_id) DO NOTHING""", (request_id,))
                connection.commit()
            except sqlite3.DatabaseError:
                connection.rollback()
                raise ServiceError("storage_unavailable") from None
            finally:
                connection.close()

    def reject(self, request_id: str, code: str) -> None:
        if code not in {"forbidden", "invalid_request", "service_unavailable"}:
            raise ValueError("invalid public rejection code")
        with self._writer:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute("UPDATE client_intake SET state='rejected',rejection_code=? WHERE request_id=? AND state='pending'", (code, request_id))
                connection.commit()
            finally:
                connection.close()

    def health(self) -> bool:
        connection = None
        try:
            connection = sqlite3.connect(self.database.as_uri() + "?mode=rw", uri=True, timeout=min(self.timeout, .25))
            return connection.execute("PRAGMA user_version").fetchone()[0] == self.SCHEMA_VERSION
        except (sqlite3.DatabaseError, OSError):
            return False
        finally:
            if connection is not None:
                connection.close()

    def lifecycle_pending(self, *, limit: int = 16, recovery: bool = False) -> list[dict]:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("invalid lifecycle batch")
        authority_state = "resume_required" if recovery else "fresh"
        connection = self._connect()
        try:
            return [dict(row) for row in connection.execute("""SELECT i.intake_json,l.*
                FROM provider_lifecycle l JOIN client_intake i USING(request_id)
                WHERE i.state='admitted' AND l.stage!='approved' AND l.authority_state=?
                ORDER BY l.request_id LIMIT ?""", (authority_state, limit))]
        finally:
            connection.close()

    def lifecycle_status(self, request_id: str) -> dict | None:
        if not identifier(request_id):
            raise ValueError("invalid request id")
        connection = self._connect()
        try:
            row = connection.execute("SELECT * FROM provider_lifecycle WHERE request_id=?", (request_id,)).fetchone()
            return dict(row) if row else None
        finally:
            connection.close()

    def retain_lifecycle_command(self, request_id: str, stage: str, target: str, command: dict) -> str:
        if target not in {"service", "runtime"}:
            raise ValueError("invalid lifecycle target")
        raw = canonical(command)
        digest = _digest(raw.encode("utf-8"))
        with self._writer:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute("SELECT * FROM provider_lifecycle WHERE request_id=?", (request_id,)).fetchone()
                if row is None:
                    raise ServiceError("not_found")
                if row["stage"] != stage:
                    raise ServiceError("version_conflict")
                if row["command_digest"] is not None:
                    if (row["command_target"] != target or row["command_digest"] != digest
                            or row["command_json"] != raw):
                        raise ServiceError("idempotency_conflict")
                else:
                    connection.execute("""UPDATE provider_lifecycle SET command_target=?,command_digest=?,command_json=?
                        WHERE request_id=? AND stage=?""", (target, digest, raw, request_id, stage))
                connection.commit()
                return digest
            except sqlite3.DatabaseError:
                connection.rollback()
                raise ServiceError("storage_unavailable") from None
            finally:
                connection.close()

    def begin_lifecycle_authority(self, request_id: str, stage: str, digest: str) -> bool:
        if not _sha256(digest):
            raise ValueError("invalid command digest")
        with self._writer:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute("SELECT stage,command_digest FROM provider_lifecycle WHERE request_id=?", (request_id,)).fetchone()
                if row is None:
                    raise ServiceError("not_found")
                if row["stage"] == stage and row["command_digest"] == digest:
                    changed = connection.execute("""UPDATE provider_lifecycle SET authority_state='resume_required'
                        WHERE request_id=? AND authority_state='fresh'""", (request_id,)).rowcount
                elif row["stage"] != stage:
                    raise ServiceError("version_conflict")
                else:
                    raise ServiceError("idempotency_conflict")
                connection.commit()
                return changed == 1
            except sqlite3.DatabaseError:
                connection.rollback()
                raise ServiceError("storage_unavailable") from None
            finally:
                connection.close()

    def complete_lifecycle_step(self, request_id: str, stage: str, next_stage: str,
                                digest: str, result: dict) -> None:
        with self._writer:
            connection = self._connect()
            try:
                connection.execute("BEGIN IMMEDIATE")
                row = connection.execute("SELECT * FROM provider_lifecycle WHERE request_id=?", (request_id,)).fetchone()
                if row is None:
                    raise ServiceError("not_found")
                encoded = canonical(result)
                if row["stage"] != stage:
                    connection.commit(); return
                if row["command_digest"] != digest:
                    raise ServiceError("idempotency_conflict")
                connection.execute("""UPDATE provider_lifecycle SET stage=?,command_target=NULL,
                    command_digest=NULL,command_json=NULL,authority_state='fresh',last_result_json=?
                    WHERE request_id=? AND stage=?""", (next_stage, encoded, request_id, stage))
                connection.commit()
            except sqlite3.DatabaseError:
                connection.rollback()
                raise ServiceError("storage_unavailable") from None
            finally:
                connection.close()


class PullWorker:
    def __init__(self, inbox: ReachableInbox, opener: EnvelopeOpener, store: IntakeStore):
        self.inbox, self.opener, self.store = inbox, opener, store

    def pull_once(self, *, limit: int = 16) -> list[dict]:
        if type(limit) is not int or not 1 <= limit <= 100:
            raise ValueError("invalid intake batch")
        results = []
        for delivery in self.inbox.pull(limit):
            opened = self.opener.open(delivery.payload)
            result = self.store.ingest(opened, delivery.receipt)
            # Queue consumption follows the durable local commit.  If this ack
            # is lost, redelivery is an exact retry through IntakeStore.
            self.inbox.acknowledge(delivery.handle)
            results.append(result)
        return results


class AdmissionWorker:
    def __init__(self, store: IntakeStore, verifier: RequesterVerifier, service: ServiceCommandPort):
        self.store, self.verifier, self.service = store, verifier, service

    @staticmethod
    def command(intake: Intake, requester: VerifiedRequester) -> bytes:
        values = intake.values
        organization = values.get("organization_name")
        summary = organization.strip() if isinstance(organization, str) and organization.strip() else intake.service_id
        details = canonical({"schema": "service.intake-link.v1", "intake_digest": intake.digest,
                             "brief_hash": intake.brief_hash, "brief_revision": intake.brief_revision,
                             "service_id": intake.service_id, "service_version": intake.service_version,
                             "requester_subject": requester.subject,
                             "membership_credential_id": requester.membership_credential_id})
        value = {"schema": "service.command.v1", "operation": "request.create",
                 "request_id": intake.idempotency_key,
                 "resource": {"kind": "ServiceRequest", "id": intake.request_id},
                 "expected_version": None, "payload": {"summary": summary[:2048], "details": details}}
        return canonical(value).encode("utf-8")

    def admit_once(self, *, limit: int = 16) -> list[dict]:
        return self._admit_once(limit=limit, recovery=False)

    def resume_once(self, *, limit: int = 16) -> list[dict]:
        """Explicitly recover retained commands; never create fresh authority."""
        if not callable(getattr(self.service, "resume", None)):
            raise ValueError("service recovery port required")
        return self._admit_once(limit=limit, recovery=True)

    def _admit_once(self, *, limit: int, recovery: bool) -> list[dict]:
        results = []
        for row in self.store.pending(limit=limit, recovery=recovery):
            intake = Intake.parse(row["intake_json"].encode("utf-8"))
            receipt_value = json.loads(row["transport_receipt_json"])
            receipt = TransportReceipt(receipt_value["transport"], receipt_value["receipt_id"],
                                       receipt_value["recorded_at"], receipt_value["expires_at"])
            receipt.validate()
            try:
                requester = self.verifier.verify(intake, bytes(row["requester_evidence"]), receipt)
            except ServiceError as error:
                if error.code == "forbidden":
                    self.store.reject(intake.request_id, "forbidden")
                    results.append(self.store.get(intake.request_id)); continue
                raise
            command = self.command(intake, requester)
            self.store.retain_command(intake.request_id, command, requester)
            digest = _digest(command)
            if recovery:
                retained = row["command_json"]
                if not isinstance(retained, str) or retained.encode("utf-8") != command:
                    raise ServiceError("idempotency_conflict")
            else:
                # Commit the recovery requirement before starting the native
                # Wallet exchange. Restart can now use only explicit resume.
                self.store.begin_authority(intake.request_id, digest)
            try:
                result = self.service.resume(command) if recovery else self.service.submit(command)
            except UnknownAdmissionOutcome:
                # The exact command and explicit recovery state remain durable.
                continue
            self.store.admit(intake.request_id, digest, result)
            results.append(self.store.get(intake.request_id))
        return results
