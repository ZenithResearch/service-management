"""All ingress surfaces converge here for authorization and lifecycle checks."""

import time
import uuid
from datetime import UTC, datetime
from typing import Callable

from .authority import AuthorityVerifier, DenyAllVerifier, LocalDevUntrustedVerifier, VerifiedCall, authorize
from .contracts import Command
from .domain import Case, ServiceRequest
from .errors import ServiceError
from .ports import Transaction, UnitOfWork
from .runtime_port import RuntimeClient, UnavailableRuntime
from .planning import PLAN_OPERATIONS, prepare_plan, apply_plan
from .delivery import public_handoff
from .queries import Query, execute_query


class Service:
    def __init__(self, storage: UnitOfWork, *, verifier: AuthorityVerifier | None = None,
                 environment: str = "production", allow_local_dev_untrusted: bool = False,
                 clock: Callable[[], float] = time.time, runtime: RuntimeClient | None = None, projection=None):
        if environment not in {"production", "development", "test"}:
            raise ValueError("unknown environment")
        if environment == "production" and allow_local_dev_untrusted:
            raise ValueError("local_dev_untrusted is prohibited in production")
        if environment == "production" and getattr(runtime, "authority_mode", None) == "local_dev_untrusted":
            raise ValueError("local_dev_untrusted runtime is prohibited in production")
        self.storage, self.verifier = storage, verifier or DenyAllVerifier()
        self.allow_local_dev, self.clock = allow_local_dev_untrusted, clock
        self.runtime, self.projection = runtime or UnavailableRuntime(), projection

    def readiness(self) -> dict:
        storage = "unknown"
        check = getattr(self.storage, "health", None)
        if callable(check):
            try:
                storage = "available" if check() is True else "unavailable"
            except Exception:
                storage = "unavailable"
        authority = "unqualified"
        if isinstance(self.verifier, DenyAllVerifier):
            authority = "default_deny"
        elif isinstance(self.verifier, LocalDevUntrustedVerifier) and self.allow_local_dev:
            authority = "local_dev_untrusted"
        return {"service": "service-management", "ready": storage == "available" and authority == "local_dev_untrusted",
                "checks": {"storage": storage, "authority": authority}}

    def execute(self, raw: bytes, evidence: bytes | None = None) -> dict:
        command = Command.parse(raw)
        try:
            prepared = None
            prepared_subject = None
            if command.operation in PLAN_OPERATIONS:
                def context(tx):
                    verified, _ = self._verify(command, evidence)
                    saved = self._prior(tx, command, verified)
                    if saved is not None: return saved, None, None, None, verified.subject
                    case = tx.get_case(command.resource.id)
                    prior = tx.get_revision(case.current_plan_revision_id) if case and case.current_plan_revision_id else None
                    handoff = tx.handoff_for_revision(prior["id"]) if prior else None
                    return None, case, prior, handoff, verified.subject
                saved, case, prior, handoff, prepared_subject = self.storage.transact(context)
                if saved is not None: return saved
                prepared = prepare_plan(self.runtime, command, case, prior, handoff)
            def commit(tx):
                # Admission can wait behind another writer. Reload receiver policy
                # here, including after any slow runtime preparation queries.
                verified, now = self._verify(command, evidence)
                if prepared_subject is not None and verified.subject != prepared_subject:
                    raise ServiceError("forbidden")
                timestamp = datetime.fromtimestamp(now, UTC).isoformat(timespec="microseconds").replace("+00:00", "Z")
                return self._execute(tx, command, verified, timestamp, prepared)
            return self.storage.transact(commit)
        except ServiceError as error:
            error.request_id = command.request_id
            raise

    def query(self, raw: bytes, evidence: bytes | None = None) -> dict:
        query = Query.parse(raw)
        try:
            def read(tx):
                verified, _ = self._verify(query, evidence)
                self._admit_replay(tx, query, verified)
                return execute_query(tx, query, self.projection)
            data = self.storage.transact(read)
            return {"schema": "service.query-result.v1", "request_id": query.request_id, "operation": query.operation, "data": data}
        except ServiceError as error:
            error.request_id = query.request_id
            raise

    def _verify(self, action: Command | Query, evidence: bytes | None) -> tuple[VerifiedCall, float]:
        verified = self.verifier.verify(action, evidence, self.clock())
        # Verification itself may block; expiry and audit time use a fresh clock.
        now = self.clock()
        authorize(verified, action, now, allow_local_dev=self.allow_local_dev)
        return verified, now

    @staticmethod
    def _admit_replay(tx, action, verified):
        if verified.replay is not None:
            replay = verified.replay
            tx.admit_replay(verified.subject, replay.session_id, replay.opcode, replay.nonce, action.digest)

    @staticmethod
    def _version(item, expected: int | None):
        if item is None:
            raise ServiceError("not_found")
        if item.version != expected:
            raise ServiceError("version_conflict", details={"expected_version": expected, "actual_version": item.version})

    @staticmethod
    def _prior(tx: Transaction, command: Command, actor: VerifiedCall):
        prior = tx.find_result(actor.subject, command.request_id)
        if prior is not None:
            digest, response = prior
            if digest != command.digest:
                raise ServiceError("idempotency_conflict")
            return response
        return None

    def _execute(self, tx: Transaction, command: Command, actor: VerifiedCall, now: str, prepared=None) -> dict:
        prior = self._prior(tx, command, actor)
        if prior is not None: return prior
        self._admit_replay(tx, command, actor)
        operation, payload = command.operation, command.payload
        request: ServiceRequest | None = None
        case: Case | None = None
        revision, handoff = None, None
        changes = []
        if operation == "request.create":
            request = ServiceRequest(command.resource.id, payload["summary"], payload.get("details", ""), "intake", 1, now, now)
            tx.insert_request(request)
            changes.append(("ServiceRequest", None, request))
        elif command.resource.kind == "ServiceRequest":
            before = tx.get_request(command.resource.id)
            self._version(before, command.expected_version)
            assert before is not None
            if operation == "request.qualify":
                request = before.qualify(payload["qualification"], now)
            elif operation == "request.accept":
                request = before.accept(payload["acceptance"], now)
            elif operation == "request.reject":
                request = before.reject(payload["reason"], now)
            elif operation == "request.convert":
                request, case = before.convert(payload["case_id"], payload["obligation"], now)
                tx.insert_case(case)
                changes.append(("Case", None, case))
            else:
                raise ServiceError("invalid_command")
            tx.update_request(request, before.version)
            changes.append(("ServiceRequest", before, request))
        else:
            before = tx.get_case(command.resource.id)
            self._version(before, command.expected_version)
            assert before is not None
            if operation in PLAN_OPERATIONS:
                case, revision, handoff = apply_plan(tx, command, actor, now, before, prepared)
            elif operation == "case.plan":
                case = before.plan(payload["scope"], now)
            elif operation == "case.close":
                case = before.close(payload["resolution"], now)
            else:
                raise ServiceError("invalid_command")
            if operation not in PLAN_OPERATIONS:
                tx.update_case(case, before.version)
            changes.append(("Case", before, case))
        event_ids = []
        for kind, before, after in changes:
            event_id = str(uuid.uuid4())
            tx.append_event({"schema": "service.audit.v1", "event_id": event_id, "request_id": command.request_id,
                             "actor": actor.subject, "authority_mode": actor.mode, "operation": operation,
                             "resource": {"kind": kind, "id": after.id}, "occurred_at": now,
                             "previous_version": before.version if before else None, "version": after.version,
                             "before": before.as_dict() if before else None, "after": after.as_dict()})
            event_ids.append(event_id)
        result = {"schema": "service.result.v1", "request_id": command.request_id, "operation": operation,
                  "authority": {"subject": actor.subject, "mode": actor.mode},
                  "service_request": request.as_dict() if request else None, "case": case.as_dict() if case else None,
                  "plan_revision": revision, "handoff": public_handoff(handoff),
                  "audit_event_ids": event_ids}
        tx.save_result(actor.subject, command.request_id, command.digest, result)
        return result
