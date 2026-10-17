import concurrent.futures
import json
import os
import sqlite3
import subprocess
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from service_management import Command, Service, ServiceError
from service_management.authority import LocalDevUntrustedVerifier, VerifiedCall
from service_management.contracts import command_schema, error_schema, result_schema
from service_management.ingress import CommandIngress
from service_management.sqlite_store import SQLiteUnitOfWork

ROOT = Path(__file__).resolve().parents[1]


def command(operation, request_id, version=None, payload=None, *, resource_id="request-1"):
    return json.dumps({"schema": "service.command.v1", "operation": operation, "request_id": request_id,
                       "resource": {"kind": "Case" if operation.startswith("case.") else "ServiceRequest", "id": resource_id},
                       "expected_version": version, "payload": payload or {}}).encode()


class FoundationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.database = Path(self.temp.name) / "service.db"
        self.store = SQLiteUnitOfWork(self.database)
        self.service = self.make_service(self.store)

    def make_service(self, store=None, **options):
        return Service(store or self.store, verifier=LocalDevUntrustedVerifier(), environment="test", allow_local_dev_untrusted=True, **options)

    def execute(self, operation, request_id, version=None, payload=None, **kwargs):
        return self.service.execute(command(operation, request_id, version, payload, **kwargs))

    def error(self, code, action):
        with self.assertRaises(ServiceError) as raised:
            action()
        self.assertEqual(raised.exception.code, code)
        return raised.exception

    def seed(self, accepted=False):
        self.execute("request.create", "create-1", payload={"summary": "Inspect the managed service obligation", "details": "User-authored intake intent."})
        self.execute("request.qualify", "qualify-1", 1, {"qualification": "Scope and owner confirmed."})
        if accepted:
            self.execute("request.accept", "accept-1", 2, {"acceptance": "Owner accepts the request."})

    def test_distinct_lifecycles_and_explicit_conversion_plan_close(self):
        self.seed(accepted=True)
        request = self.store.transact(lambda tx: tx.get_request("request-1"))
        self.assertEqual(request.state, "accepted")
        self.assertIsNone(request.case_id)
        self.assertIsNone(self.store.transact(lambda tx: tx.get_case("case-1")))
        converted = self.execute("request.convert", "convert-1", 3, {"case_id": "case-1", "obligation": "Managed inspection obligation"})
        self.assertEqual(converted["service_request"]["state"], "accepted")
        self.assertEqual(converted["service_request"]["case_id"], "case-1")
        self.assertEqual(converted["case"]["service_request_id"], "request-1")
        self.assertEqual(len(converted["audit_event_ids"]), 2)
        self.error("invalid_transition", lambda: self.execute("case.close", "too-early", 1, {"resolution": "Unsupported early close"}, resource_id="case-1"))
        planned = self.execute("case.plan", "plan-1", 1, {"scope": "Record the agreed inspection scope; no runtime dispatch."}, resource_id="case-1")
        self.assertEqual(planned["case"]["version"], 2)
        closed = self.execute("case.close", "close-1", 2, {"resolution": "Owner records fulfilment and closure evidence."}, resource_id="case-1")
        self.assertEqual(closed["case"]["state"], "closed")
        self.error("invalid_transition", lambda: self.execute("case.plan", "implicit-replan", 3, {"scope": "Silent revision"}, resource_id="case-1"))
        events = self.store.audit_history("Case", "case-1")
        self.assertEqual([row["event"]["operation"] for row in events], ["request.convert", "case.plan", "case.close"])
        self.assertEqual([row["event"]["version"] for row in events], [1, 2, 3])

    def test_intake_cannot_accept_or_convert_and_rejection_is_terminal(self):
        self.execute("request.create", "create-1", payload={"summary": "New intake"})
        self.error("invalid_transition", lambda: self.execute("request.accept", "early-accept", 1, {"acceptance": "No qualification"}))
        self.error("invalid_transition", lambda: self.execute("request.convert", "early-convert", 1, {"case_id": "case-1", "obligation": "No acceptance"}))
        result = self.execute("request.reject", "reject-1", 1, {"reason": "Outside supported scope"})
        self.assertEqual(result["service_request"]["state"], "rejected")
        for operation, payload in [("request.qualify", {"qualification": "Late qualification"}), ("request.accept", {"acceptance": "Late acceptance"}), ("request.reject", {"reason": "Duplicate rejection"}), ("request.convert", {"case_id": "case-1", "obligation": "Rejected work"})]:
            with self.subTest(operation=operation):
                self.error("invalid_transition", lambda: self.execute(operation, "invalid-" + operation, 2, payload))
        self.assertEqual(len(self.store.audit_history("ServiceRequest", "request-1")), 2)

    def test_exact_result_survives_response_loss_and_restart(self):
        raw = command("request.create", "lost-response", payload={"summary": "Durable acceptance of intake"})
        first = self.service.execute(raw)
        restarted = self.make_service(SQLiteUnitOfWork(self.database))
        self.assertEqual(restarted.execute(raw), first)
        self.assertEqual(len(self.store.audit_history("ServiceRequest", "request-1")), 1)
        changed = json.loads(raw); changed["payload"]["summary"] = "Different intent"
        self.error("idempotency_conflict", lambda: restarted.execute(json.dumps(changed).encode()))

    def test_same_request_identity_can_be_scoped_to_another_actor_but_not_replace_resource(self):
        self.execute("request.create", "same-key", payload={"summary": "Actor one"})
        other = Service(self.store, verifier=LocalDevUntrustedVerifier("other-actor"), environment="test", allow_local_dev_untrusted=True)
        result = other.execute(command("request.create", "same-key", payload={"summary": "Actor two"}, resource_id="request-2"))
        self.assertEqual(result["authority"]["subject"], "other-actor")
        self.error("resource_conflict", lambda: other.execute(command("request.create", "new-key", payload={"summary": "Cannot replace first resource"})))

    def test_duplicate_acceptance_has_one_event_even_across_independent_writers(self):
        self.seed()
        services = [self.make_service(SQLiteUnitOfWork(self.database)) for _ in range(8)]
        barrier = threading.Barrier(len(services))
        raw = command("request.accept", "parallel-accept", 2, {"acceptance": "Exactly once"})
        def run(service):
            barrier.wait()
            return service.execute(raw)
        with concurrent.futures.ThreadPoolExecutor(max_workers=len(services)) as pool:
            results = list(pool.map(run, services))
        self.assertTrue(all(result == results[0] for result in results))
        events = self.store.audit_history("ServiceRequest", "request-1")
        self.assertEqual(sum(row["event"]["operation"] == "request.accept" for row in events), 1)
        self.error("invalid_transition", lambda: self.execute("request.accept", "new-accept-key", 3, {"acceptance": "No second acceptance"}))

    def test_accept_reject_race_has_one_terminal_winner_and_stale_loser(self):
        self.seed()
        barrier = threading.Barrier(2)
        services = [self.make_service(SQLiteUnitOfWork(self.database)) for _ in range(2)]
        raws = [command("request.accept", "race-accept", 2, {"acceptance": "Accept"}), command("request.reject", "race-reject", 2, {"reason": "Reject"})]
        def run(pair):
            service, raw = pair
            barrier.wait()
            try:
                return service.execute(raw)["service_request"]["state"]
            except ServiceError as error:
                return error.code
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(run, zip(services, raws)))
        self.assertEqual(outcomes.count("version_conflict"), 1)
        self.assertEqual(sum(value in {"accepted", "rejected"} for value in outcomes), 1)
        self.assertEqual(len(self.store.audit_history("ServiceRequest", "request-1")), 3)

    def test_concurrent_conversion_creates_one_case_and_preserves_both_audit_records(self):
        self.seed(accepted=True)
        services = [self.make_service(SQLiteUnitOfWork(self.database)) for _ in range(2)]
        barrier = threading.Barrier(2)
        def run(index):
            barrier.wait()
            try:
                return services[index].execute(command("request.convert", f"convert-{index}", 3, {"case_id": f"case-{index}", "obligation": "One obligation"}))["case"]["id"]
            except ServiceError as error:
                return error.code
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            outcomes = list(pool.map(run, range(2)))
        self.assertEqual(outcomes.count("version_conflict"), 1)
        request = self.store.transact(lambda tx: tx.get_request("request-1"))
        case = self.store.transact(lambda tx: tx.get_case(request.case_id))
        self.assertEqual(case.service_request_id, request.id)
        self.assertEqual(len(self.store.audit_history("Case", case.id)), 1)
        self.error("already_converted", lambda: self.execute("request.convert", "another-conversion", 4, {"case_id": "case-third", "obligation": "Duplicate"}))

    def test_foreign_case_identity_conflict_rolls_back_conversion_request_and_audit(self):
        self.seed(accepted=True)
        self.execute("request.convert", "convert-1", 3, {"case_id": "case-shared", "obligation": "First obligation"})
        for operation, rid, version, payload in [("request.create", "create-2", None, {"summary": "Second intake"}), ("request.qualify", "qualify-2", 1, {"qualification": "In scope"}), ("request.accept", "accept-2", 2, {"acceptance": "Accepted"})]:
            self.execute(operation, rid, version, payload, resource_id="request-2")
        self.error("resource_conflict", lambda: self.execute("request.convert", "convert-2", 3, {"case_id": "case-shared", "obligation": "Second obligation"}, resource_id="request-2"))
        request = self.store.transact(lambda tx: tx.get_request("request-2"))
        self.assertEqual(request.version, 3); self.assertIsNone(request.case_id)
        self.assertEqual(len(self.store.audit_history("ServiceRequest", "request-2")), 3)

    def test_crash_inside_transaction_does_not_leave_partial_state_audit_or_result(self):
        code = """
import os,sys
from service_management.sqlite_store import SQLiteUnitOfWork
from service_management.domain import ServiceRequest
store=SQLiteUnitOfWork(sys.argv[1])
def fail(tx):
    tx.insert_request(ServiceRequest('crash-request','Crash fixture','', 'intake',1,'time','time'))
    tx.append_event({'event_id':'crash-event','resource':{'kind':'ServiceRequest','id':'crash-request'}})
    tx.save_result('actor','crash-command','a'*64,{'schema':'service.result.v1','request_id':'crash-command'})
    os._exit(91)
store.transact(fail)
"""
        process = subprocess.run([sys.executable, "-c", code, str(self.database)], env=dict(os.environ), capture_output=True, text=True, timeout=20)
        self.assertEqual(process.returncode, 91, process.stderr)
        restarted = SQLiteUnitOfWork(self.database)
        self.assertIsNone(restarted.transact(lambda tx: tx.get_request("crash-request")))
        self.assertIsNone(restarted.transact(lambda tx: tx.find_result("actor", "crash-command")))
        self.assertEqual(restarted.audit_history("ServiceRequest", "crash-request"), [])

    def test_audit_failure_rolls_back_lifecycle_and_idempotency(self):
        class FailingStore:
            def transact(inner, action):
                def fail(tx):
                    tx.append_event = lambda event: (_ for _ in ()).throw(RuntimeError("audit unavailable"))
                    return action(tx)
                return self.store.transact(fail)
        failing = self.make_service(FailingStore())
        raw = command("request.create", "atomic-audit", payload={"summary": "No partial write"})
        with self.assertRaises(RuntimeError):
            failing.execute(raw)
        self.assertIsNone(self.store.transact(lambda tx: tx.get_request("request-1")))
        self.assertIsNone(self.store.transact(lambda tx: tx.find_result("local-dev-untrusted", "atomic-audit")))
        self.assertEqual(self.service.execute(raw)["service_request"]["version"], 1)

    def test_lock_contention_returns_retryable_error_without_partial_mutation(self):
        impatient = self.make_service(SQLiteUnitOfWork(self.database, timeout=0.02))
        holder = sqlite3.connect(self.database, isolation_level=None)
        self.addCleanup(holder.close)
        holder.execute("BEGIN IMMEDIATE")
        raw = command("request.create", "lock-retry", payload={"summary": "Retry exact command"})
        self.error("storage_unavailable", lambda: impatient.execute(raw))
        holder.rollback()
        self.assertEqual(impatient.execute(raw)["service_request"]["version"], 1)

    def test_newer_schema_is_not_reinterpreted_and_migration_is_restart_safe(self):
        self.execute("request.create", "create-1", payload={"summary": "Retained v1 state"})
        reopened = SQLiteUnitOfWork(self.database)
        self.assertEqual(reopened.transact(lambda tx: tx.get_request("request-1")).summary, "Retained v1 state")
        with sqlite3.connect(self.database) as connection:
            connection.execute("PRAGMA user_version=4")
        with self.assertRaisesRegex(ValueError, "newer"):
            SQLiteUnitOfWork(self.database)

    def test_corrupt_persisted_state_fails_closed(self):
        self.seed()
        with sqlite3.connect(self.database) as connection:
            connection.execute("UPDATE service_requests SET data_json='{}' WHERE id='request-1'")
        self.error("storage_unavailable", lambda: self.execute("request.accept", "invalid-storage", 2, {"acceptance": "No corrupted state"}))

    def test_default_deny_and_production_local_dev_rejection(self):
        raw = command("request.create", "unauthorized", payload={"summary": "Cannot create"})
        self.error("forbidden", lambda: Service(self.store).execute(raw, b"Bearer spoofed"))
        with self.assertRaisesRegex(ValueError, "production"):
            Service(self.store, verifier=LocalDevUntrustedVerifier(), allow_local_dev_untrusted=True)
        self.error("forbidden", lambda: Service(self.store, verifier=LocalDevUntrustedVerifier()).execute(raw))
        self.assertIsNone(self.store.transact(lambda tx: tx.get_request("request-1")))

    def test_caller_authority_evidence_never_becomes_a_subject_or_transport_privilege(self):
        raw = command("request.create", "no-transport-authority", payload={"summary": "No forged account"})
        for evidence in [b"matrix:@operator:example.test", b"hermes:owner", b"Bearer token", b'{"subject":"owner","public_key":"fake"}']:
            with self.subTest(evidence=evidence):
                self.error("forbidden", lambda: CommandIngress(self.service).submit(raw, authority_evidence=evidence))

    def test_authority_binding_expiry_and_current_denial_precede_idempotency(self):
        raw = command("request.create", "bound-command", payload={"summary": "Binding fixture"})
        class ForgedVerifier:
            def __init__(inner, audience="service-management", digest=None, expiry=1_000_000):
                inner.audience, inner.digest, inner.expiry = audience, digest, expiry
            def verify(inner, parsed, evidence, now):
                return VerifiedCall("actor", inner.audience, inner.digest or parsed.digest, inner.expiry, "verified_call")
        for verifier in [ForgedVerifier(audience="other"), ForgedVerifier(digest="a" * 64), ForgedVerifier(expiry=1), ForgedVerifier(expiry=float("nan")), ForgedVerifier(expiry=float("inf")), ForgedVerifier(expiry="later")]:
            self.error("forbidden", lambda: Service(self.store, verifier=verifier, clock=lambda: 100).execute(raw))
        self.service.execute(raw)
        self.error("forbidden", lambda: Service(self.store).execute(raw))

    def test_ingress_uses_application_lifecycle_and_concurrency_gate(self):
        self.seed()
        ingress = CommandIngress(self.service)
        self.error("version_conflict", lambda: ingress.submit(command("request.accept", "stale-ingress", 1, {"acceptance": "Not current"})))
        accepted = ingress.submit(command("request.accept", "good-ingress", 2, {"acceptance": "Current qualification"}))
        self.assertEqual(accepted["service_request"]["state"], "accepted")

    def test_closed_contract_negative_inputs(self):
        valid = json.loads(command("request.create", "valid-key", payload={"summary": "Scope"}))
        cases = []
        for key, value in [("schema", "service.command.v2"), ("operation", "case.execute"), ("expected_version", True), ("request_id", "BAD ID")]:
            changed = dict(valid); changed[key] = value; cases.append(json.dumps(changed).encode())
        changed = dict(valid); changed["actor"] = "forged"; cases.append(json.dumps(changed).encode())
        for payload in [{"summary": " "}, {"summary": "x", "state": "accepted"}, {"summary": 1}, {"summary": "x\0"}, {"summary": "\ud800"}]:
            changed = dict(valid); changed["payload"] = payload; cases.append(json.dumps(changed).encode())
        cases += [b'{"schema":"x","schema":"y"}', b'{"number":1.5}', b'{"number":NaN}', b'\xff', b'[]', b' ' * 65537]
        for raw in cases:
            with self.subTest(raw=raw[:120]):
                with self.assertRaises(ServiceError):
                    Command.parse(raw)
        for version in [None, 0, -1, True, 2**53, 1.0]:
            with self.subTest(version=version):
                with self.assertRaises(ServiceError):
                    Command.parse(command("request.accept", "bad-version", version, {"acceptance": "Accepted"}))

    def test_published_schema_matches_producer_and_live_example_sequence_runs(self):
        for kind, factory in [("command", command_schema), ("result", result_schema), ("error", error_schema)]:
            self.assertEqual(json.loads((ROOT / f"contracts/service.{kind}.v1.schema.json").read_text()), factory())
        examples = json.loads((ROOT / "contracts/examples/service-lifecycle.json").read_text())
        results = [self.service.execute(json.dumps(example).encode()) for example in examples]
        self.assertEqual(results[-1]["case"]["state"], "closed")
        self.assertTrue(all(result["schema"] == "service.result.v1" for result in results))

    def test_domain_and_application_ports_do_not_import_sqlite(self):
        # Architectural dependency guard covers the storage-neutral owner boundary.
        import ast
        for name in ["domain.py", "application.py", "ports.py"]:
            tree = ast.parse((ROOT / "src/service_management" / name).read_text())
            modules = [node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
            modules += [alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names]
            self.assertFalse(any("sqlite" in module for module in modules), name)


if __name__ == "__main__":
    unittest.main()
