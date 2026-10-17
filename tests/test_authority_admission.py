"""Authority must still hold when the service writer admits an operation."""

import concurrent.futures
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from service_management import Service, ServiceError
from service_management.authority import AUDIENCE, LocalDevUntrustedVerifier, VerifiedCall
from service_management.delivery import OutboxDelivery
from service_management.sqlite_store import SQLiteUnitOfWork
from test_integration import FakeRuntime, query
from test_service import command


class ReloadingVerifier:
    def __init__(self, clock):
        self.clock = clock
        self.allowed = True
        self.subject = "approved-actor"
        self.expires_at = 101
        self.calls = []
        self.after_verify = None

    def verify(self, action, evidence, now):
        self.calls.append(now)
        if not self.allowed:
            raise ServiceError("forbidden")
        result = VerifiedCall(self.subject, AUDIENCE, action.digest, self.expires_at, "verified_call")
        if self.after_verify:
            self.after_verify()
        return result


class AdmissionAuthorityTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "service.db"
        self.store = SQLiteUnitOfWork(self.path)
        self.now = 100
        self.verifier = ReloadingVerifier(lambda: self.now)
        self.service = Service(self.store, verifier=self.verifier, clock=lambda: self.now)
        self.create = command("request.create", "create", payload={"summary": "Queued intake"})

    def denied(self, action):
        with self.assertRaises(ServiceError) as error:
            action()
        self.assertEqual(error.exception.code, "forbidden")

    def assert_no_intake(self):
        self.assertIsNone(self.store.transact(lambda tx: tx.get_request("request-1")))
        self.assertEqual(self.store.audit_history("ServiceRequest", "request-1"), [])

    def queued(self, action, before_admission):
        """A real second SQLite writer prevents the service callback admission."""
        waiting = threading.Event()
        store = self.store
        class ObservedStore:
            def transact(inner, callback):
                waiting.set()
                return store.transact(callback)
        self.service.storage = ObservedStore()
        blocker = sqlite3.connect(self.path, isolation_level=None)
        blocker.execute("BEGIN IMMEDIATE")
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(action)
            try:
                self.assertTrue(waiting.wait(3), "command never entered the transaction queue")
                self.assertEqual(self.verifier.calls, [], "authority was verified before writer admission")
                before_admission()
            finally:
                blocker.rollback()
                blocker.close()
            return future.result(timeout=5)

    def test_queued_expired_authority_cannot_create_or_audit(self):
        self.denied(lambda: self.queued(lambda: self.service.execute(self.create), lambda: setattr(self, "now", 200)))
        self.assertEqual(self.verifier.calls, [200])
        self.assert_no_intake()

    def test_queued_revocation_reloads_receiver_permissions(self):
        self.denied(lambda: self.queued(lambda: self.service.execute(self.create), lambda: setattr(self.verifier, "allowed", False)))
        self.assertEqual(self.verifier.calls, [100])
        self.assert_no_intake()

    def test_verifier_delay_cannot_use_expired_result(self):
        self.verifier.after_verify = lambda: setattr(self, "now", 200)
        self.denied(lambda: self.service.execute(self.create))
        self.assert_no_intake()

    def test_audit_timestamp_uses_fresh_post_verifier_clock(self):
        self.verifier.expires_at = 1000
        self.verifier.after_verify = lambda: setattr(self, "now", 200)
        result = self.service.execute(self.create)
        self.assertEqual(result["service_request"]["created_at"], "1970-01-01T00:03:20.000000Z")
        self.assertEqual(self.store.audit_history("ServiceRequest", "request-1")[0]["event"]["occurred_at"], result["service_request"]["created_at"])

    def test_queued_query_rechecks_revocation_before_disclosure(self):
        seed = Service(self.store, verifier=LocalDevUntrustedVerifier(), environment="test", allow_local_dev_untrusted=True)
        seed.execute(self.create)
        self.denied(lambda: self.queued(lambda: self.service.query(query("request.execution", "request-1")), lambda: setattr(self.verifier, "allowed", False)))

    def test_plan_preparation_rechecks_revocation_expiry_and_subject(self):
        for change in ("revoke", "expire", "subject"):
            with self.subTest(change=change):
                path = Path(self.temp.name) / (change + ".db")
                store = SQLiteUnitOfWork(path)
                runtime = FakeRuntime()
                pin = runtime.publish("inspection-v1", {"location": {"kind": "string"}})
                seed = Service(store, verifier=LocalDevUntrustedVerifier(), environment="test", allow_local_dev_untrusted=True)
                for raw in [self.create, command("request.qualify", "qualify", 1, {"qualification": "Qualified"}),
                            command("request.accept", "accept", 2, {"acceptance": "Accepted"}),
                            command("request.convert", "convert", 3, {"case_id": "case-1", "obligation": "Inspect"}),
                            command("case.plan", "plan", 1, {"scope": "Inspect"}, resource_id="case-1")]:
                    seed.execute(raw)
                self.now = 100
                verifier = ReloadingVerifier(lambda: self.now)
                service = Service(store, verifier=verifier, runtime=runtime, clock=lambda: self.now)
                original_query = runtime.query
                def query_then_change(envelope):
                    result = original_query(envelope)
                    if change == "revoke": verifier.allowed = False
                    elif change == "expire": self.now = 200
                    else: verifier.subject = "different-actor"
                    return result
                runtime.query = query_then_change
                raw = command("case.plan.approve", "approve", 2, {"revision_id": "revision-1", "reason": "Approved", "pin": pin, "inputs": {"location": "onsite"}, "carry_forward": []}, resource_id="case-1")
                self.denied(lambda: service.execute(raw))
                self.assertEqual(len(verifier.calls), 2)
                self.assertEqual(store.transact(lambda tx: tx.get_case("case-1")).version, 2)
                self.assertIsNone(store.transact(lambda tx: tx.get_revision("revision-1")))
                self.assertEqual(OutboxDelivery(store, runtime).pending(), [])
                self.assertEqual(len(store.audit_history("Case", "case-1")), 2)
