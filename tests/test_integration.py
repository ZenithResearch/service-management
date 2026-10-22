import copy
import concurrent.futures
import json
import sqlite3
import tempfile
import threading
import unittest
from pathlib import Path

from service_management import Service, ServiceError
from service_management.authority import LocalDevUntrustedVerifier
from service_management.contracts import canonical
from service_management.delivery import OutboxDelivery
from service_management.projection import RuntimeProjection
from service_management.runtime_port import RuntimeCallError, content_digest, expected_run_id
from service_management.sqlite_store import MIGRATION_1, SQLiteUnitOfWork
from test_service import command


def query(operation, resource_id="case-1", payload=None):
    return json.dumps({"schema": "service.query.v1", "request_id": "query-1", "operation": operation,
                       "resource": {"kind": "ServiceRequest" if operation.startswith("request.") else "Case", "id": resource_id}, "payload": payload or {}}).encode()


class FakeRuntime:
    """Contract-conforming fake provider; tests never import runtime core types."""
    def __init__(self):
        self.versions, self.runs, self.outputs, self.receipts, self.inbox = {}, {}, {}, {}, {}
        self.events, self.sent, self.resumed = [], [], []
        self.fail_once = None
        self.lost_response = False
        self.query_unavailable = False
        self._lock = threading.RLock()

    def publish(self, version, inputs):
        compiled = {"schema": "process.compiled.v1", "process_id": "inspection", "inputs": inputs, "steps": []}
        pin = {"process_id": "inspection", "process_version": version, "compilation_hash": content_digest(compiled)}
        self.versions[version] = {"pin": pin, "ordinal": len(self.versions)+1, "source_revision": 1, "published_at_ms": 1000, "compiled": compiled}
        return pin

    def command(self, envelope):
        with self._lock:
            self.sent.append(copy.deepcopy(envelope))
            if self.fail_once:
                failure, self.fail_once = self.fail_once, None
                raise failure
            event = envelope["payload"]
            event_id, run_id = event["event_id"], expected_run_id(event)
            if event_id in self.inbox and self.inbox[event_id] != envelope:
                raise RuntimeCallError("idempotency_conflict")
            duplicate = event_id in self.inbox
            self.inbox[event_id] = copy.deepcopy(envelope)
            self.runs.setdefault(run_id, {"run_id": run_id, "pin": event["pin"], "inputs": event["inputs"], "state": "pending", "version": 1, "source_ref": event_id, "steps": []})
            if self.lost_response:
                self.lost_response = False
                raise TimeoutError("response lost after commit")
            return {"schema": "runtime.result.v1", "request_id": envelope["request_id"], "operation": "handoff.consume", "duplicate": duplicate,
                    "resource": envelope["resource"], "version": 1,
                    "result": {"run_id": run_id, "pin": event["pin"], "state": "pending", "source_event_id": event_id}}

    def resume_command(self, envelope):
        self.resumed.append(copy.deepcopy(envelope))
        return self.command(envelope)

    def new_command(self, operation, *, request_id, expected_version, payload):
        if operation != "handoff.consume": raise AssertionError(operation)
        return {"schema": "runtime.command.v1", "operation": operation, "request_id": request_id,
                "resource": "handoffs/" + content_digest({"source": payload["source"], "event_id": payload["event_id"]}),
                "expected_version": expected_version, "payload": copy.deepcopy(payload)}

    def query(self, envelope):
        if self.query_unavailable: raise RuntimeCallError("storage_unavailable", retryable=True)
        operation, payload = envelope["operation"], envelope["payload"]
        if operation == "version.get": data = self.versions[payload["process_version"]]
        elif operation == "run.get": data = self.runs[payload["run_id"]]
        elif operation == "output.get": data = self.outputs[tuple(payload[key] for key in ("run_id", "step_id", "attempt_id"))]
        elif operation == "receipt.get": data = self.receipts[payload["receipt_id"]]
        elif operation == "events.list":
            events = [event for event in self.events if event["sequence"] > payload["after"]][:payload["limit"]]
            data = {"events": events, "next_cursor": events[-1]["sequence"] if events else payload["after"], "high_watermark": self.events[-1]["sequence"] if self.events else 0}
        else: raise AssertionError(operation)
        return {"schema": "runtime.query-result.v1", "operation": operation, "data": copy.deepcopy(data)}

    def commit_output(self, run_id, *, run_state="running"):
        run = self.runs[run_id]
        run["state"] = run_state
        run["steps"] = [{"step_id": "inspect", "state": "succeeded", "attempt_id": "attempt-1", "fence": 1, "version": 3}]
        output = {"output_id": "output-1", "run_id": run_id, "step_id": "inspect", "attempt_id": "attempt-1", "fence": 1,
                  "pin": run["pin"], "actor_id": "inspector", "inputs_digest": content_digest(run["inputs"]),
                  "outputs": {"finding": "inspection evidence"}, "output_types": {"finding": {"kind": "string"}},
                  "output_digest": content_digest({"finding": "inspection evidence"}), "committed_at_ms": 2000, "receipt_id": "receipt-1"}
        self.outputs[(run_id, "inspect", "attempt-1")] = output
        self.receipts["receipt-1"] = {"schema": "runtime.receipt.v1", "receipt_id": "receipt-1", "pin": run["pin"], "run_id": run_id,
                                      "step_id": "inspect", "attempt_id": "attempt-1", "actor_id": "inspector", "input_digest": output["inputs_digest"],
                                      "output_digest": output["output_digest"], "fence": 1, "started_at_ms": 1000, "recorded_at_ms": 2000,
                                      "outcome": "succeeded", "signature": None}
        return {"run_id": run_id, "step_id": "inspect", "attempt_id": "attempt-1", "output_name": "finding", "target_input": "evidence", "expected_output_digest": output["output_digest"]}


class ServiceIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "service.db"
        self.store = SQLiteUnitOfWork(self.path)
        self.runtime = FakeRuntime()
        self.pin = self.runtime.publish("inspection-v1", {"location": {"kind": "string"}})
        self.service = self.make_service()
        self.delivery = OutboxDelivery(self.store, self.runtime)
        self.service.execute(command("request.create", "create", payload={"summary": "Inspection"}))
        self.service.execute(command("request.qualify", "qualify", 1, {"qualification": "Qualified"}))
        self.service.execute(command("request.accept", "accept", 2, {"acceptance": "Accepted"}))

    def make_service(self, store=None, **kwargs):
        return Service(store or self.store, verifier=LocalDevUntrustedVerifier(), environment="test", allow_local_dev_untrusted=True, runtime=self.runtime, **kwargs)

    def seed_case(self):
        self.service.execute(command("request.convert", "convert", 3, {"case_id": "case-1", "obligation": "Inspection obligation"}))
        self.service.execute(command("case.plan", "scope", 1, {"scope": "Record the inspection findings"}, resource_id="case-1"))

    def approval(self, request_id="approve", revision_id="revision-1", version=2):
        return command("case.plan.approve", request_id, version, {"revision_id": revision_id, "reason": "Approved selected published process", "pin": self.pin, "inputs": {"location": "onsite"}, "carry_forward": []}, resource_id="case-1")

    def approve(self):
        self.seed_case()
        return self.service.execute(self.approval())

    def revised(self, run_id, pin, selection=None, *, request_id="revise", revision_id="revision-2", version=3):
        return command("case.plan.revise", request_id, version, {"revision_id": revision_id, "reason": "Explicit replacement plan", "pin": pin, "inputs": {} if selection else {"location": "new site"}, "carry_forward": [selection] if selection else [], "superseded_run_id": run_id}, resource_id="case-1")

    def error(self, code, action):
        with self.assertRaises(ServiceError) as error: action()
        self.assertEqual(error.exception.code, code)

    def test_acceptance_without_pin_is_explainably_awaiting_plan(self):
        result = self.service.query(query("request.execution", "request-1"))["data"]
        self.assertEqual(result["execution_state"], "awaiting_plan")
        self.assertIsNone(result["case_id"])
        self.assertEqual(self.delivery.pending(), [])
        self.assertEqual(self.runtime.sent, [])

    def test_approved_plan_commits_revision_case_link_and_exact_outbox_together(self):
        result = self.approve()
        self.assertEqual(result["case"]["current_plan_revision_id"], "revision-1")
        self.assertEqual(result["plan_revision"]["author"], "local-dev-untrusted")
        self.assertEqual(result["handoff"]["state"], "pending")
        row = self.store.transact(lambda tx: tx.get_handoff(result["handoff"]["event_id"]))
        self.assertEqual(row["command"]["payload"]["pin"], self.pin)
        self.assertEqual(self.runtime.sent, [])
        self.runtime.query_unavailable = True
        self.assertEqual(self.make_service(SQLiteUnitOfWork(self.path)).execute(self.approval()), result)
        self.assertEqual(len(self.delivery.pending()), 1)

    def test_outbox_insert_failure_rolls_back_revision_case_link_and_audit(self):
        self.seed_case()
        class FailingStore:
            def transact(inner, action):
                def execute(tx):
                    tx.insert_handoff = lambda row: (_ for _ in ()).throw(RuntimeError("outbox failure"))
                    return action(tx)
                return self.store.transact(execute)
        with self.assertRaises(RuntimeError): self.make_service(FailingStore()).execute(self.approval())
        self.assertIsNone(self.store.transact(lambda tx: tx.get_revision("revision-1")))
        self.assertIsNone(self.store.transact(lambda tx: tx.get_case("case-1")).current_plan_revision_id)
        self.assertEqual(len(self.store.audit_history("Case", "case-1")), 2)
        self.assertEqual(self.service.execute(self.approval())["case"]["version"], 3)

    def test_lost_acknowledgement_reconciles_exact_original_after_restart(self):
        event_id = self.approve()["handoff"]["event_id"]
        self.runtime.lost_response = True
        pending = self.delivery.reconcile(event_id)
        self.assertEqual(pending["state"], "pending"); self.assertEqual(pending["last_error"], "unknown_outcome")
        self.assertEqual(len(self.runtime.runs), 1)
        started = OutboxDelivery(SQLiteUnitOfWork(self.path), self.runtime).reconcile(event_id)
        self.assertEqual(started["state"], "started")
        self.assertEqual(self.runtime.sent[0], self.runtime.sent[1])
        self.assertEqual(self.runtime.resumed, [self.runtime.sent[1]])
        self.assertEqual(len(self.runtime.runs), 1)
        self.assertEqual(self.service.query(query("request.execution", "request-1"))["data"]["execution_state"], "started")

    def test_incompatible_runtime_is_explainably_failed_and_requires_explicit_retry(self):
        event_id = self.approve()["handoff"]["event_id"]
        self.runtime.fail_once = RuntimeCallError("incompatible_version")
        failed = self.delivery.reconcile(event_id)
        self.assertEqual(failed["state"], "failed")
        self.assertEqual(self.delivery.reconcile(event_id), failed)
        self.assertEqual(len(self.runtime.sent), 1)
        self.assertEqual(self.delivery.reconcile(event_id, retry_failed=True)["state"], "started")
        self.assertEqual(self.runtime.sent[0], self.runtime.sent[1])

    def test_version_skew_after_unknown_commit_cannot_turn_uncertainty_into_failure(self):
        event_id = self.approve()["handoff"]["event_id"]
        self.runtime.lost_response = True
        self.assertTrue(self.delivery.reconcile(event_id)["uncertain"])
        self.runtime.fail_once = RuntimeCallError("incompatible_version")
        uncertain = self.delivery.reconcile(event_id)
        self.assertEqual(uncertain["state"], "pending")
        self.assertTrue(uncertain["uncertain"])
        self.assertEqual(self.delivery.reconcile(event_id)["state"], "started")
        self.assertEqual(len(self.runtime.runs), 1)

    def test_malformed_ack_is_uncertain_and_does_not_authorize_replacement(self):
        event_id = self.approve()["handoff"]["event_id"]
        original = self.runtime.command
        def forged(envelope):
            result = original(envelope); result["result"]["pin"]["process_version"] = "wrong-version"; return result
        self.runtime.command = forged
        self.assertEqual(self.delivery.reconcile(event_id)["state"], "pending")
        self.error("handoff_unresolved", lambda: self.service.execute(self.revised("unknown", self.pin)))

    def test_concurrent_approval_creates_one_revision_and_outbox(self):
        self.seed_case()
        barrier = threading.Barrier(2)
        def run(index):
            service = self.make_service(SQLiteUnitOfWork(self.path)); barrier.wait()
            try: return service.execute(self.approval(f"approve-{index}", f"revision-{index}"))["handoff"]["state"]
            except ServiceError as error: return error.code
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool: results = list(pool.map(run, range(2)))
        self.assertCountEqual(results, ["pending", "version_conflict"])
        self.assertEqual(len(self.delivery.pending()), 1)

    def test_concurrent_delivery_creates_one_runtime_run(self):
        event_id = self.approve()["handoff"]["event_id"]
        barrier = threading.Barrier(4)
        def run(_):
            worker = OutboxDelivery(SQLiteUnitOfWork(self.path), self.runtime); barrier.wait(); return worker.reconcile(event_id)
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool: results = list(pool.map(run, range(4)))
        self.assertEqual({result["state"] for result in results}, {"started"})
        self.assertEqual(len(self.runtime.runs), 1)
        self.assertTrue(all(envelope == self.runtime.sent[0] for envelope in self.runtime.sent))

    def test_late_failed_delivery_cannot_overwrite_newer_unknown_outcome(self):
        event_id = self.approve()["handoff"]["event_id"]
        first_entered, second_finished = threading.Event(), threading.Event()
        count, lock = 0, threading.Lock()
        def runtime_call(envelope):
            nonlocal count
            with lock: count += 1; this_call = count
            if this_call == 1:
                first_entered.set(); second_finished.wait(5)
                raise RuntimeCallError("incompatible_version")
            raise TimeoutError("unknown result")
        self.runtime.command = runtime_call
        def first(): return self.delivery.reconcile(event_id)
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            pending_first = pool.submit(first)
            self.assertTrue(first_entered.wait(5))
            second = OutboxDelivery(SQLiteUnitOfWork(self.path), self.runtime).reconcile(event_id)
            second_finished.set()
            final = pending_first.result(5)
        self.assertEqual(second["state"], "pending")
        self.assertEqual(final["state"], "pending")
        self.assertTrue(final["uncertain"])

    def test_new_process_version_cannot_repin_pending_handoff(self):
        approved = self.approve()
        pin2 = self.runtime.publish("inspection-v2", {"location": {"kind": "string"}})
        self.error("handoff_unresolved", lambda: self.service.execute(self.revised("unknown", pin2)))
        started = self.delivery.reconcile(approved["handoff"]["event_id"])
        self.assertEqual(self.runtime.runs[started["run_id"]]["pin"], self.pin)

    def test_revision_carries_selected_committed_output_without_repinning_prior_run(self):
        approved = self.approve(); started = self.delivery.reconcile(approved["handoff"]["event_id"])
        prior_run_id = started["run_id"]
        selection = self.runtime.commit_output(prior_run_id)
        pin2 = self.runtime.publish("inspection-v2", {"evidence": {"kind": "string"}})
        raw = self.revised(prior_run_id, pin2, selection)
        result = self.service.execute(raw)
        revision = result["plan_revision"]
        self.assertEqual(revision["prior_pin"], self.pin)
        self.assertEqual(revision["superseded_run_id"], prior_run_id)
        self.assertEqual(revision["inputs"], {"evidence": "inspection evidence"})
        self.assertEqual(revision["carry_forward"][0]["receipt_id"], "receipt-1")
        new_run = self.delivery.reconcile(result["handoff"]["event_id"])["run_id"]
        self.assertNotEqual(new_run, prior_run_id)
        self.assertEqual(self.runtime.runs[prior_run_id]["pin"], self.pin)
        self.assertEqual(self.runtime.runs[new_run]["pin"], pin2)
        self.assertEqual(self.service.execute(raw), result)
        history = self.service.query(query("case.plan-history", payload={"after_revision": 0, "limit": 1}))["data"]
        self.assertEqual(history["next_revision"], 1)
        self.assertEqual(history["revisions"][0]["id"], "revision-1")

    def test_cancelled_prior_run_preserves_committed_evidence_for_explicit_replacement(self):
        started = self.delivery.reconcile(self.approve()["handoff"]["event_id"])
        selection = self.runtime.commit_output(started["run_id"], run_state="cancelled")
        pin2 = self.runtime.publish("inspection-v2", {"evidence": {"kind": "string"}})
        result = self.service.execute(self.revised(started["run_id"], pin2, selection))
        self.assertEqual(result["plan_revision"]["superseded_run_id"], started["run_id"])
        self.assertEqual(self.runtime.runs[started["run_id"]]["state"], "cancelled")

    def test_stale_tampered_and_incompatible_carry_forward_are_rejected(self):
        started = self.delivery.reconcile(self.approve()["handoff"]["event_id"])
        selection = self.runtime.commit_output(started["run_id"])
        pin2 = self.runtime.publish("inspection-v2", {"evidence": {"kind": "string"}})
        stale = {**selection, "expected_output_digest": "0"*64}
        self.error("invalid_carry_forward", lambda: self.service.execute(self.revised(started["run_id"], pin2, stale)))
        self.runtime.receipts["receipt-1"]["fence"] = 2
        self.error("invalid_carry_forward", lambda: self.service.execute(self.revised(started["run_id"], pin2, selection)))
        self.runtime.receipts["receipt-1"]["fence"] = 1
        self.runtime.runs[started["run_id"]]["steps"][0]["attempt_id"] = "new-attempt"
        self.error("invalid_carry_forward", lambda: self.service.execute(self.revised(started["run_id"], pin2, selection)))
        self.runtime.runs[started["run_id"]]["steps"][0]["attempt_id"] = "attempt-1"
        integer_pin = self.runtime.publish("inspection-v3", {"evidence": {"kind": "integer"}})
        self.error("invalid_carry_forward", lambda: self.service.execute(self.revised(started["run_id"], integer_pin, selection)))
        self.assertIsNone(self.store.transact(lambda tx: tx.get_revision("revision-2")))

    def test_published_hash_and_input_type_validation_fail_closed(self):
        self.seed_case()
        self.runtime.versions["inspection-v1"]["compiled"]["inputs"]["unexpected"] = {"kind": "integer"}
        self.error("runtime_contract", lambda: self.service.execute(self.approval()))
        self.assertEqual(self.delivery.pending(), [])

    def test_queries_require_authority_and_bound_history(self):
        self.seed_case()
        self.error("forbidden", lambda: Service(self.store).query(query("case.summary")))
        for limit in [0, 101, True]:
            self.error("invalid_command", lambda: self.service.query(query("case.plan-history", payload={"after_revision": 0, "limit": limit})))
        summary = self.service.query(query("case.summary"))["data"]
        self.assertFalse(summary["canonical_runtime"])
        self.assertTrue(summary["redaction"]["applied"])
        self.assertEqual(summary["execution_state"], "awaiting_plan")

    def test_rebuilt_case_progress_does_not_close_or_change_canonical_case(self):
        approved = self.approve(); started = self.delivery.reconcile(approved["handoff"]["event_id"])
        run_id = started["run_id"]
        self.runtime.events = [event(1, "run.created", f"run/{run_id}"), event(2, "run.succeeded", f"run/{run_id}")]
        projection = RuntimeProjection(Path(self.temp.name) / "progress.db")
        projection.rebuild(self.runtime)
        service = self.make_service(projection=projection)
        summary = service.query(query("case.summary"))["data"]
        self.assertEqual(summary["canonical_service"]["state"], "planned")
        self.assertEqual(summary["derived_runtime"]["state"], "succeeded")
        projection.reset_for_rebuild()
        reset = service.query(query("case.summary"))["data"]
        self.assertIsNone(reset["derived_runtime"])
        self.assertEqual(reset["canonical_service"], summary["canonical_service"])

    def test_schema_one_migration_preserves_canonical_snapshots_and_saved_results(self):
        path = Path(self.temp.name) / "v1.db"
        with sqlite3.connect(path) as connection:
            for statement in MIGRATION_1: connection.execute(statement)
            connection.execute("PRAGMA user_version=1")
            response = {"schema": "service.result.v1", "request_id": "legacy", "legacy_fixture": True}
            connection.execute("INSERT INTO command_results VALUES(?,?,?,?)", ("local-dev-untrusted", "legacy", "a"*64, canonical(response)))
        migrated = SQLiteUnitOfWork(path)
        self.assertEqual(migrated.transact(lambda tx: tx.find_result("local-dev-untrusted", "legacy")), ("a"*64, response))
        self.assertEqual(migrated.transact(lambda tx: tx.pending_handoffs()), [])


def event(sequence, kind, resource="run/run-1", data=None):
    return {"schema": "runtime.event.v1", "event_id": f"event-{sequence}", "sequence": sequence, "kind": kind,
            "resource": resource, "resource_version": sequence, "request_id": f"command-{sequence}", "correlation_id": "run-1", "recorded_at_ms": sequence*1000, "data": data or {}}


class ProjectionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.projection = RuntimeProjection(Path(self.temp.name) / "projection.db", clock=lambda: 100)
        self.runtime = FakeRuntime()
        self.runtime.events = [event(1, "run.created"), event(2, "attempt.claimed", "run/run-1/step/inspect", {"secret": "do not persist"}),
                               event(3, "attempt.completed", "run/run-1/step/inspect", {"outputs": {"private": "omit"}}), event(4, "run.succeeded")]

    def test_duplicate_replay_and_clean_rebuild_converge_with_redacted_progress(self):
        self.projection.rebuild(self.runtime)
        first = self.projection.run("run-1")
        self.projection.apply_page(self.runtime.events)
        self.assertEqual(self.projection.run("run-1"), first)
        self.projection.rebuild(self.runtime)
        self.assertEqual(self.projection.run("run-1"), first)
        self.assertEqual(first["completion"], {"observed_steps": 1, "succeeded_steps": 1})
        self.assertNotIn("do not persist", canonical(first))
        self.assertNotIn("private", canonical(first))
        with sqlite3.connect(self.projection.filename) as connection:
            database_text = "\n".join(connection.iterdump())
        self.assertNotIn("do not persist", database_text)
        self.assertNotIn("private", database_text)

    def test_gap_out_of_order_and_changed_duplicate_require_rebuild(self):
        for events in [[self.runtime.events[1]], [self.runtime.events[0], self.runtime.events[2], self.runtime.events[1]]]:
            with self.assertRaises(ServiceError): self.projection.apply_page(events)
            self.assertEqual(self.projection.health()["cursor"], 0)
            self.assertEqual(self.projection.health()["freshness"], "gap")
        self.projection.apply_page(self.runtime.events[:1])
        forged = {**self.runtime.events[0], "kind": "run.failed"}
        with self.assertRaises(ServiceError): self.projection.apply_page([forged])
        self.assertEqual(self.projection.run("run-1")["state"], "pending")
        self.projection.rebuild(self.runtime)
        self.assertEqual(self.projection.run("run-1")["state"], "succeeded")

    def test_page_limit_freshness_and_age_do_not_overstate_catchup(self):
        health = self.projection.sync(self.runtime, limit=2)
        self.assertEqual(health["freshness"], "catching_up")
        health = self.projection.sync(self.runtime, limit=2)
        self.assertEqual(health["freshness"], "current")
        self.projection.clock = lambda: 161
        self.assertEqual(self.projection.health()["freshness"], "stale")

    def test_projection_refuses_canonical_database_and_rebuild_does_not_mutate_service(self):
        canonical_path = Path(self.temp.name) / "canonical.db"
        store = SQLiteUnitOfWork(canonical_path)
        with self.assertRaisesRegex(ValueError, "own empty"):
            RuntimeProjection(canonical_path)
        service = Service(store, verifier=LocalDevUntrustedVerifier(), environment="test", allow_local_dev_untrusted=True)
        result = service.execute(command("request.create", "create", payload={"summary": "Retained intake"}))
        self.projection.rebuild(self.runtime); self.projection.reset_for_rebuild()
        self.assertEqual(service.execute(command("request.create", "create", payload={"summary": "Retained intake"})), result)

    def test_subscription_cursor_gap_marks_projection_unusable(self):
        self.projection.rebuild(self.runtime)
        def lost_history(envelope): raise RuntimeCallError("cursor_gap")
        self.runtime.query = lost_history
        with self.assertRaises(ServiceError) as failure: self.projection.sync(self.runtime)
        self.assertEqual(failure.exception.code, "projection_gap")
        self.assertEqual(self.projection.health()["freshness"], "gap")

    def test_rebuild_reports_and_repairs_drift_at_the_same_source_cursor(self):
        self.projection.rebuild(self.runtime)
        with sqlite3.connect(self.projection.filename) as connection:
            row = json.loads(connection.execute("SELECT data_json FROM run_summaries WHERE run_id='run-1'").fetchone()[0])
            row["state"] = "failed"
            connection.execute("UPDATE run_summaries SET data_json=? WHERE run_id='run-1'", (canonical(row),))
        health = self.projection.rebuild(self.runtime)
        self.assertTrue(health["last_rebuild"]["drift_detected"])
        self.assertEqual(self.projection.run("run-1")["state"], "succeeded")


if __name__ == "__main__": unittest.main()
