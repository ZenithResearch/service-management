"""Optional real-provider qualification, launched only through its public CLI.

Set SERVICE_RUNTIME_COMMAND to a JSON argv list for the installed runtime CLI.
Only the public process_runtime_client package is imported by this consumer.
"""

import json
import os
import socket
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from urllib.request import urlopen

from service_management import Service
from service_management.authority import LocalDevUntrustedVerifier
from service_management.contracts import canonical
from service_management.delivery import OutboxDelivery
from service_management.projection import RuntimeProjection
from service_management.sdk_adapter import SDKRuntimeAdapter
from service_management.sqlite_store import SQLiteUnitOfWork
from test_service import command
from test_integration import query


@unittest.skipUnless(os.environ.get("SERVICE_RUNTIME_COMMAND"), "set SERVICE_RUNTIME_COMMAND for real public-provider qualification")
class PublicSDKIntegrationTests(unittest.TestCase):
    def test_published_process_handoff_output_revision_and_projection_over_public_http(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0)); port = listener.getsockname()[1]
        argv = json.loads(os.environ["SERVICE_RUNTIME_COMMAND"])
        process = subprocess.Popen([*argv, "--database", str(Path(temp.name)/"runtime.db"), "--port", str(port), "--environment", "test", "--local-dev-untrusted"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        def stop():
            if process.poll() is None: process.terminate()
            try: process.communicate(timeout=10)
            except subprocess.TimeoutExpired: process.kill(); process.communicate(timeout=5)
        self.addCleanup(stop)
        endpoint = f"http://127.0.0.1:{port}"
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            if process.poll() is not None: self.fail("runtime CLI exited before readiness: " + process.stderr.read().decode()[-2000:])
            try:
                with urlopen(endpoint+"/live", timeout=0.2) as response:
                    if response.status == 200: break
            except OSError: time.sleep(0.05)
        else: self.fail("runtime CLI did not become live within 30 seconds")
        runtime = SDKRuntimeAdapter.connect(endpoint, environment="test", local_dev_untrusted=True)
        with self.assertRaisesRegex(ValueError, "production"):
            SDKRuntimeAdapter.connect(endpoint, local_dev_untrusted=True)
        def runtime_command(operation, request_id, resource, payload, expected_version=None):
            return runtime.command(runtime.new_command(operation, request_id=request_id, expected_version=expected_version, payload=payload))
        def runtime_query(operation, payload):
            return runtime.query({"schema": "runtime.query.v1", "operation": operation, "payload": payload})["data"]
        draft = {"schema": "process.draft.v1", "process_id": "inspection", "inputs": {"location": {"kind": "string"}}, "steps": [
            {"step_id": "inspect", "depends_on": [], "capabilities": ["inspect"], "resources": [], "inputs": {"location": {"kind": "string"}},
             "bindings": {"location": {"source": "run_input", "name": "location"}}, "outputs": {"finding": {"kind": "string"}}, "max_attempts": 3}]}
        provenance = {"source_id": "service-integration-test", "media_type": "application/json", "content_hash": "0"*64, "parser": "explicit-structured-block.v1", "uncertainties": []}
        runtime_command("process.draft.put", "draft-1", "process/inspection", {"draft": draft, "provenance": provenance})
        runtime_command("process.publish", "publish-1", "process/inspection", {"process_id": "inspection", "draft_revision": 1, "version_id": "inspection-v1"}, 1)
        pin = runtime_query("version.get", {"process_version": "inspection-v1"})["pin"]
        store = SQLiteUnitOfWork(Path(temp.name)/"service.db")
        with self.assertRaisesRegex(ValueError, "production"):
            Service(store, runtime=runtime)
        projection = RuntimeProjection(Path(temp.name)/"projection.db")
        service = Service(store, verifier=LocalDevUntrustedVerifier(), environment="test", allow_local_dev_untrusted=True, runtime=runtime, projection=projection)
        for raw in [command("request.create", "create", payload={"summary": "Inspection"}), command("request.qualify", "qualify", 1, {"qualification": "Qualified"}),
                    command("request.accept", "accept", 2, {"acceptance": "Accepted"}), command("request.convert", "convert", 3, {"case_id": "case-1", "obligation": "Inspect"}),
                    command("case.plan", "scope", 1, {"scope": "Inspect the location"}, resource_id="case-1")]:
            service.execute(raw)
        approval = service.execute(command("case.plan.approve", "approve", 2, {"revision_id": "revision-1", "reason": "Approved", "pin": pin, "inputs": {"location": "test site"}, "carry_forward": []}, resource_id="case-1"))
        worker = OutboxDelivery(store, runtime)
        delivered = worker.reconcile(approval["handoff"]["event_id"])
        self.assertEqual(delivered["state"], "started", delivered)
        run_id = delivered["run_id"]
        self.assertEqual(worker.reconcile(approval["handoff"]["event_id"]), delivered)
        runtime_command("actor.register", "register", "actor/inspector", {"actor_id": "inspector", "capabilities": ["inspect"], "resources": []})
        claim = runtime_command("executor.claim", "claim", f"run/{run_id}/step/inspect", {"run_id": run_id, "step_id": "inspect", "actor_id": "inspector", "lease_ms": 30000}, 1)["result"]
        runtime_command("executor.complete", "complete", f"run/{run_id}/step/inspect", {"run_id": run_id, "step_id": "inspect", "attempt_id": claim["attempt_id"], "fence": claim["fence"], "outputs": {"finding": "approved finding"}}, claim["step_version"])
        output = runtime_query("output.get", {"run_id": run_id, "step_id": "inspect", "attempt_id": claim["attempt_id"]})
        self.assertEqual(output["outputs"], {"finding": "approved finding"})
        projection.rebuild(runtime)
        summary = service.query(query("case.summary"))["data"]
        self.assertEqual(summary["canonical_service"]["state"], "planned")
        self.assertEqual(summary["derived_runtime"]["state"], "succeeded")
        self.assertNotIn("approved finding", canonical(summary))
        # A second explicitly selected version takes the first run's committed
        # finding as its input; the first run retains its original pin.
        draft2 = json.loads(json.dumps(draft)); draft2["inputs"] = {"evidence": {"kind": "string"}}
        draft2["steps"][0]["bindings"]["location"] = {"source": "run_input", "name": "evidence"}
        definition = runtime_query("process.get", {"process_id": "inspection"})
        draft_result = runtime_command("process.draft.put", "draft-2", "process/inspection", {"draft": draft2, "provenance": provenance}, definition["version"])
        runtime_command("process.publish", "publish-2", "process/inspection", {"process_id": "inspection", "draft_revision": draft_result["result"]["revision"], "version_id": "inspection-v2"}, draft_result["version"])
        pin2 = runtime_query("version.get", {"process_version": "inspection-v2"})["pin"]
        selection = {"run_id": run_id, "step_id": "inspect", "attempt_id": claim["attempt_id"], "output_name": "finding", "target_input": "evidence", "expected_output_digest": output["output_digest"]}
        revised = service.execute(command("case.plan.revise", "revise", 3, {"revision_id": "revision-2", "reason": "Owner approved replacement", "pin": pin2, "inputs": {}, "carry_forward": [selection], "superseded_run_id": run_id}, resource_id="case-1"))
        replacement = worker.reconcile(revised["handoff"]["event_id"])
        self.assertEqual(replacement["state"], "started", replacement)
        self.assertNotEqual(replacement["run_id"], run_id)
        self.assertEqual(runtime_query("run.get", {"run_id": run_id})["pin"], pin)
        self.assertEqual(runtime_query("run.get", {"run_id": replacement["run_id"]})["inputs"], {"evidence": "approved finding"})
        projection.rebuild(runtime)
        self.assertEqual(service.query(query("case.summary"))["data"]["derived_runtime"]["state"], "pending")


if __name__ == "__main__": unittest.main()
