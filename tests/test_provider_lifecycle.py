import base64
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from service_management import Service
from service_management.authority import LocalDevUntrustedVerifier
from service_management.client_intake import (AdmissionWorker, Intake, IntakeStore,
                                               OpenedEnvelope, TransportReceipt,
                                               VerifiedRequester)
from service_management.contracts import canonical
from service_management.errors import ServiceError
from service_management.ingress import CommandIngress
from service_management.provider_lifecycle import BrandPackageLifecycleWorker
from service_management.runtime_port import RuntimeCallError, content_digest
from service_management.sqlite_store import SQLiteUnitOfWork


def intake():
    values = {"organization_name": "North Shore Field Notes",
              "brand_brief": "Build a practical identity."}
    return canonical({
        "schema": "service.intake.v1", "request_id": "anima-brand-request-01",
        "idempotency_key": "anima-brand-submit-01",
        "service": {"provider_id": "zenith", "service_id": "zenith.anima.brand-package",
                    "service_version": "1.0.0"},
        "brief": {"schema": "service.reviewed-brief.v1", "revision": 1,
                  "content_hash": hashlib.sha256(canonical(values).encode()).hexdigest(),
                  "values": values},
        "references": [], "submitted_at": "2026-10-21T18:00:00Z",
    }).encode()


class MemberVerifier:
    def verify(self, parsed, evidence, receipt):
        return VerifiedRequester("did.castalia.member.42f891", "membership-credential-01")


class LocalServicePort:
    def __init__(self, ingress):
        self.ingress, self.commands = ingress, []

    def submit(self, command):
        self.commands.append(("issue", command))
        return self.ingress.submit(command)

    def resume(self, command):
        self.commands.append(("resume", command))
        return self.ingress.submit(command)


class Runtime:
    def __init__(self, compiled, process_pin):
        self.compiled, self.pin = compiled, process_pin
        self.commands = []
        self.lose_artifact_result = True

    def new_command(self, operation, *, request_id, expected_version, payload):
        if operation == "artifact.put":
            resource = "artifacts/" + payload["artifact"]["content_hash"]
        elif operation == "handoff.consume":
            resource = "handoffs/" + content_digest(
                {"source": payload["source"], "event_id": payload["event_id"]})
        else:
            raise AssertionError(operation)
        return {"schema": "runtime.command.v1", "operation": operation,
                "request_id": request_id, "resource": resource,
                "expected_version": expected_version, "payload": payload}

    def query(self, envelope):
        if envelope["operation"] != "version.get":
            raise AssertionError(envelope)
        return {"schema": "runtime.query-result.v1", "operation": "version.get",
                "data": {"pin": self.pin, "compiled": self.compiled}}

    def command(self, envelope):
        self.commands.append(("issue", json.loads(canonical(envelope))))
        if self.lose_artifact_result:
            self.lose_artifact_result = False
            raise RuntimeCallError("unknown_outcome", retryable=True, uncertain=True)
        return self._artifact_result(envelope)

    def resume_command(self, envelope):
        self.commands.append(("resume", json.loads(canonical(envelope))))
        return self._artifact_result(envelope)

    @staticmethod
    def _artifact_result(envelope):
        return {"schema": "runtime.result.v1", "request_id": envelope["request_id"],
                "operation": envelope["operation"], "duplicate": False,
                "resource": envelope["resource"], "version": 1,
                "result": {"artifact": envelope["payload"]["artifact"]}}


class ProviderLifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        root = Path(self.temp.name)
        self.intakes = IntakeStore(root / "intake.db")
        self.store = SQLiteUnitOfWork(root / "service.db")
        compiled = {"inputs": {"organization_name": {"kind": "string"},
                               "reference_manifest": {"kind": "artifact"},
                               "reviewed_brief": {"kind": "artifact"}}}
        self.pin = {"process_id": "zenith.anima.brand-package",
                    "process_version": "zenith.anima.brand-package-v1",
                    "compilation_hash": content_digest(compiled)}
        self.runtime = Runtime(compiled, self.pin)
        service = Service(self.store, verifier=LocalDevUntrustedVerifier(),
                          environment="test", allow_local_dev_untrusted=True,
                          runtime=self.runtime)
        self.port = LocalServicePort(CommandIngress(service))
        receipt = TransportReceipt("fixture-inbox", "receipt-01", "2026-10-21T18:00:01Z", None)
        self.intakes.ingest(OpenedEnvelope(intake(), b"membership-proof"), receipt)
        AdmissionWorker(self.intakes, MemberVerifier(), self.port).admit_once()
        self.worker = BrandPackageLifecycleWorker(
            self.intakes, self.port, self.runtime, self.pin)

    def test_advances_exact_brand_package_with_artifacts_and_explicit_runtime_resume(self):
        for expected in ("qualified", "accepted", "converted", "planned"):
            self.assertEqual(self.worker.advance_once()[0]["stage"], expected)

        self.assertEqual(self.worker.advance_once(), [])
        held = self.intakes.lifecycle_status("anima-brand-request-01")
        self.assertEqual((held["stage"], held["authority_state"]),
                         ("planned", "resume_required"))
        issued = self.runtime.commands[-1][1]
        self.assertEqual(self.worker.advance_once(), [], "fresh authority is never repeated")
        self.assertEqual(self.worker.resume_once()[0]["stage"], "brief_stored")
        self.assertEqual(self.runtime.commands[-1], ("resume", issued))

        self.assertEqual(self.worker.advance_once()[0]["stage"], "references_stored")
        approved = self.worker.advance_once()[0]
        self.assertEqual(approved["stage"], "approved")
        handoff = self.store.transact(lambda tx: tx.pending_handoffs("", 1))[0]
        self.assertEqual(
            approved["activation"]["handoff_id"],
            content_digest({"source": "service-management", "event_id": handoff["event_id"]}),
        )
        self.assertEqual(
            approved["activation"]["run_id"],
            "handoff-" + approved["activation"]["handoff_id"][:48],
        )
        self.assertEqual(len(approved["activation"]["handoff_id"]), 64)
        self.assertEqual(self.intakes.lifecycle_status("anima-brand-request-01")["stage"], "approved")

        artifact_commands = [command for _, command in self.runtime.commands
                             if command["operation"] == "artifact.put"]
        self.assertEqual(len(artifact_commands), 3)  # issue+resume brief, then manifest
        contents = [base64.b64decode(command["payload"]["content_base64"])
                    for command in (artifact_commands[1], artifact_commands[2])]
        for command, content in zip((artifact_commands[1], artifact_commands[2]), contents):
            self.assertEqual(hashlib.sha256(content).hexdigest(),
                             command["payload"]["artifact"]["content_hash"])

        approval = json.loads(self.port.commands[-1][1])
        self.assertEqual(approval["operation"], "case.plan.approve")
        self.assertEqual(approval["payload"]["pin"], self.pin)
        self.assertEqual(approval["payload"]["inputs"]["organization_name"],
                         "North Shore Field Notes")
        self.assertEqual(set(approval["payload"]["inputs"]),
                         {"organization_name", "reference_manifest", "reviewed_brief"})
        handoffs = self.store.transact(lambda tx: tx.pending_handoffs("", 10))
        self.assertEqual(len(handoffs), 1)
        self.assertEqual(handoffs[0]["command"]["payload"]["pin"], self.pin)

    def test_rejects_other_provider_or_process_pin(self):
        bad = dict(self.pin, process_id="different")
        with self.assertRaisesRegex(ValueError, "exact brand-package"):
            BrandPackageLifecycleWorker(self.intakes, self.port, self.runtime, bad)

        value = json.loads(intake()); value["service"]["provider_id"] = "other"
        parsed = Intake.parse(canonical(value).encode())
        with self.assertRaises(ServiceError) as raised:
            self.worker._command("request_admitted", parsed)
        self.assertEqual(raised.exception.code, "invalid_command")


if __name__ == "__main__":
    unittest.main()
