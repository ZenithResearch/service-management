from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime
from types import SimpleNamespace
import unittest

from service_management.contracts import canonical
from service_management.errors import ServiceError
from service_management.provider_projection import LocalProviderProjection
from service_management.runtime_port import RuntimeCallError


class Intakes:
    def projection_source(self, request_id):
        if request_id != "request-1": return None
        return {"request_id": request_id, "idempotency_key": "submit-1",
                "intake": {"service": {"provider_id": "zenith",
                                         "service_id": "zenith.anima.brand-package"}},
                "transport_receipt": {"transport": "vercel-queue", "receipt_id": "receipt-transport",
                                      "recorded_at": "2026-10-22T12:00:00.000Z", "expires_at": None},
                "state": "admitted", "requester_subject": "did.castalia.key.member-1",
                "rejection_code": None}


class Storage:
    def transact(self, operation):
        request = SimpleNamespace(id="request-1", state="accepted", version=4, case_id="case-1")
        case = SimpleNamespace(id="case-1", state="planned", version=3,
                               current_plan_revision_id="revision-1")
        tx = SimpleNamespace(
            get_request=lambda value: request if value == "request-1" else None,
            get_case=lambda value: case if value == "case-1" else None,
            handoff_for_revision=lambda value: {"run_id": "run-1", "state": "started"},
        )
        return operation(tx)


class Runtime:
    def __init__(self, unavailable=False): self.unavailable = unavailable
    def query(self, envelope):
        if self.unavailable: raise RuntimeCallError("storage_unavailable", retryable=True)
        operation, payload = envelope["operation"], envelope["payload"]
        artifact = {"content_hash": hashlib.sha256(b"package").hexdigest(),
                    "byte_length": 7, "media_type": "text/markdown"}
        outputs = {"brand_package": artifact,
                   "deliverable_manifest": {"content_hash": "d" * 64, "byte_length": 2,
                                             "media_type": "application/json"},
                   "quality_report": {"content_hash": "e" * 64, "byte_length": 2,
                                      "media_type": "text/markdown"}}
        if operation == "run.get":
            data = {"run_id": "run-1", "state": "succeeded", "steps": [
                {"step_id": "package-deliverables", "state": "succeeded", "attempt_id": "attempt-1"}]}
        elif operation == "output.get":
            data = {"receipt_id": "receipt-attempt-1", "run_id": "run-1",
                    "step_id": "package-deliverables", "attempt_id": "attempt-1",
                    "output_digest": hashlib.sha256(canonical(outputs).encode()).hexdigest(),
                    "outputs": outputs}
        elif operation == "receipt.get":
            data = {"schema": "runtime.receipt.v1", "receipt_id": payload["receipt_id"],
                    "run_id": "run-1", "step_id": "package-deliverables",
                    "attempt_id": "attempt-1", "outcome": "succeeded",
                    "output_digest": hashlib.sha256(canonical(outputs).encode()).hexdigest(),
                    "recorded_at_ms": 1_798_000_000_000}
        elif operation == "artifact.get":
            data = {"artifact": artifact, "content_base64": base64.b64encode(b"package").decode()}
        else: raise AssertionError(operation)
        return {"schema": "runtime.query-result.v1", "operation": operation, "data": data}


class ProviderProjectionTests(unittest.TestCase):
    def projection(self, unavailable=False):
        return LocalProviderProjection(Intakes(), Storage(), Runtime(unavailable),
            clock=lambda: datetime(2026, 10, 22, 12, tzinfo=UTC))

    def test_delivered_projection_and_exact_artifact_receipt_reads(self):
        projection = self.projection()
        result = projection.status("request-1", "did.castalia.key.member-1")
        self.assertEqual(result["execution"]["state"], "succeeded")
        self.assertEqual([item["id"] for item in result["deliverables"]],
                         ["brand-package", "deliverable-manifest", "quality-report"])
        reference = result["receipts"][0]
        self.assertEqual(reference["verification"]["state"], "unverified")
        media_type, body = projection.artifact(
            "request-1", hashlib.sha256(b"package").hexdigest(), "did.castalia.key.member-1")
        self.assertEqual((media_type, body), ("text/markdown", b"package"))
        receipt = projection.receipt(
            "request-1", "process-runtime", "receipt-attempt-1", "did.castalia.key.member-1")
        self.assertEqual(hashlib.sha256(receipt).hexdigest(), reference["content_hash"])

    def test_wrong_member_denies_and_runtime_outage_stays_unknown(self):
        with self.assertRaises(ServiceError) as denied:
            self.projection().status("request-1", "did.castalia.key.member-2")
        self.assertEqual(denied.exception.code, "forbidden")
        result = self.projection(unavailable=True).status(
            "request-1", "did.castalia.key.member-1")
        self.assertEqual(result["execution"], {"run_id": "run-1", "state": "unknown",
                                               "freshness": "unavailable", "observed_at": None})
        self.assertEqual(result["deliverables"], [])


if __name__ == "__main__": unittest.main()
