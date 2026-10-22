import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from service_management import Service
from service_management.authority import LocalDevUntrustedVerifier
from service_management.client_intake import (
    AdmissionWorker,
    Delivery,
    Intake,
    IntakeStore,
    NativeAuthorizedServicePort,
    OpenedEnvelope,
    OpenedReferenceObject,
    PullWorker,
    TransportReceipt,
    UnknownAdmissionOutcome,
    VerifiedRequester,
)
from service_management.contracts import canonical
from service_management.errors import ServiceError
from service_management.ingress import CommandIngress
from service_management.sqlite_store import SQLiteUnitOfWork


def intake(*, request_id="anima-brand-request-01", key="anima-brand-submit-01", name="North Shore Field Notes"):
    values = {"organization_name": name, "brand_brief": "Build a practical identity."}
    return canonical({
        "schema": "service.intake.v1",
        "request_id": request_id,
        "idempotency_key": key,
        "service": {"provider_id": "zenith", "service_id": "zenith.anima.brand-package", "service_version": "1.0.0"},
        "brief": {"schema": "service.reviewed-brief.v1", "revision": 1,
                  "content_hash": hashlib.sha256(canonical(values).encode()).hexdigest(), "values": values},
        "references": [],
        "submitted_at": "2026-10-21T18:00:00Z",
    }).encode()


def opened(raw=None, evidence=b"membership-proof"):
    return OpenedEnvelope(raw or intake(), evidence)


def intake_with_reference(content=b"original-reference"):
    value = json.loads(intake())
    value["references"] = [{"schema": "service.artifact-manifest.v1",
                            "artifact_id": "reference-1",
                            "content_hash": hashlib.sha256(content).hexdigest(),
                            "byte_length": len(content), "media_type": "image/png",
                            "filename": "reference.png"}]
    return canonical(value).encode()


def receipt():
    return TransportReceipt("fixture-inbox", "transport-receipt-01", "2026-10-21T18:00:01Z", "2026-10-28T18:00:01Z")


class FakeInbox:
    def __init__(self, payload=b"ciphertext", *, lose_first_ack=False):
        self.delivery = Delivery("queue-handle", payload, receipt())
        self.acked = False
        self.ack_calls = 0
        self.lose_first_ack = lose_first_ack

    def pull(self, limit):
        return [] if self.acked else [self.delivery]

    def acknowledge(self, handle):
        self.ack_calls += 1
        if self.lose_first_ack and self.ack_calls == 1:
            raise RuntimeError("lost acknowledgement")
        self.acked = True


class FakeOpener:
    def __init__(self, value): self.value = value
    def open(self, payload): return self.value


class MemberVerifier:
    def __init__(self, *, allowed=True): self.allowed = allowed; self.calls = []
    def verify(self, parsed, evidence, transport_receipt):
        self.calls.append((parsed.digest, evidence, transport_receipt))
        if not self.allowed: raise ServiceError("forbidden")
        return VerifiedRequester("did.castalia.member.42f891", "membership-credential-01")


class LocalServicePort:
    def __init__(self, ingress, *, lose_first_result=False):
        self.ingress = ingress
        self.commands = []
        self.lose_first_result = lose_first_result

    def submit(self, command):
        self.commands.append(command)
        result = self.ingress.submit(command)
        if self.lose_first_result and len(self.commands) == 1:
            raise UnknownAdmissionOutcome()
        return result

    def resume(self, command):
        self.commands.append(command)
        return self.ingress.submit(command)


class ClientIntakeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.intakes = IntakeStore(self.root / "intake.db")
        canonical_store = SQLiteUnitOfWork(self.root / "service.db")
        service = Service(canonical_store, verifier=LocalDevUntrustedVerifier(), environment="test", allow_local_dev_untrusted=True)
        self.ingress = CommandIngress(service)
        self.canonical_store = canonical_store

    def test_parse_closes_contract_and_verifies_reviewed_brief_hash(self):
        parsed = Intake.parse(intake())
        self.assertEqual(parsed.service_id, "zenith.anima.brand-package")
        value = json.loads(intake())
        value["brief"]["values"]["organization_name"] = "Changed after review"
        with self.assertRaises(ServiceError) as raised:
            Intake.parse(canonical(value).encode())
        self.assertEqual(raised.exception.code, "invalid_command")
        value = json.loads(intake()); value["unexpected"] = True
        with self.assertRaises(ServiceError): Intake.parse(canonical(value).encode())

    def test_acknowledges_only_after_durable_commit_and_ack_loss_is_exact_retry(self):
        inbox = FakeInbox(lose_first_ack=True)
        worker = PullWorker(inbox, FakeOpener(opened()), self.intakes)
        with self.assertRaisesRegex(RuntimeError, "lost acknowledgement"):
            worker.pull_once()
        self.assertEqual(self.intakes.get("anima-brand-request-01")["state"], "pending")
        self.assertEqual(worker.pull_once()[0]["request_id"], "anima-brand-request-01")
        self.assertTrue(inbox.acked)
        self.assertEqual(len(self.intakes.pending()), 1)

    def test_idempotency_identity_rejects_changed_content_or_split_keys(self):
        self.intakes.ingest(opened(), receipt())
        self.assertEqual(self.intakes.ingest(opened(), receipt())["state"], "pending")
        with self.assertRaises(ServiceError) as changed:
            self.intakes.ingest(opened(intake(name="Different")), receipt())
        self.assertEqual(changed.exception.code, "idempotency_conflict")
        with self.assertRaises(ServiceError):
            self.intakes.ingest(opened(intake(request_id="different-request")), receipt())
        with self.assertRaises(ServiceError):
            self.intakes.ingest(opened(intake(key="different-key")), receipt())
        with self.assertRaises(ServiceError) as evidence:
            self.intakes.ingest(opened(evidence=b"different-membership-proof"), receipt())
        self.assertEqual(evidence.exception.code, "idempotency_conflict")

    def test_reference_can_arrive_before_or_after_intake_and_gates_admission(self):
        content, evidence = b"original-reference", b"membership-proof"
        reference = OpenedReferenceObject(
            "anima-brand-request-01", "anima-brand-submit-01", "reference-1",
            hashlib.sha256(content).hexdigest(), content, evidence)
        self.intakes.ingest_reference(reference, receipt())
        self.intakes.ingest(opened(intake_with_reference(), evidence), receipt())
        port = LocalServicePort(self.ingress)
        result = AdmissionWorker(self.intakes, MemberVerifier(), port).admit_once()
        self.assertEqual(result[0]["state"], "admitted")
        exact = self.intakes.reference_objects_for_intake(
            Intake.parse(intake_with_reference()), evidence)
        self.assertEqual(exact[0]["content"], content)

        other = IntakeStore(self.root / "other-intake.db")
        other.ingest(opened(intake_with_reference(), evidence), receipt())
        waiting = LocalServicePort(self.ingress)
        self.assertEqual(AdmissionWorker(other, MemberVerifier(), waiting).admit_once(), [])
        self.assertEqual(waiting.commands, [])
        other.ingest_reference(OpenedReferenceObject(
            reference.request_id, reference.idempotency_key, reference.artifact_id,
            reference.content_hash, content, b"different-evidence"), receipt())
        with self.assertRaises(ServiceError) as mismatch:
            AdmissionWorker(other, MemberVerifier(), waiting).admit_once()
        self.assertEqual(mismatch.exception.code, "idempotency_conflict")

    def test_unknown_service_result_retries_same_command_without_duplicate_request(self):
        self.intakes.ingest(opened(), receipt())
        port = LocalServicePort(self.ingress, lose_first_result=True)
        worker = AdmissionWorker(self.intakes, MemberVerifier(), port)
        self.assertEqual(worker.admit_once(), [])
        self.assertEqual(self.intakes.get("anima-brand-request-01")["state"], "pending")
        self.assertEqual(worker.admit_once(), [], "fresh issue is never repeated after uncertainty")
        completed = worker.resume_once()
        self.assertEqual(completed[0]["state"], "admitted")
        self.assertEqual(port.commands[0], port.commands[1])
        self.assertEqual(completed[0]["service_request_id"], "anima-brand-request-01")
        self.assertEqual(len(self.canonical_store.audit_history("ServiceRequest", "anima-brand-request-01")), 1)

    def test_dispatcher_transport_proof_cannot_replace_requester_membership(self):
        self.intakes.ingest(opened(evidence=b"valid-dispatcher-but-no-member"), receipt())
        port = LocalServicePort(self.ingress)
        result = AdmissionWorker(self.intakes, MemberVerifier(allowed=False), port).admit_once()
        self.assertEqual(result[0]["state"], "rejected")
        self.assertEqual(port.commands, [])
        self.assertEqual(self.canonical_store.audit_history("ServiceRequest", "anima-brand-request-01"), [])

    def test_restart_retains_pending_command_and_recovers(self):
        self.intakes.ingest(opened(), receipt())
        first = LocalServicePort(self.ingress, lose_first_result=True)
        AdmissionWorker(self.intakes, MemberVerifier(), first).admit_once()
        reopened = IntakeStore(self.root / "intake.db")
        second = LocalServicePort(self.ingress)
        restarted = AdmissionWorker(reopened, MemberVerifier(), second)
        self.assertEqual(restarted.admit_once(), [])
        result = restarted.resume_once()[0]
        self.assertEqual(result["state"], "admitted")
        self.assertEqual(first.commands[0], second.commands[0])
        self.assertTrue(reopened.health())

    def test_admission_rejects_a_result_bound_to_a_different_command_or_resource(self):
        self.intakes.ingest(opened(), receipt())
        requester = MemberVerifier().verify(Intake.parse(intake()), b"membership-proof", receipt())
        command = AdmissionWorker.command(Intake.parse(intake()), requester)
        self.intakes.retain_command("anima-brand-request-01", command, requester)
        result = self.ingress.submit(command)

        wrong_command = dict(result, request_id="different-command")
        with self.assertRaises(ServiceError) as command_error:
            self.intakes.admit("anima-brand-request-01", hashlib.sha256(command).hexdigest(), wrong_command)
        self.assertEqual(command_error.exception.code, "internal_error")

        wrong_resource = dict(result, service_request=dict(result["service_request"], id="different-resource"))
        with self.assertRaises(ServiceError) as resource_error:
            self.intakes.admit("anima-brand-request-01", hashlib.sha256(command).hexdigest(), wrong_resource)
        self.assertEqual(resource_error.exception.code, "internal_error")
        self.assertEqual(self.intakes.get("anima-brand-request-01")["state"], "pending")

    def test_native_service_port_issues_for_and_submits_the_exact_command(self):
        calls = []

        class Issuer:
            def issue(self, command):
                calls.append(("issue", command)); return b"native-evidence"
            def resume(self, command):
                calls.append(("resume", command)); return b"native-evidence"

        class Ingress:
            def submit(self, command, *, authority_evidence=None):
                calls.append(("submit", command, authority_evidence)); return {"accepted": True}

        command = AdmissionWorker.command(Intake.parse(intake()), VerifiedRequester(
            "did.castalia.member.42f891", "membership-credential-01"))
        self.assertEqual(NativeAuthorizedServicePort(Ingress(), Issuer()).submit(command), {"accepted": True})
        self.assertEqual(calls, [("issue", command), ("submit", command, b"native-evidence")])
        self.assertEqual(NativeAuthorizedServicePort(Ingress(), Issuer()).resume(command), {"accepted": True})
        self.assertEqual(calls[-2:], [("resume", command), ("submit", command, b"native-evidence")])

        class EmptyIssuer:
            def issue(self, command): return b""

        with self.assertRaises(ServiceError) as rejected:
            NativeAuthorizedServicePort(Ingress(), EmptyIssuer()).submit(command)
        self.assertEqual(rejected.exception.code, "forbidden")

    def test_authority_marker_is_durable_before_issue_and_resume_is_explicit(self):
        self.intakes.ingest(opened(), receipt())

        class Uncertain:
            def __init__(self): self.issued = 0; self.resumed = 0
            def submit(inner, command):
                inner.issued += 1
                row = self.intakes.pending(recovery=True)[0]
                self.assertEqual(row["authority_state"], "resume_required")
                raise UnknownAdmissionOutcome()
            def resume(inner, command):
                inner.resumed += 1
                return self.ingress.submit(command)

        port = Uncertain(); worker = AdmissionWorker(self.intakes, MemberVerifier(), port)
        self.assertEqual(worker.admit_once(), [])
        self.assertEqual(port.issued, 1)
        self.assertEqual(worker.admit_once(), [])
        self.assertEqual(port.issued, 1)
        self.assertEqual(worker.resume_once()[0]["state"], "admitted")
        self.assertEqual(port.resumed, 1)


if __name__ == "__main__":
    unittest.main()
