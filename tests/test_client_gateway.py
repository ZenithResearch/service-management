import hashlib
import tempfile
import unittest
from datetime import UTC, datetime
from pathlib import Path

from service_management.client_gateway import (
    EncryptedGatewayConfig,
    EncryptedGatewaySubmission,
    EncryptedIntakeGateway,
    EncryptedReferenceGateway,
    EncryptedReferenceSubmission,
    GatewayConfig,
    INTAKE_ENVELOPE_MAGIC,
    REFERENCE_OBJECT_ENVELOPE_MAGIC,
    PublicIntakeGateway,
    UnknownGatewayOutcome,
    VercelQueuePublisher,
    VerifiedGatewayRequester,
)
from service_management.client_intake import IntakeStore, OpenedEnvelope, TransportReceipt
from service_management.errors import ServiceError
from tests.test_client_intake import intake


NOW = datetime(2026, 10, 22, 8, 0, tzinfo=UTC)
KEY_ID = "tunnel:x25519:fixture-key"


def encrypted_envelope(*, key_id=KEY_ID, expires_at_ms=1792742400000,
                       ciphertext=b"0" * 16):
    key = key_id.encode("ascii")
    return (INTAKE_ENVELOPE_MAGIC + expires_at_ms.to_bytes(8, "big") + bytes([len(key)])
            + key + b"e" * 32 + b"n" * 12 + len(ciphertext).to_bytes(4, "big")
            + ciphertext)


def encrypted_reference_envelope(*, key_id=KEY_ID, expires_at_ms=1792742400000,
                                 ciphertext=b"0" * 16):
    key = key_id.encode("ascii")
    return (REFERENCE_OBJECT_ENVELOPE_MAGIC + expires_at_ms.to_bytes(8, "big")
            + bytes([len(key)]) + key + b"e" * 32 + b"n" * 12
            + len(ciphertext).to_bytes(4, "big") + ciphertext)


class Verifier:
    def __init__(self): self.calls = []
    def verify(self, parsed, body_digest, presentation, *, now, required_until):
        self.calls.append((parsed.request_id, body_digest, presentation, now, required_until))
        if presentation != b"wallet-membership-presentation": raise ServiceError("forbidden")
        return VerifiedGatewayRequester("did.castalia.member.42f891", b"durable-exact-request-proof")


class Sealer:
    def __init__(self): self.calls = []
    def seal(self, body, evidence, *, provider_id, expires_at):
        self.calls.append((body, evidence, provider_id, expires_at)); return b"secs-encrypted-envelope"


class Publisher:
    def __init__(self, *, fail=False): self.calls = []; self.fail = fail
    async def send(self, payload, *, idempotency_key, retention_seconds):
        self.calls.append((payload, idempotency_key, retention_seconds))
        if self.fail: raise RuntimeError("network outcome unknown")
        return "opaque/message/id"


class Queue:
    def __init__(self): self.calls = []
    async def send(self, topic, payload, **options):
        self.calls.append((topic, payload, options)); return "opaque-id"


class EncryptedVerifier:
    def __init__(self): self.calls = []
    def verify(self, submission, envelope_digest, presentation, *, now, required_until):
        self.calls.append((submission, envelope_digest, presentation, now, required_until))
        if presentation != b"wallet-membership-presentation": raise ServiceError("forbidden")
        return VerifiedGatewayRequester("did.castalia.member.42f891", b"not-used-by-gateway")


class GatewayTests(unittest.IsolatedAsyncioTestCase):
    async def test_encrypted_reference_uses_distinct_frame_topic_key_and_result(self):
        verifier, publisher = EncryptedVerifier(), Publisher()
        submission = EncryptedReferenceSubmission(
            "anima-brand-request-01", "anima-brand-submit-01", "zenith",
            "reference-1", "a" * 64)
        gateway = EncryptedReferenceGateway(
            EncryptedGatewayConfig("zenith", KEY_ID), verifier, publisher,
            clock=lambda: NOW)
        result = await gateway.submit(
            encrypted_reference_envelope(), submission=submission,
            requester_presentation=b"wallet-membership-presentation")
        self.assertEqual(result["schema"], "service.reference-object-result.v1")
        self.assertEqual(result["artifact_id"], "reference-1")
        self.assertRegex(publisher.calls[0][1], r"^serv1\.[a-f0-9]{64}$")
        with self.assertRaises(ServiceError):
            await gateway.submit(encrypted_envelope(), submission=submission,
                                 requester_presentation=b"wallet-membership-presentation")

    async def test_already_encrypted_gateway_publishes_ciphertext_without_plaintext(self):
        verifier, publisher = EncryptedVerifier(), Publisher()
        envelope = encrypted_envelope()
        submission = EncryptedGatewaySubmission(
            "anima-brand-request-01", "anima-brand-submit-01", "zenith", "a" * 64)
        gateway = EncryptedIntakeGateway(
            EncryptedGatewayConfig("zenith", KEY_ID), verifier, publisher, clock=lambda: NOW)
        result = await gateway.submit(
            envelope, submission=submission,
            requester_presentation=b"wallet-membership-presentation")
        self.assertEqual(result["state"], "pending")
        self.assertEqual(result["request_id"], submission.request_id)
        self.assertEqual(result["transport_receipt"]["expires_at"], "2026-10-23T08:00:00.000Z")
        self.assertEqual(publisher.calls[0][0], envelope)
        self.assertRegex(publisher.calls[0][1], r"^seiv1\.[a-f0-9]{64}$")
        self.assertEqual(publisher.calls[0][2], 86400)
        self.assertEqual(verifier.calls[0][1], hashlib.sha256(envelope).hexdigest())

    async def test_encrypted_gateway_rejects_wrong_key_expiry_frame_or_membership_before_publish(self):
        cases = [
            (encrypted_envelope(key_id="tunnel:x25519:other"), b"wallet-membership-presentation"),
            (encrypted_envelope(expires_at_ms=1792655999000), b"wallet-membership-presentation"),
            (encrypted_envelope() + b"trailing", b"wallet-membership-presentation"),
            (encrypted_envelope(), b"wrong-proof"),
        ]
        for envelope, proof in cases:
            with self.subTest(envelope=envelope[:24], proof=proof):
                publisher = Publisher()
                gateway = EncryptedIntakeGateway(
                    EncryptedGatewayConfig("zenith", KEY_ID), EncryptedVerifier(), publisher,
                    clock=lambda: NOW)
                with self.assertRaises(ServiceError):
                    await gateway.submit(
                        envelope,
                        submission=EncryptedGatewaySubmission(
                            "anima-brand-request-01", "anima-brand-submit-01", "zenith", "a" * 64),
                        requester_presentation=proof)
                self.assertEqual(publisher.calls, [])

    async def test_encrypted_gateway_retry_uses_same_logical_dedup_key(self):
        submission = EncryptedGatewaySubmission(
            "anima-brand-request-01", "anima-brand-submit-01", "zenith", "a" * 64)
        failed = Publisher(fail=True)
        gateway = EncryptedIntakeGateway(
            EncryptedGatewayConfig("zenith", KEY_ID), EncryptedVerifier(), failed, clock=lambda: NOW)
        with self.assertRaises(UnknownGatewayOutcome):
            await gateway.submit(encrypted_envelope(), submission=submission,
                                 requester_presentation=b"wallet-membership-presentation")
        succeeded = Publisher()
        retry = EncryptedIntakeGateway(
            EncryptedGatewayConfig("zenith", KEY_ID), EncryptedVerifier(), succeeded, clock=lambda: NOW)
        await retry.submit(encrypted_envelope(), submission=submission,
                           requester_presentation=b"wallet-membership-presentation")
        self.assertEqual(failed.calls[0][1], succeeded.calls[0][1])

    async def test_verifies_seals_and_publishes_one_bounded_pending_request(self):
        verifier, sealer, publisher = Verifier(), Sealer(), Publisher()
        body = intake()
        gateway = PublicIntakeGateway(GatewayConfig("zenith"), verifier, sealer, publisher, clock=lambda: NOW)
        result = await gateway.submit(body, idempotency_key="anima-brand-submit-01",
                                      requester_presentation=b"wallet-membership-presentation")
        self.assertEqual(result["state"], "pending")
        self.assertIsNone(result["service_request_id"])
        self.assertEqual(result["transport_receipt"]["expires_at"], "2026-10-23T08:00:00.000Z")
        self.assertEqual(verifier.calls[0][1], hashlib.sha256(body).hexdigest())
        self.assertEqual(sealer.calls[0][:3], (body, b"durable-exact-request-proof", "zenith"))
        self.assertEqual(publisher.calls[0][0], b"secs-encrypted-envelope")
        self.assertRegex(publisher.calls[0][1], r"^siv1\.[a-f0-9]{64}$")

    async def test_wrong_header_provider_or_membership_fails_before_publish(self):
        for body, key, proof in [
            (intake(), "wrong-key", b"wallet-membership-presentation"),
            (b" " + intake(), "anima-brand-submit-01", b"wallet-membership-presentation"),
            (intake(), "anima-brand-submit-01", b"wrong-wallet-proof"),
        ]:
            publisher = Publisher()
            gateway = PublicIntakeGateway(GatewayConfig("zenith"), Verifier(), Sealer(), publisher, clock=lambda: NOW)
            with self.assertRaises(ServiceError):
                await gateway.submit(body, idempotency_key=key, requester_presentation=proof)
            self.assertEqual(publisher.calls, [])

    async def test_publish_failure_is_explicitly_unknown_and_exact_retry_key_is_stable(self):
        body = intake()
        failed = Publisher(fail=True)
        gateway = PublicIntakeGateway(GatewayConfig("zenith"), Verifier(), Sealer(), failed, clock=lambda: NOW)
        with self.assertRaises(UnknownGatewayOutcome):
            await gateway.submit(body, idempotency_key="anima-brand-submit-01",
                                 requester_presentation=b"wallet-membership-presentation")
        succeeded = Publisher()
        retry = PublicIntakeGateway(GatewayConfig("zenith"), Verifier(), Sealer(), succeeded, clock=lambda: NOW)
        await retry.submit(body, idempotency_key="anima-brand-submit-01",
                           requester_presentation=b"wallet-membership-presentation")
        self.assertEqual(failed.calls[0][1], succeeded.calls[0][1])

    async def test_different_requester_evidence_cannot_replace_the_retained_proof(self):
        temp = tempfile.TemporaryDirectory(); self.addCleanup(temp.cleanup)
        store = IntakeStore(Path(temp.name) / "intake.db")
        receipt = TransportReceipt("vercel-queue", "receipt-01", "2026-10-22T08:00:00Z", None)
        store.ingest(OpenedEnvelope(intake(), b"durable-proof-one"), receipt)
        with self.assertRaises(ServiceError) as raised:
            store.ingest(OpenedEnvelope(intake(), b"durable-proof-two"), receipt)
        self.assertEqual(raised.exception.code, "idempotency_conflict")

    async def test_official_publisher_passes_stable_idempotency_and_retention(self):
        queue = Queue(); publisher = VercelQueuePublisher(queue, "topic")
        result = await publisher.send(b"ciphertext", idempotency_key="stable-key", retention_seconds=86400)
        self.assertEqual(result, "opaque-id")
        self.assertEqual(queue.calls, [("topic", b"ciphertext", {"idempotency_key": "stable-key", "retention": 86400})])

    async def test_official_publisher_rejects_retention_beyond_live_vercel_limit(self):
        with self.assertRaises(ValueError):
            await VercelQueuePublisher(Queue(), "topic").send(
                b"ciphertext", idempotency_key="stable-key", retention_seconds=86401)

    def test_factory_rejects_static_token_shape_before_import(self):
        with self.assertRaises(ValueError):
            VercelQueuePublisher.from_sdk(region="sfo1", token="static-token", topic="zenith-intake-v1")


if __name__ == "__main__":
    unittest.main()
