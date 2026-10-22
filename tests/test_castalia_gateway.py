import base64
import copy
import hashlib
import unittest
from datetime import UTC, datetime, timedelta

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:
    Ed25519PrivateKey = None

from service_management.castalia_gateway import (
    CastaliaClientReadPolicy,
    CastaliaClientReadVerifier,
    CastaliaEncryptedGatewayVerifier,
    CastaliaGatewayPolicy,
    client_read_authorization,
    encrypted_intake_authorization,
)
from service_management.castalia_requester import (
    CREDENTIAL_SIGNATURE_DOMAIN,
    PRESENTATION_SIGNATURE_DOMAIN,
    WalletPresentationPin,
)
from service_management.client_gateway import EncryptedGatewaySubmission
from service_management.contracts import canonical
from service_management.errors import ServiceError


def public(key):
    return key.public_key().public_bytes_raw().hex()


@unittest.skipIf(Ed25519PrivateKey is None, "install service-management[castalia-verifier]")
class CastaliaEncryptedGatewayVerifierTests(unittest.TestCase):
    def setUp(self):
        self.request_issuer = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("1c" * 32))
        self.holder = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("1d" * 32))
        self.policy_digest = "ab" * 32
        self.key_id = "tunnel:x25519:fixture-key"
        self.policy = CastaliaGatewayPolicy(
            (WalletPresentationPin("zenith-service-authority", "request-test-1",
                                   public(self.request_issuer), "zenith-service-management",
                                   (("browser", "https://anima.example"),)),),
            self.policy_digest, self.key_id, ("browser", "https://anima.example"))
        self.verifier = CastaliaEncryptedGatewayVerifier(self.policy)
        self.submission = EncryptedGatewaySubmission(
            "anima-brand-request-01", "anima-brand-submit-01", "zenith", "11" * 32)
        self.envelope_digest = "22" * 32
        self.now = datetime.fromtimestamp(1_800_000_001, tz=UTC)
        self.required_until = self.now + timedelta(days=7)

    def evidence(self):
        authorization = encrypted_intake_authorization(
            self.submission, self.envelope_digest, recipient_key_id=self.key_id,
            expires_at_ms=int(self.required_until.timestamp() * 1000))
        raw = canonical(authorization).encode()
        disclosure = {"title": "Send encrypted service request",
                      "statements": ["Send this exact encrypted request to Zenith."]}
        claims = {
            "schema": "castalia.request-credential.v1", "issuer": "zenith-service-authority",
            "key_id": "request-test-1", "holder_public_key": public(self.holder),
            "audience": "zenith-service-management",
            "caller": {"kind": "browser", "id": "https://anima.example"},
            "request_digest_sha256": hashlib.sha256(raw).hexdigest(),
            "disclosure_digest_sha256": hashlib.sha256(canonical(disclosure).encode()).hexdigest(),
            "policy_digest_sha256": self.policy_digest, "nonce": "01" * 16,
            "issued_at": 1_800_000_000, "expires_at": 1_800_000_120,
        }
        credential = {"claims": claims, "signature": self.request_issuer.sign(
            CREDENTIAL_SIGNATURE_DOMAIN + canonical(claims).encode()).hex()}
        request = {
            "schema": "castalia.credential-presentation-request.v2",
            "request_bytes_base64": base64.b64encode(raw).decode(),
            "disclosure": disclosure, "credential": credential,
        }
        unsigned = {
            "schema": "castalia.credential-presentation.v2",
            "holder_public_key": public(self.holder), "issuer": claims["issuer"],
            "key_id": claims["key_id"], "audience": claims["audience"],
            "caller": claims["caller"], "request_digest_sha256": claims["request_digest_sha256"],
            "credential_digest_sha256": hashlib.sha256(canonical(credential).encode()).hexdigest(),
            "disclosure_digest_sha256": claims["disclosure_digest_sha256"], "nonce": "02" * 16,
            "issued_at": 1_800_000_001, "expires_at": 1_800_000_061,
        }
        presentation = dict(unsigned, signature=self.holder.sign(
            PRESENTATION_SIGNATURE_DOMAIN + canonical(unsigned).encode()).hex())
        return {"schema": "service.castalia-gateway-presentation.v1",
                "presentation_request": request, "presentation": presentation}

    def verify(self, value, **overrides):
        return self.verifier.verify(
            overrides.get("submission", self.submission),
            overrides.get("envelope_digest", self.envelope_digest),
            canonical(value).encode(), now=overrides.get("now", self.now),
            required_until=overrides.get("required_until", self.required_until))

    def test_verifies_exact_public_gateway_request_at_submit_time(self):
        requester = self.verify(self.evidence())
        self.assertEqual(requester.subject, "did.castalia.key." + public(self.holder))
        self.assertEqual(requester.durable_evidence, canonical(self.evidence()).encode())

    def test_rejects_changed_envelope_submission_expiry_or_unknown_fields(self):
        evidence = self.evidence()
        cases = [
            {"envelope_digest": "33" * 32},
            {"submission": EncryptedGatewaySubmission(
                self.submission.request_id, self.submission.idempotency_key, "other", "11" * 32)},
            {"required_until": self.required_until - timedelta(seconds=1)},
        ]
        for changed in cases:
            with self.subTest(changed=changed):
                with self.assertRaises(ServiceError):
                    self.verify(evidence, **changed)
        unknown = copy.deepcopy(evidence); unknown["role"] = "admin"
        with self.assertRaises(ServiceError): self.verify(unknown)

    def test_rejects_expired_presentation_but_does_not_require_it_to_span_queue_ttl(self):
        self.verify(self.evidence())
        with self.assertRaises(ServiceError):
            self.verify(self.evidence(), now=datetime.fromtimestamp(1_800_000_061, tz=UTC))


@unittest.skipIf(Ed25519PrivateKey is None, "install service-management[castalia-verifier]")
class CastaliaClientReadVerifierTests(unittest.TestCase):
    def setUp(self):
        self.request_issuer = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("2c" * 32))
        self.holder = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("2d" * 32))
        self.policy_digest = "cd" * 32
        self.caller = ("browser", "https://anima.example")
        self.pin = WalletPresentationPin(
            "zenith-service-authority", "request-test-2", public(self.request_issuer),
            "zenith-service-management", (self.caller,))
        self.now = datetime.fromtimestamp(1_800_000_001, tz=UTC)
        self.verifier = CastaliaClientReadVerifier(
            CastaliaClientReadPolicy((self.pin,), self.policy_digest, self.caller),
            clock=lambda: self.now)

    def evidence(self, operation="request.status", resource="requests/anima-brand-request-01"):
        raw = canonical(client_read_authorization(operation, resource)).encode()
        disclosure = {"title": "Read service request",
                      "statements": ["Read this exact service request resource from Zenith."]}
        claims = {
            "schema": "castalia.request-credential.v1", "issuer": self.pin.issuer,
            "key_id": self.pin.key_id, "holder_public_key": public(self.holder),
            "audience": self.pin.audience,
            "caller": {"kind": self.caller[0], "id": self.caller[1]},
            "request_digest_sha256": hashlib.sha256(raw).hexdigest(),
            "disclosure_digest_sha256": hashlib.sha256(canonical(disclosure).encode()).hexdigest(),
            "policy_digest_sha256": self.policy_digest, "nonce": "11" * 16,
            "issued_at": 1_800_000_000, "expires_at": 1_800_000_120,
        }
        credential = {"claims": claims, "signature": self.request_issuer.sign(
            CREDENTIAL_SIGNATURE_DOMAIN + canonical(claims).encode()).hex()}
        request = {
            "schema": "castalia.credential-presentation-request.v2",
            "request_bytes_base64": base64.b64encode(raw).decode(),
            "disclosure": disclosure, "credential": credential,
        }
        unsigned = {
            "schema": "castalia.credential-presentation.v2",
            "holder_public_key": public(self.holder), "issuer": claims["issuer"],
            "key_id": claims["key_id"], "audience": claims["audience"],
            "caller": claims["caller"], "request_digest_sha256": claims["request_digest_sha256"],
            "credential_digest_sha256": hashlib.sha256(canonical(credential).encode()).hexdigest(),
            "disclosure_digest_sha256": claims["disclosure_digest_sha256"], "nonce": "12" * 16,
            "issued_at": 1_800_000_001, "expires_at": 1_800_000_061,
        }
        presentation = dict(unsigned, signature=self.holder.sign(
            PRESENTATION_SIGNATURE_DOMAIN + canonical(unsigned).encode()).hex())
        return canonical({"schema": "service.castalia-gateway-presentation.v1",
                          "presentation_request": request, "presentation": presentation}).encode()

    def test_verifies_exact_client_read_and_rejects_resource_substitution(self):
        evidence = self.evidence()
        self.assertEqual(
            self.verifier.verify("request.status", "requests/anima-brand-request-01", evidence),
            "did.castalia.key." + public(self.holder))
        with self.assertRaises(ServiceError):
            self.verifier.verify("request.status", "requests/anima-brand-request-02", evidence)
        with self.assertRaises(ServiceError):
            self.verifier.verify("artifact.get", "artifacts/" + "11" * 32, evidence)

    def test_rejects_unknown_operation_and_noncanonical_evidence(self):
        with self.assertRaises(ServiceError):
            self.verifier.verify("artifact.put", "artifacts/" + "11" * 32, self.evidence())
        with self.assertRaises(ServiceError):
            self.verifier.verify(
                "request.status", "requests/anima-brand-request-01", self.evidence() + b"\n")


if __name__ == "__main__":
    unittest.main()
