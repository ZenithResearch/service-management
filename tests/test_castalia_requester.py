import base64
import copy
import hashlib
import tempfile
import unittest
from pathlib import Path

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:
    Ed25519PrivateKey = None

from service_management.castalia_requester import (
    CREDENTIAL_SIGNATURE_DOMAIN,
    MEMBERSHIP_CREDENTIAL_DOMAIN,
    MEMBERSHIP_ID_DOMAIN,
    PRESENTATION_SIGNATURE_DOMAIN,
    CastaliaRequesterPolicy,
    CastaliaRequesterVerifier,
    WalletPresentationPin,
    ZenithMembershipRoot,
    load_requester_policy,
)
from service_management.client_intake import Intake, TransportReceipt
from service_management.contracts import canonical
from service_management.errors import ServiceError
from tests.test_client_intake import intake


def public(key):
    return key.public_key().public_bytes_raw().hex()


def b64url(value):
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def frame(value):
    encoded = value.encode()
    return len(encoded).to_bytes(4, "little") + encoded


@unittest.skipIf(Ed25519PrivateKey is None, "install service-management[castalia-verifier]")
class CastaliaRequesterVerifierTests(unittest.TestCase):
    def setUp(self):
        self.membership_issuer = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("0b" * 32))
        self.request_issuer = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("0c" * 32))
        self.holder = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("0d" * 32))
        self.policy_digest = "ab" * 32
        self.policy = CastaliaRequesterPolicy(
            (ZenithMembershipRoot("zenith-research", "membership-test-1", public(self.membership_issuer)),),
            (WalletPresentationPin("zenith-service-authority", "request-test-1", public(self.request_issuer),
                                   "zenith-service-management", (("browser", "https://anima.example"),)),),
            self.policy_digest,
        )
        self.verifier = CastaliaRequesterVerifier(self.policy)
        self.intake = Intake.parse(intake())
        self.receipt = TransportReceipt("vercel-queue", "vqs." + "01" * 32,
                                        "2027-01-15T08:00:01Z", "2027-01-22T08:00:01Z")

    def evidence(self):
        holder = public(self.holder)
        membership_id = hashlib.sha256(MEMBERSHIP_ID_DOMAIN + bytes.fromhex(holder)).hexdigest()
        membership_payload = {
            "schema": "castalia.zenith-membership-credential.v3", "version": 3,
            "membershipId": membership_id, "ownerPublicKey": holder, "status": "active",
            "issuerId": "zenith-research", "issuerKeyId": "membership-test-1", "signatureSuite": "Ed25519",
        }
        transcript = (MEMBERSHIP_CREDENTIAL_DOMAIN + (3).to_bytes(8, "little")
                      + bytes.fromhex(membership_id) + bytes.fromhex(holder) + frame("active")
                      + frame("zenith-research") + frame("membership-test-1") + frame("ed25519"))
        membership = dict(membership_payload,
                          issuerSignature=b64url(self.membership_issuer.sign(transcript)))

        raw = self.intake.raw_json.encode()
        disclosure = {"title": "Submit branding request", "statements": ["Create this exact service request."]}
        claims = {
            "schema": "castalia.request-credential.v1", "issuer": "zenith-service-authority",
            "key_id": "request-test-1", "holder_public_key": holder,
            "audience": "zenith-service-management",
            "caller": {"kind": "browser", "id": "https://anima.example"},
            "request_digest_sha256": hashlib.sha256(raw).hexdigest(),
            "disclosure_digest_sha256": hashlib.sha256(canonical(disclosure).encode()).hexdigest(),
            "policy_digest_sha256": self.policy_digest, "nonce": "01" * 16,
            "issued_at": 1800000000, "expires_at": 1800000120,
        }
        credential = {"claims": claims, "signature": self.request_issuer.sign(
            CREDENTIAL_SIGNATURE_DOMAIN + canonical(claims).encode()).hex()}
        request = {
            "schema": "castalia.credential-presentation-request.v2",
            "request_bytes_base64": base64.b64encode(raw).decode(),
            "disclosure": disclosure, "credential": credential,
        }
        unsigned = {
            "schema": "castalia.credential-presentation.v2", "holder_public_key": holder,
            "issuer": claims["issuer"], "key_id": claims["key_id"], "audience": claims["audience"],
            "caller": claims["caller"], "request_digest_sha256": claims["request_digest_sha256"],
            "credential_digest_sha256": hashlib.sha256(canonical(credential).encode()).hexdigest(),
            "disclosure_digest_sha256": claims["disclosure_digest_sha256"], "nonce": "02" * 16,
            "issued_at": 1800000001, "expires_at": 1800000061,
        }
        presentation = dict(unsigned, signature=self.holder.sign(
            PRESENTATION_SIGNATURE_DOMAIN + canonical(unsigned).encode()).hex())
        return {"schema": "service.castalia-requester-evidence.v1", "membership": membership,
                "presentation_request": request, "presentation": presentation}

    def verify(self, value, receipt=None):
        return self.verifier.verify(self.intake, canonical(value).encode(), receipt or self.receipt)

    def test_verifies_membership_and_exact_request_at_authenticated_queue_time(self):
        requester = self.verify(self.evidence())
        expected = hashlib.sha256(MEMBERSHIP_ID_DOMAIN + bytes.fromhex(public(self.holder))).hexdigest()
        self.assertEqual(requester.membership_credential_id, expected)
        self.assertEqual(requester.subject, "did.castalia.member." + expected)

    def test_rejects_membership_or_request_tampering(self):
        forged = self.evidence(); forged["membership"]["status"] = "revoked"
        with self.assertRaises(ServiceError) as membership_error: self.verify(forged)
        self.assertEqual(membership_error.exception.code, "forbidden")

        changed = self.evidence()
        changed["presentation_request"]["request_bytes_base64"] = base64.b64encode(b"other request").decode()
        with self.assertRaises(ServiceError) as request_error: self.verify(changed)
        self.assertEqual(request_error.exception.code, "forbidden")

    def test_rejects_proof_that_was_expired_when_queue_accepted_it(self):
        late = TransportReceipt("vercel-queue", "vqs." + "02" * 32,
                                "2027-01-15T08:02:01Z", None)
        with self.assertRaises(ServiceError) as raised: self.verify(self.evidence(), late)
        self.assertEqual(raised.exception.code, "forbidden")

    def test_transport_time_does_not_substitute_for_trusted_transport(self):
        local = TransportReceipt("fixture-inbox", "fixture-receipt", "2027-01-15T08:00:01Z", None)
        with self.assertRaises(ServiceError) as raised: self.verify(self.evidence(), local)
        self.assertEqual(raised.exception.code, "forbidden")

    def test_closed_operator_policy_file_round_trips_exact_pins(self):
        value = {
            "schema": "service.castalia-requester-policy.v1",
            "membership_roots": [{"issuer_id": root.issuer_id, "key_id": root.key_id,
                                  "public_key_hex": root.public_key_hex}
                                 for root in self.policy.membership_roots],
            "presentation_pins": [{"issuer": pin.issuer, "key_id": pin.key_id,
                                   "public_key_hex": pin.public_key_hex, "audience": pin.audience,
                                   "callers": [list(caller) for caller in pin.callers]}
                                  for pin in self.policy.presentation_pins],
            "policy_digest_sha256": self.policy.policy_digest_sha256,
            "trusted_transports": list(self.policy.trusted_transports),
        }
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "requester-policy.json"
            path.write_text(canonical(value)); path.chmod(0o600)
            self.assertEqual(load_requester_policy(path), self.policy)
            path.write_text(canonical({**value, "unexpected": True}))
            with self.assertRaises(ValueError): load_requester_policy(path)

    def test_rejects_unknown_fields_before_crypto(self):
        unknown = self.evidence(); unknown["presentation"]["role"] = "admin"
        with self.assertRaises(ServiceError) as raised: self.verify(unknown)
        self.assertEqual(raised.exception.code, "forbidden")


if __name__ == "__main__":
    unittest.main()
