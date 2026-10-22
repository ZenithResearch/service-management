import base64
import hashlib
import unittest
from datetime import UTC, datetime

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:
    Ed25519PrivateKey = None

from service_management.castalia_credential import (
    CREDENTIAL_SIGNATURE_DOMAIN,
    ReceiverCredentialConfig,
    ReceiverCredentialIssuer,
)
from service_management.castalia_requester import (
    MEMBERSHIP_CREDENTIAL_DOMAIN,
    MEMBERSHIP_ID_DOMAIN,
    ZenithMembershipRoot,
)
from service_management.contracts import canonical
from service_management.errors import ServiceError


def public(key): return key.public_key().public_bytes_raw().hex()
def b64url(value): return base64.urlsafe_b64encode(value).decode().rstrip("=")
def frame(value):
    encoded = value.encode(); return len(encoded).to_bytes(4, "little") + encoded


class Signer:
    def __init__(self, key): self.key = key; self.calls = []
    def sign(self, transcript): self.calls.append(transcript); return self.key.sign(transcript)


@unittest.skipIf(Ed25519PrivateKey is None, "install service-management[castalia-verifier]")
class ReceiverCredentialIssuerTests(unittest.TestCase):
    def setUp(self):
        self.membership_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("21" * 32))
        self.receiver_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("22" * 32))
        self.holder_key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("23" * 32))
        self.signer = Signer(self.receiver_key)
        self.root = ZenithMembershipRoot("zenith-research", "membership-1", public(self.membership_key))
        self.config = ReceiverCredentialConfig(
            "zenith-service-authority", "request-1", public(self.receiver_key), "zenith-service-management",
            (("browser", "https://anima.example"),), "ab" * 32,
        )
        self.issuer = ReceiverCredentialIssuer(
            self.config, (self.root,), self.signer,
            clock=lambda: datetime.fromtimestamp(1800000000, UTC),
        )

    def membership(self):
        owner = public(self.holder_key)
        membership_id = hashlib.sha256(MEMBERSHIP_ID_DOMAIN + bytes.fromhex(owner)).hexdigest()
        payload = {"schema":"castalia.zenith-membership-credential.v3", "version":3,
                   "membershipId":membership_id, "ownerPublicKey":owner, "status":"active",
                   "issuerId":"zenith-research", "issuerKeyId":"membership-1", "signatureSuite":"Ed25519"}
        transcript = (MEMBERSHIP_CREDENTIAL_DOMAIN + (3).to_bytes(8, "little")
                      + bytes.fromhex(membership_id) + bytes.fromhex(owner) + frame("active")
                      + frame("zenith-research") + frame("membership-1") + frame("ed25519"))
        return dict(payload, issuerSignature=b64url(self.membership_key.sign(transcript)))

    def request(self):
        return {"schema":"service.castalia-credential-issuance.v1", "membership":self.membership(),
                "request_digest_sha256":"cd" * 32, "disclosure_digest_sha256":"ef" * 32,
                "caller":{"kind":"browser", "id":"https://anima.example"}, "nonce":"01" * 16}

    def test_issues_existing_wallet_auth_v2_credential_for_member_and_exact_digests(self):
        result = self.issuer.issue(canonical(self.request()).encode())
        claims = result["claims"]
        self.assertEqual(claims["schema"], "castalia.request-credential.v1")
        self.assertEqual(claims["holder_public_key"], public(self.holder_key))
        self.assertEqual(claims["request_digest_sha256"], "cd" * 32)
        self.assertEqual(claims["issued_at"], 1800000000)
        self.assertEqual(claims["expires_at"], 1800000120)
        self.receiver_key.public_key().verify(
            bytes.fromhex(result["signature"]),
            CREDENTIAL_SIGNATURE_DOMAIN + canonical(claims).encode(),
        )
        self.assertEqual(self.signer.calls[-1], CREDENTIAL_SIGNATURE_DOMAIN + canonical(claims).encode())

    def test_rejects_untrusted_membership_caller_and_unknown_fields_before_signing(self):
        forged = self.request(); forged["membership"]["issuerSignature"] = "A" * 86
        wrong_caller = self.request(); wrong_caller["caller"]["id"] = "https://attacker.example"
        unknown = self.request(); unknown["role"] = "admin"
        for value in (forged, wrong_caller, unknown):
            with self.subTest(value=value), self.assertRaises(ServiceError):
                self.issuer.issue(canonical(value).encode())
        self.assertEqual(self.signer.calls, [])

    def test_signer_failure_or_wrong_length_never_returns_a_credential(self):
        class Broken:
            def sign(self, transcript): return b"short"
        issuer = ReceiverCredentialIssuer(self.config, (self.root,), Broken(),
            clock=lambda: datetime.fromtimestamp(1800000000, UTC))
        with self.assertRaises(ServiceError) as raised:
            issuer.issue(canonical(self.request()).encode())
        self.assertEqual(raised.exception.code, "internal_error")


if __name__ == "__main__": unittest.main()
