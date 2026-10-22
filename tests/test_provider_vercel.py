import base64
import json
import unittest
from unittest.mock import patch

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:
    Ed25519PrivateKey = None

from service_management.provider_vercel import provider_application_from_environment


class Publisher:
    async def send(self, payload, *, idempotency_key, retention_seconds):
        return "fixture"


@unittest.skipIf(Ed25519PrivateKey is None, "install service-management[castalia-verifier]")
class ProviderVercelCompositionTests(unittest.TestCase):
    def setUp(self):
        key = Ed25519PrivateKey.from_private_bytes(bytes.fromhex("3c" * 32))
        self.seed = base64.urlsafe_b64encode(bytes.fromhex("3c" * 32)).decode().rstrip("=")
        self.environment = {
            "ZENITH_ANIMA_ORIGIN": "https://anima.example",
            "ZENITH_PROVIDER_ID": "zenith",
            "ZENITH_RECIPIENT_KEY_ID": "tunnel:x25519:provider-1",
            "ZENITH_RECEIVER_ISSUER": "zenith-service-authority",
            "ZENITH_RECEIVER_KEY_ID": "request-1",
            "ZENITH_RECEIVER_PUBLIC_KEY_HEX": key.public_key().public_bytes_raw().hex(),
            "ZENITH_RECEIVER_AUDIENCE": "zenith-service-management",
            "ZENITH_REQUESTER_POLICY_DIGEST_SHA256": "ab" * 32,
            "ZENITH_MEMBERSHIP_ROOTS_JSON": json.dumps([{
                "issuer_id": "zenith-research", "key_id": "membership-1",
                "public_key_hex": "22" * 32,
            }]),
            "ZENITH_RECEIVER_SIGNING_SEED_B64": self.seed,
            "ZENITH_QUEUE_REGION": "sfo1",
            "ZENITH_QUEUE_TOPIC": "zenith-intake-v1",
            "ZENITH_STATUS_BASE_URL": "https://operator-response.example",
            "VERCEL_OIDC_TOKEN": "a.b.c",
        }

    @patch("service_management.provider_vercel.VercelQueuePublisher.from_sdk",
           return_value=Publisher())
    def test_composes_only_from_explicit_pins_and_secret(self, factory):
        app = provider_application_from_environment(self.environment)
        self.assertEqual(app.config.browser_origin, "https://anima.example")
        self.assertEqual(app.intake_gateway.config.provider_id, "zenith")
        self.assertEqual(app.intake_gateway.config.recipient_key_id,
                         "tunnel:x25519:provider-1")
        self.assertEqual(app.config.status_base_url,
                         "https://operator-response.example")
        factory.assert_called_once_with(region="sfo1", token="a.b.c",
                                        topic="zenith-intake-v1")

    @patch("service_management.provider_vercel.VercelQueuePublisher.from_sdk",
           return_value=Publisher())
    def test_missing_or_mismatched_secret_fails_before_queue_composition(self, factory):
        missing = dict(self.environment); del missing["ZENITH_RECEIVER_SIGNING_SEED_B64"]
        with self.assertRaises(ValueError):
            provider_application_from_environment(missing)
        changed = dict(self.environment); changed["ZENITH_RECEIVER_SIGNING_SEED_B64"] = (
            base64.urlsafe_b64encode(bytes.fromhex("4c" * 32)).decode().rstrip("="))
        with self.assertRaises(ValueError):
            provider_application_from_environment(changed)
        factory.assert_not_called()

    @patch("service_management.provider_vercel.VercelQueuePublisher.from_sdk",
           return_value=Publisher())
    def test_rejects_insecure_browser_origin_and_malformed_membership_roots(self, factory):
        insecure = dict(self.environment); insecure["ZENITH_ANIMA_ORIGIN"] = "http://anima.example"
        with self.assertRaises(ValueError): provider_application_from_environment(insecure)
        malformed = dict(self.environment); malformed["ZENITH_MEMBERSHIP_ROOTS_JSON"] = "[]"
        with self.assertRaises(ValueError): provider_application_from_environment(malformed)
        factory.assert_not_called()


if __name__ == "__main__":
    unittest.main()
