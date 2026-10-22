import base64
import json
import unittest

from service_management.client_gateway import (
    INTAKE_ENVELOPE_MAGIC,
    REFERENCE_OBJECT_ENVELOPE_MAGIC,
    UnknownGatewayOutcome,
)
from service_management.provider_http import (
    ProviderHttpApplication,
    ProviderHttpConfig,
    ProviderHttpRequest,
)


KEY_ID = "tunnel:x25519:fixture-key"


def envelope(expires_at_ms=1_900_000_000_000):
    key = KEY_ID.encode()
    ciphertext = b"0" * 16
    return (INTAKE_ENVELOPE_MAGIC + expires_at_ms.to_bytes(8, "big") + bytes([len(key)])
            + key + b"e" * 32 + b"n" * 12 + len(ciphertext).to_bytes(4, "big") + ciphertext)


def reference_envelope(expires_at_ms=1_900_000_000_000):
    key = KEY_ID.encode(); ciphertext = b"0" * 16
    return (REFERENCE_OBJECT_ENVELOPE_MAGIC + expires_at_ms.to_bytes(8, "big")
            + bytes([len(key)]) + key + b"e" * 32 + b"n" * 12
            + len(ciphertext).to_bytes(4, "big") + ciphertext)


class Issuer:
    def __init__(self): self.calls = []
    def issue(self, body):
        self.calls.append(body)
        return {"claims": {"fixture": True}, "signature": "fixture"}


class Gateway:
    def __init__(self, *, unknown=False): self.calls = []; self.unknown = unknown
    async def submit(self, body, *, submission, requester_presentation):
        self.calls.append((body, submission, requester_presentation))
        if self.unknown: raise UnknownGatewayOutcome()
        if hasattr(submission, "artifact_id"):
            return {"schema": "service.reference-object-result.v1",
                    "request_id": submission.request_id,
                    "idempotency_key": submission.idempotency_key,
                    "artifact_id": submission.artifact_id,
                    "content_hash": submission.content_hash, "state": "pending",
                    "transport_receipt": {"transport": "fixture", "receipt_id": "receipt-1",
                                          "recorded_at": "2026-10-22T08:00:00.000Z",
                                          "expires_at": None}}
        return {"schema": "service.intake-result.v1", "request_id": submission.request_id,
                "idempotency_key": submission.idempotency_key, "state": "pending",
                "transport_receipt": None, "service_request_id": None,
                "service_request_version": None,
                "status_url": f"/v1/client/requests/{submission.request_id}"}


class ReadAuthorizer:
    def __init__(self): self.calls = []
    def verify(self, operation, resource, presentation):
        self.calls.append((operation, resource, presentation))
        return "did.castalia.key.member-1"


class Reader:
    def status(self, request_id, subject):
        return {"schema": "service.client-projection.v1", "request_id": request_id,
                "subject_for_test": subject}
    def artifact(self, request_id, content_hash, subject):
        return "text/plain", b"artifact"
    def receipt(self, request_id, owner, receipt_id, subject):
        return b'{"receipt":true}'


def headers(*items):
    return (("Origin", "https://anima.example"), *items)


class ProviderHttpApplicationTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.issuer, self.gateway = Issuer(), Gateway()
        self.app = ProviderHttpApplication(
            ProviderHttpConfig("https://anima.example"), self.issuer, self.gateway,
            reference_gateway=self.gateway)

    async def test_credential_issuance_has_exact_origin_and_no_ambient_credentials(self):
        body = b'{"fixture":true}'
        result = await self.app.handle(ProviderHttpRequest(
            "POST", "/v1/request-credential",
            headers(("Content-Type", "application/json"), ("Content-Length", str(len(body)))), body))
        self.assertEqual(result.status, 200)
        self.assertEqual(self.issuer.calls, [body])
        response_headers = dict(result.headers)
        self.assertEqual(response_headers["Access-Control-Allow-Origin"], "https://anima.example")
        self.assertNotIn("Access-Control-Allow-Credentials", response_headers)

    async def test_encrypted_intake_maps_only_bounded_metadata_and_ciphertext(self):
        body = envelope()
        proof = base64.urlsafe_b64encode(b'{"proof":"fixture"}').decode().rstrip("=")
        result = await self.app.handle(ProviderHttpRequest(
            "POST", "/v1/client/requests", headers(
                ("Content-Type", "application/vnd.zenith.service-intake-envelope-v1"),
                ("Content-Length", str(len(body))), ("Authorization", "Castalia " + proof),
                ("Idempotency-Key", "anima-brand-submit-01"),
                ("X-Zenith-Request-Id", "anima-brand-request-01"),
                ("X-Zenith-Provider-Id", "zenith"),
                ("X-Zenith-Intake-SHA256", "11" * 32),
                ("X-Zenith-Envelope-Key-Id", KEY_ID),
                ("X-Zenith-Envelope-Expires-At", "1900000000000")), body))
        self.assertEqual(result.status, 202)
        sent, submission, presentation = self.gateway.calls[0]
        self.assertEqual(sent, body)
        self.assertEqual(submission.request_id, "anima-brand-request-01")
        self.assertEqual(submission.intake_digest, "11" * 32)
        self.assertEqual(presentation, b'{"proof":"fixture"}')
        self.assertEqual(json.loads(result.body)["state"], "pending")

    async def test_encrypted_reference_maps_only_bound_metadata_and_ciphertext(self):
        body = reference_envelope()
        proof = base64.urlsafe_b64encode(b'{"proof":"reference"}').decode().rstrip("=")
        result = await self.app.handle(ProviderHttpRequest(
            "POST", "/v1/client/reference-objects", headers(
                ("Content-Type", "application/vnd.zenith.service-reference-object-envelope-v1"),
                ("Content-Length", str(len(body))), ("Authorization", "Castalia " + proof),
                ("Idempotency-Key", "anima-brand-submit-01"),
                ("X-Zenith-Request-Id", "anima-brand-request-01"),
                ("X-Zenith-Provider-Id", "zenith"),
                ("X-Zenith-Artifact-Id", "reference-1"),
                ("X-Zenith-Content-SHA256", "11" * 32),
                ("X-Zenith-Envelope-Key-Id", KEY_ID),
                ("X-Zenith-Envelope-Expires-At", "1900000000000")), body))
        self.assertEqual(result.status, 202)
        sent, submission, presentation = self.gateway.calls[0]
        self.assertEqual(sent, body)
        self.assertEqual(submission.artifact_id, "reference-1")
        self.assertEqual(submission.content_hash, "11" * 32)
        self.assertEqual(presentation, b'{"proof":"reference"}')

    async def test_origin_duplicates_header_mismatch_and_unknown_outcome_fail_closed(self):
        denied = await self.app.handle(ProviderHttpRequest(
            "POST", "/v1/request-credential", (("Origin", "https://attacker.example"),
                                                  ("Content-Type", "application/json")), b"{}"))
        self.assertEqual(denied.status, 403)
        duplicate = await self.app.handle(ProviderHttpRequest(
            "POST", "/v1/request-credential", headers(("Content-Type", "application/json"),
                                                         ("content-type", "application/json")), b"{}"))
        self.assertEqual(duplicate.status, 400)

        failing = ProviderHttpApplication(
            ProviderHttpConfig("https://anima.example"), self.issuer, Gateway(unknown=True))
        body = envelope(); proof = base64.urlsafe_b64encode(b"proof").decode().rstrip("=")
        result = await failing.handle(ProviderHttpRequest(
            "POST", "/v1/client/requests", headers(
                ("Content-Type", "application/vnd.zenith.service-intake-envelope-v1"),
                ("Authorization", "Castalia " + proof),
                ("Idempotency-Key", "anima-brand-submit-01"),
                ("X-Zenith-Request-Id", "anima-brand-request-01"),
                ("X-Zenith-Provider-Id", "zenith"),
                ("X-Zenith-Intake-SHA256", "11" * 32),
                ("X-Zenith-Envelope-Key-Id", KEY_ID),
                ("X-Zenith-Envelope-Expires-At", "1900000000000")), body))
        self.assertEqual(result.status, 503)
        error = json.loads(result.body)
        self.assertEqual(error["error"]["code"], "unavailable")
        self.assertTrue(error["error"]["retryable"])
        self.assertEqual(error["request_id"], "anima-brand-request-01")

    async def test_preflight_is_bounded_to_the_configured_origin(self):
        response = await self.app.handle(ProviderHttpRequest(
            "OPTIONS", "/v1/client/requests", headers(), b""))
        self.assertEqual(response.status, 204)
        self.assertEqual(response.body, b"")

    async def test_intake_can_publish_an_explicit_https_status_origin(self):
        app = ProviderHttpApplication(
            ProviderHttpConfig("https://anima.example",
                               status_base_url="https://operator-response.example/zenith/provider"),
            self.issuer, self.gateway)
        body = envelope()
        proof = base64.urlsafe_b64encode(b"proof").decode().rstrip("=")
        result = await app.handle(ProviderHttpRequest(
            "POST", "/v1/client/requests", headers(
                ("Content-Type", "application/vnd.zenith.service-intake-envelope-v1"),
                ("Content-Length", str(len(body))),
                ("Authorization", "Castalia " + proof),
                ("Idempotency-Key", "anima-brand-submit-01"),
                ("X-Zenith-Request-Id", "anima-brand-request-01"),
                ("X-Zenith-Provider-Id", "zenith"),
                ("X-Zenith-Intake-SHA256", "11" * 32),
                ("X-Zenith-Envelope-Key-Id", KEY_ID),
                ("X-Zenith-Envelope-Expires-At", "1900000000000")), body))
        self.assertEqual(json.loads(result.body)["status_url"],
                         "https://operator-response.example/zenith/provider/v1/client/requests/anima-brand-request-01")

    async def test_read_only_composition_rejects_every_mutating_method(self):
        app = ProviderHttpApplication(
            ProviderHttpConfig("https://anima.example"), None, None,
            client_reader=Reader(), read_authorizer=ReadAuthorizer(), read_only=True)
        response = await app.handle(ProviderHttpRequest(
            "POST", "/v1/client/requests", headers(), b""))
        self.assertEqual(response.status, 405)

    async def test_authorized_status_artifact_and_receipt_reads_are_separate(self):
        authorizer, reader = ReadAuthorizer(), Reader()
        app = ProviderHttpApplication(
            ProviderHttpConfig("https://anima.example"), self.issuer, self.gateway,
            client_reader=reader, read_authorizer=authorizer)
        proof = base64.urlsafe_b64encode(b"proof").decode().rstrip("=")
        values = []
        for path in (
            "/v1/client/requests/request-1",
            "/v1/client/requests/request-1/artifacts/" + "a" * 64,
            "/v1/client/requests/request-1/receipts/process-runtime/receipt-1",
        ):
            values.append(await app.handle(ProviderHttpRequest(
                "GET", path, headers(("Authorization", "Castalia " + proof)), b"")))
        self.assertEqual([value.status for value in values], [200, 200, 200])
        self.assertEqual(values[1].body, b"artifact")
        self.assertEqual(dict(values[1].headers)["Content-Type"], "text/plain")
        self.assertEqual([call[:2] for call in authorizer.calls], [
            ("request.status", "requests/request-1"),
            ("artifact.get", "artifacts/" + "a" * 64),
            ("receipt.get", "process-runtime/receipts/receipt-1"),
        ])

    async def test_read_route_without_projection_or_authority_is_unavailable(self):
        proof = base64.urlsafe_b64encode(b"proof").decode().rstrip("=")
        response = await self.app.handle(ProviderHttpRequest(
            "GET", "/v1/client/requests/request-1",
            headers(("Authorization", "Castalia " + proof)), b""))
        self.assertEqual(response.status, 503)
        self.assertTrue(json.loads(response.body)["error"]["retryable"])


if __name__ == "__main__":
    unittest.main()
