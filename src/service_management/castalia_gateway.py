"""Castalia Wallet Auth v2 verifier for the public encrypted-intake boundary."""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from .castalia_requester import (
    Ed25519PublicKey,
    MEMBERSHIP_ID_DOMAIN,
    WalletPresentationPin,
    verify_wallet_presentation,
)
from .client_gateway import (
    EncryptedGatewaySubmission,
    VerifiedGatewayRequester,
)
from .client_intake import MAX_EVIDENCE_BODY
from .contracts import canonical
from .errors import ServiceError

AUTHORIZATION_SCHEMA = "service.encrypted-intake-authorization.v1"
PRESENTATION_SCHEMA = "service.castalia-gateway-presentation.v1"
CLIENT_READ_SCHEMA = "service.client-read-authorization.v1"
CLIENT_READ_OPERATIONS = {"request.status", "artifact.get", "receipt.get"}


def gateway_requester_schema() -> dict:
    """Published bundle for exact gateway authorization and Wallet presentation."""
    hex32 = {"type": "string", "pattern": "^[0-9a-f]{64}$"}
    identifier = {"type": "string", "pattern": "^[a-z0-9][a-z0-9._-]{0,127}$"}
    authorization = {
        "type": "object", "additionalProperties": False,
        "required": ["schema", "provider_id", "request_id", "idempotency_key",
                     "intake_digest_sha256", "envelope_digest_sha256", "recipient_key_id",
                     "envelope_expires_at_ms"],
        "properties": {
            "schema": {"const": AUTHORIZATION_SCHEMA},
            "provider_id": identifier, "request_id": identifier, "idempotency_key": identifier,
            "intake_digest_sha256": hex32, "envelope_digest_sha256": hex32,
            "recipient_key_id": {"type": "string", "minLength": 1, "maxLength": 255,
                                 "pattern": "^[!-~]+$"},
            "envelope_expires_at_ms": {"type": "integer", "minimum": 0,
                                       "maximum": 9_007_199_254_740_991},
        },
    }
    presentation = {
        "type": "object", "additionalProperties": False,
        "required": ["schema", "presentation_request", "presentation"],
        "properties": {
            "schema": {"const": PRESENTATION_SCHEMA},
            "presentation_request": {"$ref": "requester.evidence.v1.schema.json#/$defs/presentationRequest"},
            "presentation": {"$ref": "requester.evidence.v1.schema.json#/$defs/presentation"},
        },
    }
    return {
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$id": "urn:service-management:gateway-requester:v1",
        "title": "Encrypted intake gateway requester contracts v1",
        "$defs": {"authorization": authorization, "presentation": presentation},
    }


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _exact(value: Any, fields: set[str]) -> dict:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("invalid shape")
    return value


def encrypted_intake_authorization(submission: EncryptedGatewaySubmission,
                                   envelope_digest: str, *, recipient_key_id: str,
                                   expires_at_ms: int) -> dict:
    """Build the exact public request a Wallet credential and presentation bind."""
    if (not isinstance(envelope_digest, str) or len(envelope_digest) != 64
            or any(c not in "0123456789abcdef" for c in envelope_digest)
            or not isinstance(recipient_key_id, str)
            or not 1 <= len(recipient_key_id.encode("ascii", errors="ignore")) <= 255
            or recipient_key_id.encode("ascii", errors="ignore").decode("ascii") != recipient_key_id
            or any(ord(c) < 0x21 or ord(c) > 0x7e for c in recipient_key_id)
            or type(expires_at_ms) is not int or not 0 <= expires_at_ms <= 2**53 - 1):
        raise ValueError("invalid encrypted intake authorization")
    return {
        "schema": AUTHORIZATION_SCHEMA,
        "provider_id": submission.provider_id,
        "request_id": submission.request_id,
        "idempotency_key": submission.idempotency_key,
        "intake_digest_sha256": submission.intake_digest,
        "envelope_digest_sha256": envelope_digest,
        "recipient_key_id": recipient_key_id,
        "envelope_expires_at_ms": expires_at_ms,
    }


@dataclass(frozen=True)
class CastaliaGatewayPolicy:
    presentation_pins: tuple[WalletPresentationPin, ...]
    policy_digest_sha256: str
    recipient_key_id: str
    caller: tuple[str, str]

    def __post_init__(self):
        if (not self.presentation_pins or not isinstance(self.policy_digest_sha256, str)
                or len(self.policy_digest_sha256) != 64
                or any(c not in "0123456789abcdef" for c in self.policy_digest_sha256)):
            raise ValueError("invalid Castalia gateway policy")
        # Reuse the exact request builder's closed key checks.
        encrypted_intake_authorization(
            EncryptedGatewaySubmission("check", "check", "check", "0" * 64), "0" * 64,
            recipient_key_id=self.recipient_key_id, expires_at_ms=0)
        if self.caller not in {caller for pin in self.presentation_pins for caller in pin.callers}:
            raise ValueError("gateway caller is not pinned")


class CastaliaEncryptedGatewayVerifier:
    """Verify the outer browser presentation over immutable public routing data."""

    def __init__(self, policy: CastaliaGatewayPolicy):
        if Ed25519PublicKey is None:
            raise RuntimeError("install service-management[castalia-verifier]")
        self.policy = policy

    def verify(self, submission: EncryptedGatewaySubmission, envelope_digest: str,
               presentation: bytes, *, now: datetime, required_until: datetime
               ) -> VerifiedGatewayRequester:
        try:
            if (not isinstance(now, datetime) or now.tzinfo is None
                    or not isinstance(required_until, datetime) or required_until.tzinfo is None):
                raise ValueError("gateway times must be timezone-aware")
            expires_at_ms = math.floor(required_until.timestamp() * 1000)
            authorization = encrypted_intake_authorization(
                submission, envelope_digest, recipient_key_id=self.policy.recipient_key_id,
                expires_at_ms=expires_at_ms)
            request_bytes = canonical(authorization).encode("utf-8")
            if not isinstance(presentation, bytes) or not 0 < len(presentation) <= MAX_EVIDENCE_BODY:
                raise ValueError("invalid presentation size")
            value = json.loads(
                presentation.decode("utf-8"), object_pairs_hook=_pairs,
                parse_float=lambda _: (_ for _ in ()).throw(ValueError()),
                parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
            if canonical(value).encode("utf-8") != presentation:
                raise ValueError("gateway presentation is not canonical")
            value = _exact(value, {"schema", "presentation_request", "presentation"})
            if value["schema"] != PRESENTATION_SCHEMA:
                raise ValueError("unsupported gateway presentation")
            holder = verify_wallet_presentation(
                request_bytes, value["presentation_request"], value["presentation"],
                presentation_pins=self.policy.presentation_pins,
                policy_digest_sha256=self.policy.policy_digest_sha256,
                accepted_at=math.floor(now.timestamp()), expected_caller=self.policy.caller)
            subject = "did.castalia.key." + holder
            return VerifiedGatewayRequester(subject, canonical(value).encode("utf-8"))
        except (KeyError, TypeError, ValueError, UnicodeError, OverflowError, json.JSONDecodeError):
            raise ServiceError("forbidden") from None


def client_read_authorization(operation: str, resource: str) -> dict:
    if (operation not in CLIENT_READ_OPERATIONS or not isinstance(resource, str)
            or not 1 <= len(resource) <= 4096 or "\0" in resource):
        raise ValueError("invalid client read authorization")
    prefixes = {"request.status": "requests/", "artifact.get": "artifacts/",
                "receipt.get": ("process-runtime/receipts/", "service-management/receipts/",
                                "secs/receipts/")}
    expected = prefixes[operation]
    if ((isinstance(expected, str) and not resource.startswith(expected))
            or (isinstance(expected, tuple) and not resource.startswith(expected))):
        raise ValueError("invalid client read resource")
    return {"schema": CLIENT_READ_SCHEMA, "operation": operation, "resource": resource}


@dataclass(frozen=True)
class CastaliaClientReadPolicy:
    presentation_pins: tuple[WalletPresentationPin, ...]
    policy_digest_sha256: str
    caller: tuple[str, str]

    def __post_init__(self):
        if (not self.presentation_pins or not isinstance(self.policy_digest_sha256, str)
                or len(self.policy_digest_sha256) != 64
                or any(c not in "0123456789abcdef" for c in self.policy_digest_sha256)
                or self.caller not in {caller for pin in self.presentation_pins
                                       for caller in pin.callers}):
            raise ValueError("invalid Castalia client-read policy")


class CastaliaClientReadVerifier:
    """Verify a fresh Wallet presentation over one exact browser read."""

    def __init__(self, policy: CastaliaClientReadPolicy,
                 *, clock=lambda: datetime.now().astimezone()):
        if Ed25519PublicKey is None:
            raise RuntimeError("install service-management[castalia-verifier]")
        self.policy, self.clock = policy, clock

    def verify(self, operation: str, resource: str, presentation: bytes) -> str:
        try:
            request_bytes = canonical(client_read_authorization(operation, resource)).encode("utf-8")
            if not isinstance(presentation, bytes) or not 0 < len(presentation) <= MAX_EVIDENCE_BODY:
                raise ValueError("invalid presentation size")
            value = json.loads(presentation.decode("utf-8"), object_pairs_hook=_pairs,
                parse_float=lambda _: (_ for _ in ()).throw(ValueError()),
                parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
            if canonical(value).encode("utf-8") != presentation:
                raise ValueError("client-read presentation is not canonical")
            value = _exact(value, {"schema", "presentation_request", "presentation"})
            if value["schema"] != PRESENTATION_SCHEMA:
                raise ValueError("unsupported client-read presentation")
            now = self.clock()
            if not isinstance(now, datetime) or now.tzinfo is None:
                raise ValueError("client-read clock must be timezone-aware")
            holder = verify_wallet_presentation(
                request_bytes, value["presentation_request"], value["presentation"],
                presentation_pins=self.policy.presentation_pins,
                policy_digest_sha256=self.policy.policy_digest_sha256,
                accepted_at=math.floor(now.timestamp()), expected_caller=self.policy.caller)
            # Intake ownership is the deterministic Zenith membership identity,
            # not a second key-shaped account. Receiver credentials are issued
            # only after verifying membership for this same holder key.
            membership_id = hashlib.sha256(
                MEMBERSHIP_ID_DOMAIN + bytes.fromhex(holder)).hexdigest()
            return "did.castalia.member." + membership_id
        except (KeyError, TypeError, ValueError, UnicodeError, OverflowError, json.JSONDecodeError):
            raise ServiceError("forbidden") from None
