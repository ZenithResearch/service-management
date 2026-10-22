"""Fail-closed Vercel composition for the first encrypted provider path."""

from __future__ import annotations

import base64
import binascii
import json
import os
from collections.abc import Mapping

from .castalia_credential import (
    CredentialSigner,
    ReceiverCredentialConfig,
    ReceiverCredentialIssuer,
)
from .castalia_gateway import (
    CastaliaEncryptedGatewayVerifier,
    CastaliaEncryptedReferenceVerifier,
    CastaliaGatewayPolicy,
)
from .castalia_requester import (
    Ed25519PublicKey,
    WalletPresentationPin,
    ZenithMembershipRoot,
)
from .client_gateway import (
    EncryptedGatewayConfig,
    EncryptedIntakeGateway,
    EncryptedReferenceGateway,
    VercelQueuePublisher,
)
from .contracts import identifier
from .provider_http import ProviderHttpApplication, ProviderHttpConfig

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
except ImportError:  # pragma: no cover - deployment dependency check
    Ed25519PrivateKey = None


def _required(environment: Mapping[str, str], name: str, maximum: int = 16_384) -> str:
    value = environment.get(name)
    if not isinstance(value, str) or not 1 <= len(value) <= maximum or value != value.strip():
        raise ValueError(f"missing or invalid {name}")
    return value


def _seed(value: str) -> bytes:
    if "=" in value:
        raise ValueError("receiver signing seed must be unpadded base64url")
    try:
        raw = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except (ValueError, binascii.Error):
        raise ValueError("invalid receiver signing seed") from None
    if len(raw) != 32 or base64.urlsafe_b64encode(raw).decode().rstrip("=") != value:
        raise ValueError("invalid receiver signing seed")
    return raw


class Ed25519CredentialSigner(CredentialSigner):
    def __init__(self, seed: bytes, expected_public_key_hex: str):
        if Ed25519PrivateKey is None or Ed25519PublicKey is None:
            raise RuntimeError("install service-management[castalia-verifier]")
        if not isinstance(seed, bytes) or len(seed) != 32:
            raise ValueError("invalid receiver signing seed")
        self._key = Ed25519PrivateKey.from_private_bytes(seed)
        if self._key.public_key().public_bytes_raw().hex() != expected_public_key_hex:
            raise ValueError("receiver signing seed does not match configured public key")

    def sign(self, transcript: bytes) -> bytes:
        return self._key.sign(transcript)


def _membership_roots(raw: str) -> tuple[ZenithMembershipRoot, ...]:
    try:
        values = json.loads(raw)
        if not isinstance(values, list) or not 1 <= len(values) <= 16:
            raise ValueError()
        roots = tuple(ZenithMembershipRoot(value["issuer_id"], value["key_id"],
                                            value["public_key_hex"]) for value in values
                      if isinstance(value, dict) and set(value) == {"issuer_id", "key_id", "public_key_hex"})
        if len(roots) != len(values):
            raise ValueError()
        return roots
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        raise ValueError("invalid ZENITH_MEMBERSHIP_ROOTS_JSON") from None


def provider_application_from_environment(
        environment: Mapping[str, str] = os.environ) -> ProviderHttpApplication:
    """Compose only from explicit deployment configuration; create no keys."""
    origin = _required(environment, "ZENITH_ANIMA_ORIGIN", 512)
    if not origin.startswith("https://"):
        raise ValueError("ZENITH_ANIMA_ORIGIN must use HTTPS")
    provider_id = _required(environment, "ZENITH_PROVIDER_ID", 128)
    recipient_key_id = _required(environment, "ZENITH_RECIPIENT_KEY_ID", 255)
    issuer = _required(environment, "ZENITH_RECEIVER_ISSUER", 200)
    issuer_key_id = _required(environment, "ZENITH_RECEIVER_KEY_ID", 200)
    if not identifier(provider_id) or not identifier(issuer_key_id):
        raise ValueError("provider and receiver key IDs must use the published identifier profile")
    issuer_public_key = _required(environment, "ZENITH_RECEIVER_PUBLIC_KEY_HEX", 64)
    audience = _required(environment, "ZENITH_RECEIVER_AUDIENCE", 200)
    policy_digest = _required(environment, "ZENITH_REQUESTER_POLICY_DIGEST_SHA256", 64)
    roots = _membership_roots(_required(environment, "ZENITH_MEMBERSHIP_ROOTS_JSON", 16_384))
    signer = Ed25519CredentialSigner(
        _seed(_required(environment, "ZENITH_RECEIVER_SIGNING_SEED_B64", 64)), issuer_public_key)
    caller = ("browser", origin)
    pin = WalletPresentationPin(issuer, issuer_key_id, issuer_public_key, audience, (caller,))
    credential_issuer = ReceiverCredentialIssuer(
        ReceiverCredentialConfig(issuer, issuer_key_id, issuer_public_key, audience,
                                 (caller,), policy_digest), roots, signer)
    publisher = VercelQueuePublisher.from_sdk(
        region=_required(environment, "ZENITH_QUEUE_REGION", 32),
        token=None,
        topic=_required(environment, "ZENITH_QUEUE_TOPIC", 128))
    reference_publisher = VercelQueuePublisher.from_sdk(
        region=_required(environment, "ZENITH_QUEUE_REGION", 32),
        token=None,
        topic=_required(environment, "ZENITH_REFERENCE_QUEUE_TOPIC", 128))
    gateway_policy = CastaliaGatewayPolicy((pin,), policy_digest, recipient_key_id, caller)
    gateway = EncryptedIntakeGateway(
        EncryptedGatewayConfig(provider_id, recipient_key_id),
        CastaliaEncryptedGatewayVerifier(gateway_policy),
        publisher)
    reference_gateway = EncryptedReferenceGateway(
        EncryptedGatewayConfig(provider_id, recipient_key_id),
        CastaliaEncryptedReferenceVerifier(gateway_policy), reference_publisher)
    status_base_url = environment.get("ZENITH_STATUS_BASE_URL") or None
    return ProviderHttpApplication(
        ProviderHttpConfig(origin, status_base_url=status_base_url), credential_issuer, gateway,
        reference_gateway=reference_gateway)
