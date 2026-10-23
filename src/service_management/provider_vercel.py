"""Fail-closed Vercel composition for the first encrypted provider path."""

from __future__ import annotations

import base64
import binascii
import json
import os
from collections.abc import Mapping
from datetime import UTC, datetime
from urllib.parse import urlsplit

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
from .client_contract import client_schema
from .contracts import canonical, identifier
from .provider_http import ProviderHttpApplication, ProviderHttpConfig

try:
    from jsonschema import Draft202012Validator, FormatChecker
except ImportError:  # pragma: no cover - deployment dependency check
    Draft202012Validator = FormatChecker = None

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


def _https_origin(value: str, name: str) -> str:
    parsed = urlsplit(value)
    if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
            or parsed.path or parsed.query or parsed.fragment or value.endswith("/")):
        raise ValueError(f"invalid {name}")
    return value


def _catalog_time(value: str) -> datetime:
    try:
        parsed = datetime.fromisoformat(value[:-1] + "+00:00")
    except (TypeError, ValueError):
        raise ValueError("invalid catalog recipient interval") from None
    canonical_time = parsed.astimezone(UTC).isoformat(timespec="milliseconds").replace(
        "+00:00", "Z")
    if not value.endswith("Z") or parsed.tzinfo is None or canonical_time != value:
        raise ValueError("invalid catalog recipient interval")
    return parsed


def _catalog(raw: str, *, public_base_url: str, origin: str, provider_id: str,
             recipient_key_id: str, recipient_public_key_hex: str, issuer: str,
             issuer_key_id: str, issuer_public_key_hex: str, audience: str,
             policy_digest: str, membership_issuer_origin: str,
             roots: tuple[ZenithMembershipRoot, ...]) -> dict:
    if Draft202012Validator is None or FormatChecker is None:
        raise RuntimeError("install service-management[catalog-validation]")
    try:
        value = json.loads(raw)
        if not isinstance(value, dict) or canonical(value) != raw:
            raise ValueError()
        Draft202012Validator(
            client_schema(4)["$defs"]["provider_catalog_v4"],
            format_checker=FormatChecker(),
        ).validate(value)
        expected_roots = [
            {"issuer_id": root.issuer_id, "key_id": root.key_id,
             "public_key_hex": root.public_key_hex}
            for root in roots
        ]
        not_before = _catalog_time(value["intake"]["envelope"]["not_before"])
        not_after = _catalog_time(value["intake"]["envelope"]["not_after"])
        if (value["provider"]["id"] != provider_id
                or not_before >= not_after
                or value["intake"]["endpoint"] != public_base_url + "/v1/client/requests"
                or value["intake"]["max_retention_seconds"] != 604800
                or value["intake"]["envelope"]["recipient_key_id"] != recipient_key_id
                or value["intake"]["envelope"]["recipient_public_key_hex"] != recipient_public_key_hex
                or value["reference_objects"]["endpoint"] != public_base_url + "/v1/client/reference-objects"
                or value["reference_objects"]["max_retention_seconds"] != 604800
                or any(value["reference_objects"]["envelope"][field]
                       != value["intake"]["envelope"][field]
                       for field in ("algorithm", "recipient_key_id",
                                     "recipient_public_key_hex", "not_before", "not_after"))
                or value["requester"]["membership"]["issuer_origin"] != membership_issuer_origin
                or value["requester"]["membership"]["roots"] != expected_roots
                or value["requester"]["credential"]["endpoint"] != public_base_url + "/v1/request-credential"
                or value["requester"]["credential"]["issuer"] != issuer
                or value["requester"]["credential"]["key_id"] != issuer_key_id
                or value["requester"]["credential"]["public_key_hex"] != issuer_public_key_hex
                or value["requester"]["credential"]["audience"] != audience
                or value["requester"]["credential"]["policy_digest_sha256"] != policy_digest
                or value["requester"]["credential"]["callers"] != [
                    {"kind": "browser", "id": origin}
                ]):
            raise ValueError()
        return value
    except Exception as error:
        if (error.__class__.__module__.startswith("jsonschema")
                or isinstance(error, (KeyError, TypeError, ValueError,
                                      json.JSONDecodeError))):
            raise ValueError("invalid ZENITH_PROVIDER_CATALOG_JSON") from None
        raise


def provider_application_from_environment(
        environment: Mapping[str, str] = os.environ) -> ProviderHttpApplication:
    """Compose only from explicit deployment configuration; create no keys."""
    origin = _required(environment, "ZENITH_ANIMA_ORIGIN", 512)
    # Validate the caller before constructing queue publishers. The public
    # gateway remains HTTPS; an explicitly configured browser caller may use
    # HTTP only on an exact numeric loopback origin for the local Anima pilot.
    ProviderHttpConfig(origin)
    provider_id = _required(environment, "ZENITH_PROVIDER_ID", 128)
    public_base_url = _https_origin(
        _required(environment, "ZENITH_PUBLIC_BASE_URL", 512), "ZENITH_PUBLIC_BASE_URL")
    recipient_key_id = _required(environment, "ZENITH_RECIPIENT_KEY_ID", 255)
    recipient_public_key = _required(environment, "ZENITH_RECIPIENT_PUBLIC_KEY_HEX", 64)
    issuer = _required(environment, "ZENITH_RECEIVER_ISSUER", 200)
    issuer_key_id = _required(environment, "ZENITH_RECEIVER_KEY_ID", 200)
    if not identifier(provider_id) or not identifier(issuer_key_id):
        raise ValueError("provider and receiver key IDs must use the published identifier profile")
    issuer_public_key = _required(environment, "ZENITH_RECEIVER_PUBLIC_KEY_HEX", 64)
    audience = _required(environment, "ZENITH_RECEIVER_AUDIENCE", 200)
    policy_digest = _required(environment, "ZENITH_REQUESTER_POLICY_DIGEST_SHA256", 64)
    roots = _membership_roots(_required(environment, "ZENITH_MEMBERSHIP_ROOTS_JSON", 16_384))
    membership_issuer_origin = _https_origin(
        _required(environment, "ZENITH_MEMBERSHIP_ISSUER_ORIGIN", 512),
        "ZENITH_MEMBERSHIP_ISSUER_ORIGIN")
    catalog = _catalog(
        _required(environment, "ZENITH_PROVIDER_CATALOG_JSON", 65_536),
        public_base_url=public_base_url, origin=origin, provider_id=provider_id,
        recipient_key_id=recipient_key_id, recipient_public_key_hex=recipient_public_key,
        issuer=issuer, issuer_key_id=issuer_key_id,
        issuer_public_key_hex=issuer_public_key, audience=audience,
        policy_digest=policy_digest, membership_issuer_origin=membership_issuer_origin,
        roots=roots)
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
        reference_gateway=reference_gateway, catalog=catalog)
