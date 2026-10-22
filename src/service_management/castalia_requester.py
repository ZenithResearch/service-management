"""Independent Castalia membership and exact-request verification.

The encrypted envelope carries a public Zenith membership v3 credential plus a
Castalia Wallet Auth v2 presentation over the exact canonical intake bytes.
Transport time is used only to evaluate short-lived proof freshness; it cannot
establish membership or Service Management command authority.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
import struct
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

from .client_intake import Intake, TransportReceipt, VerifiedRequester
from .contracts import canonical
from .errors import ServiceError

try:
    from cryptography.exceptions import InvalidSignature
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
except ImportError:  # pragma: no cover - exercised by installed-dependency qualification
    Ed25519PublicKey = None
    InvalidSignature = Exception

EVIDENCE_SCHEMA = "service.castalia-requester-evidence.v1"
MEMBERSHIP_SCHEMA = "castalia.zenith-membership-credential.v3"
REQUEST_SCHEMA = "castalia.credential-presentation-request.v2"
CREDENTIAL_SCHEMA = "castalia.request-credential.v1"
PRESENTATION_SCHEMA = "castalia.credential-presentation.v2"
MEMBERSHIP_ID_DOMAIN = b"castalia/zenith-membership-id/v3\0"
MEMBERSHIP_CREDENTIAL_DOMAIN = b"castalia/zenith-membership-credential/v3\0"
CREDENTIAL_SIGNATURE_DOMAIN = b"castalia.request-credential.v1/signature\0"
PRESENTATION_SIGNATURE_DOMAIN = b"castalia.credential-presentation.v2/signature\0"
HEX_32 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
HEX_16 = re.compile(r"^[0-9a-f]{32}$", re.ASCII)
HEX_64 = re.compile(r"^[0-9a-f]{128}$", re.ASCII)
MEMBERSHIP_IDENTIFIER = re.compile(r"^[a-z0-9](?:[a-z0-9.-]{0,62}[a-z0-9])?$", re.ASCII)
CONTROL = re.compile(r"[\x00-\x1f\x7f-\x9f\u061c\u200e\u200f\u202a-\u202e\u2066-\u2069]")
SAFE_INTEGER = 2**53 - 1
MAX_EVIDENCE = 262_144


def _exact(value: Any, fields: set[str]) -> dict:
    if not isinstance(value, dict) or set(value) != fields:
        raise ValueError("invalid shape")
    return value


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _number(_value):
    raise ValueError("noninteger number")


def _load(raw: bytes) -> dict:
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_EVIDENCE:
        raise ValueError("invalid evidence size")
    value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                       parse_float=_number, parse_constant=_number)
    if not isinstance(value, dict):
        raise ValueError("invalid evidence")
    canonical(value).encode("utf-8")  # Reject invalid Unicode before verification.
    return value


def _hex(value: Any, pattern: re.Pattern[str]) -> bytes:
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ValueError("invalid hex")
    return bytes.fromhex(value)


def _base64url64(value: Any) -> bytes:
    if not isinstance(value, str) or len(value) != 86 or re.fullmatch(r"[A-Za-z0-9_-]{86}", value) is None:
        raise ValueError("invalid base64url signature")
    decoded = base64.urlsafe_b64decode(value + "==")
    if len(decoded) != 64 or base64.urlsafe_b64encode(decoded).decode().rstrip("=") != value:
        raise ValueError("noncanonical base64url signature")
    return decoded


def _text(value: Any, maximum: int, *, ascii_only: bool = False) -> str:
    if not isinstance(value, str) or not 1 <= len(value.encode("utf-8")) <= maximum or CONTROL.search(value):
        raise ValueError("invalid text")
    if ascii_only and re.fullmatch(r"[\x20-\x7e]+", value, re.ASCII) is None:
        raise ValueError("invalid ASCII text")
    return value


def _caller(value: Any) -> tuple[str, str]:
    value = _exact(value, {"kind", "id"})
    kind, caller_id = value["kind"], _text(value["id"], 200, ascii_only=True)
    if kind not in {"browser", "terminal"}:
        raise ValueError("invalid caller")
    if kind == "browser":
        parsed = urlsplit(caller_id)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise ValueError("invalid browser origin")
        if parsed.path or parsed.query or parsed.fragment:
            raise ValueError("invalid browser origin")
        if parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}:
            raise ValueError("insecure browser origin")
        host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
        default = 443 if parsed.scheme == "https" else 80
        expected = f"{parsed.scheme}://{host}" + (f":{parsed.port}" if parsed.port and parsed.port != default else "")
        if caller_id != expected:
            raise ValueError("noncanonical browser origin")
    return kind, caller_id


def _unix(value: Any) -> int:
    if type(value) is not int or not 0 <= value <= SAFE_INTEGER:
        raise ValueError("invalid Unix time")
    return value


def _receipt_time(receipt: TransportReceipt) -> int:
    receipt.validate()
    parsed = datetime.fromisoformat(receipt.recorded_at[:-1] + "+00:00")
    return int(parsed.timestamp())


def _verify(public_key: bytes, signature: bytes, message: bytes) -> None:
    try:
        Ed25519PublicKey.from_public_bytes(public_key).verify(signature, message)
    except (InvalidSignature, ValueError):
        raise ValueError("invalid signature") from None


def _frame(value: str) -> bytes:
    encoded = value.encode("utf-8")
    return struct.pack("<I", len(encoded)) + encoded


@dataclass(frozen=True)
class ZenithMembershipRoot:
    issuer_id: str
    key_id: str
    public_key_hex: str

    def __post_init__(self):
        if (MEMBERSHIP_IDENTIFIER.fullmatch(self.issuer_id) is None
                or MEMBERSHIP_IDENTIFIER.fullmatch(self.key_id) is None):
            raise ValueError("invalid Zenith membership root")
        _hex(self.public_key_hex, HEX_32)


@dataclass(frozen=True)
class WalletPresentationPin:
    issuer: str
    key_id: str
    public_key_hex: str
    audience: str
    callers: tuple[tuple[str, str], ...]

    def __post_init__(self):
        _text(self.issuer, 200, ascii_only=True)
        _text(self.key_id, 200, ascii_only=True)
        _text(self.audience, 200, ascii_only=True)
        _hex(self.public_key_hex, HEX_32)
        if not self.callers:
            raise ValueError("wallet presentation pin needs callers")
        for kind, caller_id in self.callers:
            if _caller({"kind": kind, "id": caller_id}) != (kind, caller_id):
                raise ValueError("invalid caller pin")


@dataclass(frozen=True)
class CastaliaRequesterPolicy:
    membership_roots: tuple[ZenithMembershipRoot, ...]
    presentation_pins: tuple[WalletPresentationPin, ...]
    policy_digest_sha256: str
    trusted_transports: tuple[str, ...] = ("vercel-queue",)

    def __post_init__(self):
        if not self.membership_roots or not self.presentation_pins or not self.trusted_transports:
            raise ValueError("requester policy cannot be empty")
        _hex(self.policy_digest_sha256, HEX_32)
        if len({(root.issuer_id, root.key_id) for root in self.membership_roots}) != len(self.membership_roots):
            raise ValueError("duplicate membership root")
        if len({(pin.issuer, pin.key_id, pin.audience) for pin in self.presentation_pins}) != len(self.presentation_pins):
            raise ValueError("duplicate presentation pin")
        for transport in self.trusted_transports:
            _text(transport, 64, ascii_only=True)


def verify_zenith_membership(value: Any,
                             roots: tuple[ZenithMembershipRoot, ...]) -> tuple[str, str]:
    """Verify one active v3 credential and return membership/owner hex IDs."""
    value = _exact(value, {"schema", "version", "membershipId", "ownerPublicKey", "status",
                           "issuerId", "issuerKeyId", "signatureSuite", "issuerSignature"})
    if (value["schema"] != MEMBERSHIP_SCHEMA or value["version"] != 3
            or value["status"] != "active" or value["signatureSuite"] != "Ed25519"):
        raise ValueError("invalid membership")
    membership_id = _hex(value["membershipId"], HEX_32)
    owner_key = _hex(value["ownerPublicKey"], HEX_32)
    issuer_id = _text(value["issuerId"], 64, ascii_only=True)
    issuer_key_id = _text(value["issuerKeyId"], 64, ascii_only=True)
    if MEMBERSHIP_IDENTIFIER.fullmatch(issuer_id) is None or MEMBERSHIP_IDENTIFIER.fullmatch(issuer_key_id) is None:
        raise ValueError("invalid membership issuer")
    if hashlib.sha256(MEMBERSHIP_ID_DOMAIN + owner_key).digest() != membership_id:
        raise ValueError("invalid membership ID")
    root = next((candidate for candidate in roots
                 if candidate.issuer_id == issuer_id and candidate.key_id == issuer_key_id), None)
    if root is None:
        raise ValueError("untrusted membership issuer")
    transcript = (MEMBERSHIP_CREDENTIAL_DOMAIN + struct.pack("<Q", 3) + membership_id + owner_key
                  + _frame("active") + _frame(issuer_id) + _frame(issuer_key_id) + _frame("ed25519"))
    _verify(bytes.fromhex(root.public_key_hex), _base64url64(value["issuerSignature"]), transcript)
    return membership_id.hex(), owner_key.hex()


def verify_wallet_presentation(request_bytes: bytes, request: Any, presentation: Any, *,
                               presentation_pins: tuple[WalletPresentationPin, ...],
                               policy_digest_sha256: str, accepted_at: int,
                               expected_holder_key: str | None = None,
                               expected_caller: tuple[str, str] | None = None) -> str:
    """Verify Wallet Auth v2 over exact bytes and return the holder public key."""
    if (not isinstance(request_bytes, bytes) or not 0 < len(request_bytes) <= MAX_EVIDENCE
            or type(accepted_at) is not int or not 0 <= accepted_at <= SAFE_INTEGER
            or HEX_32.fullmatch(policy_digest_sha256) is None or not presentation_pins):
        raise ValueError("invalid presentation verification input")
    request = _exact(request, {"schema", "request_bytes_base64", "disclosure", "credential"})
    if request["schema"] != REQUEST_SCHEMA:
        raise ValueError("invalid presentation request")
    encoded = request["request_bytes_base64"]
    if not isinstance(encoded, str) or len(encoded) > 174_764:
        raise ValueError("invalid request bytes")
    try:
        decoded = base64.b64decode(encoded, validate=True)
    except (ValueError, binascii.Error):
        raise ValueError("invalid request bytes") from None
    if base64.b64encode(decoded).decode() != encoded or decoded != request_bytes:
        raise ValueError("request bytes do not match")

    disclosure = _exact(request["disclosure"], {"title", "statements"})
    _text(disclosure["title"], 160)
    statements = disclosure["statements"]
    if not isinstance(statements, list) or not 1 <= len(statements) <= 144:
        raise ValueError("invalid disclosure")
    for statement in statements:
        _text(statement, 512)

    credential = _exact(request["credential"], {"claims", "signature"})
    claims = _exact(credential["claims"], {"schema", "issuer", "key_id", "holder_public_key", "audience",
                                            "caller", "request_digest_sha256", "disclosure_digest_sha256",
                                            "policy_digest_sha256", "nonce", "issued_at", "expires_at"})
    if claims["schema"] != CREDENTIAL_SCHEMA:
        raise ValueError("invalid request credential")
    issuer = _text(claims["issuer"], 200, ascii_only=True)
    key_id = _text(claims["key_id"], 200, ascii_only=True)
    audience = _text(claims["audience"], 200, ascii_only=True)
    caller = _caller(claims["caller"])
    if expected_caller is not None and caller != expected_caller:
        raise ValueError("caller mismatch")
    holder = _hex(claims["holder_public_key"], HEX_32).hex()
    if expected_holder_key is not None and holder != expected_holder_key:
        raise ValueError("membership holder mismatch")
    request_digest = _hex(claims["request_digest_sha256"], HEX_32).hex()
    disclosure_digest = _hex(claims["disclosure_digest_sha256"], HEX_32).hex()
    if request_digest != hashlib.sha256(request_bytes).hexdigest():
        raise ValueError("request digest mismatch")
    if disclosure_digest != hashlib.sha256(canonical(disclosure).encode("utf-8")).hexdigest():
        raise ValueError("disclosure digest mismatch")
    if claims["policy_digest_sha256"] != policy_digest_sha256:
        raise ValueError("policy mismatch")
    _hex(claims["nonce"], HEX_16)
    credential_issued, credential_expires = _unix(claims["issued_at"]), _unix(claims["expires_at"])
    if (credential_expires - credential_issued > 120
            or not credential_issued <= accepted_at < credential_expires):
        raise ValueError("request credential not fresh at receipt")
    pin = next((candidate for candidate in presentation_pins
                if candidate.issuer == issuer and candidate.key_id == key_id
                and candidate.audience == audience and caller in candidate.callers), None)
    if pin is None:
        raise ValueError("untrusted request issuer")
    _verify(bytes.fromhex(pin.public_key_hex), _hex(credential["signature"], HEX_64),
            CREDENTIAL_SIGNATURE_DOMAIN + canonical(claims).encode("utf-8"))

    presentation = _exact(presentation, {"schema", "holder_public_key", "issuer", "key_id", "audience", "caller",
                                              "request_digest_sha256", "credential_digest_sha256",
                                              "disclosure_digest_sha256", "nonce", "issued_at", "expires_at", "signature"})
    if presentation["schema"] != PRESENTATION_SCHEMA:
        raise ValueError("invalid presentation")
    for field, expected in (("holder_public_key", holder), ("issuer", issuer), ("key_id", key_id),
                            ("audience", audience), ("request_digest_sha256", request_digest),
                            ("disclosure_digest_sha256", disclosure_digest)):
        if presentation[field] != expected:
            raise ValueError("presentation binding mismatch")
    if _caller(presentation["caller"]) != caller:
        raise ValueError("presentation caller mismatch")
    if presentation["credential_digest_sha256"] != hashlib.sha256(canonical(credential).encode("utf-8")).hexdigest():
        raise ValueError("credential digest mismatch")
    _hex(presentation["nonce"], HEX_16)
    presentation_issued = _unix(presentation["issued_at"])
    presentation_expires = _unix(presentation["expires_at"])
    if (presentation_expires - presentation_issued > 60
            or presentation_issued < credential_issued or presentation_expires > credential_expires
            or not presentation_issued <= accepted_at < presentation_expires):
        raise ValueError("presentation not fresh at receipt")
    unsigned = dict(presentation)
    signature = _hex(unsigned.pop("signature"), HEX_64)
    _verify(bytes.fromhex(holder), signature,
            PRESENTATION_SIGNATURE_DOMAIN + canonical(unsigned).encode("utf-8"))
    return holder


class CastaliaRequesterVerifier:
    """Verify public membership and Wallet Auth consent without minting authority."""

    def __init__(self, policy: CastaliaRequesterPolicy):
        if Ed25519PublicKey is None:
            raise RuntimeError("install service-management[castalia-verifier]")
        self.policy = policy

    def verify(self, intake: Intake, evidence: bytes, receipt: TransportReceipt) -> VerifiedRequester:
        try:
            if receipt.transport not in self.policy.trusted_transports:
                raise ValueError("untrusted transport time")
            accepted_at = _receipt_time(receipt)
            value = _exact(_load(evidence), {"schema", "membership", "presentation_request", "presentation"})
            if value["schema"] != EVIDENCE_SCHEMA:
                raise ValueError("unsupported evidence")
            membership_id, owner_key = self._membership(value["membership"])
            self._presentation(intake, value["presentation_request"], value["presentation"], owner_key, accepted_at)
            return VerifiedRequester(f"did.castalia.member.{membership_id}", membership_id)
        except (KeyError, TypeError, ValueError, UnicodeError, OverflowError, json.JSONDecodeError):
            raise ServiceError("forbidden") from None

    def _membership(self, value: Any) -> tuple[str, str]:
        return verify_zenith_membership(value, self.policy.membership_roots)

    def _presentation(self, intake: Intake, request: Any, presentation: Any,
                      owner_key: str, accepted_at: int) -> None:
        verify_wallet_presentation(
            intake.raw_json.encode("utf-8"), request, presentation,
            presentation_pins=self.policy.presentation_pins,
            policy_digest_sha256=self.policy.policy_digest_sha256,
            accepted_at=accepted_at, expected_holder_key=owner_key)
