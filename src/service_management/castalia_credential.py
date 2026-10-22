"""Short-lived receiver credentials for Castalia Wallet Auth v2.

This core signs only a fixed request-credential transcript after verifying an
active Zenith membership credential.  The injected signer owns key custody; the
public endpoint never receives Service Management command authority.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Callable, Protocol
from urllib.parse import urlsplit

from .castalia_requester import Ed25519PublicKey, InvalidSignature, ZenithMembershipRoot, verify_zenith_membership
from .contracts import canonical
from .errors import ServiceError

ISSUANCE_SCHEMA = "service.castalia-credential-issuance.v1"
CREDENTIAL_SCHEMA = "castalia.request-credential.v1"
CREDENTIAL_SIGNATURE_DOMAIN = b"castalia.request-credential.v1/signature\0"
HEX_32 = re.compile(r"^[0-9a-f]{64}$", re.ASCII)
HEX_16 = re.compile(r"^[0-9a-f]{32}$", re.ASCII)
MAX_REQUEST = 65_536


class CredentialSigner(Protocol):
    def sign(self, transcript: bytes) -> bytes:
        """Return an Ed25519 signature without exporting private key material."""
        ...


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def _load(raw: bytes) -> dict:
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_REQUEST:
        raise ServiceError("invalid_command")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_pairs,
                           parse_float=lambda _: (_ for _ in ()).throw(ValueError()),
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if not isinstance(value, dict):
            raise ValueError()
        canonical(value).encode("utf-8")
        return value
    except (ValueError, UnicodeError, RecursionError):
        raise ServiceError("invalid_command") from None


def _exact(value, fields):
    if not isinstance(value, dict) or set(value) != set(fields):
        raise ServiceError("invalid_command")
    return value


def _label(value, maximum=200):
    if (not isinstance(value, str) or not 1 <= len(value) <= maximum
            or re.fullmatch(r"[\x20-\x7e]+", value, re.ASCII) is None or value != value.strip()):
        raise ValueError("invalid label")
    return value


def _caller(value) -> tuple[str, str]:
    value = _exact(value, {"kind", "id"})
    if value["kind"] not in {"browser", "terminal"}:
        raise ServiceError("invalid_command")
    caller_id = _label(value["id"])
    if value["kind"] == "browser":
        parsed = urlsplit(caller_id)
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment
                or parsed.scheme == "http" and parsed.hostname not in {"localhost", "127.0.0.1", "::1"}):
            raise ValueError("invalid browser caller")
        host = f"[{parsed.hostname}]" if ":" in parsed.hostname else parsed.hostname
        default = 443 if parsed.scheme == "https" else 80
        expected = f"{parsed.scheme}://{host}" + (f":{parsed.port}" if parsed.port and parsed.port != default else "")
        if caller_id != expected:
            raise ValueError("noncanonical browser caller")
    return value["kind"], caller_id


@dataclass(frozen=True)
class ReceiverCredentialConfig:
    issuer: str
    key_id: str
    public_key_hex: str
    audience: str
    callers: tuple[tuple[str, str], ...]
    policy_digest_sha256: str
    lifetime_seconds: int = 120

    def __post_init__(self):
        _label(self.issuer); _label(self.key_id); _label(self.audience)
        if (not self.callers or HEX_32.fullmatch(self.public_key_hex) is None
                or HEX_32.fullmatch(self.policy_digest_sha256) is None
                or type(self.lifetime_seconds) is not int or not 1 <= self.lifetime_seconds <= 120):
            raise ValueError("invalid receiver credential configuration")
        if len(set(self.callers)) != len(self.callers):
            raise ValueError("duplicate receiver caller")
        for kind, caller_id in self.callers:
            if _caller({"kind": kind, "id": caller_id}) != (kind, caller_id):
                raise ValueError("invalid receiver caller")


class ReceiverCredentialIssuer:
    """Issue one transient credential for a member and exact request digest."""

    def __init__(self, config: ReceiverCredentialConfig,
                 membership_roots: tuple[ZenithMembershipRoot, ...],
                 signer: CredentialSigner,
                 *, clock: Callable[[], datetime] = lambda: datetime.now(UTC)):
        if not membership_roots or not callable(getattr(signer, "sign", None)):
            raise ValueError("credential issuer requires trust roots and signer")
        if Ed25519PublicKey is None:
            raise RuntimeError("install service-management[castalia-verifier]")
        self.config, self.membership_roots, self.signer, self.clock = config, membership_roots, signer, clock

    def issue(self, raw: bytes) -> dict:
        value = _exact(_load(raw), {"schema", "membership", "request_digest_sha256",
                                    "disclosure_digest_sha256", "caller", "nonce"})
        if value["schema"] != ISSUANCE_SCHEMA:
            raise ServiceError("invalid_command")
        request_digest = value["request_digest_sha256"]
        disclosure_digest = value["disclosure_digest_sha256"]
        nonce = value["nonce"]
        if (not isinstance(request_digest, str) or HEX_32.fullmatch(request_digest) is None
                or not isinstance(disclosure_digest, str) or HEX_32.fullmatch(disclosure_digest) is None
                or not isinstance(nonce, str) or HEX_16.fullmatch(nonce) is None):
            raise ServiceError("invalid_command")
        caller = _caller(value["caller"])
        if caller not in self.config.callers:
            raise ServiceError("forbidden")
        try:
            _membership_id, holder_key = verify_zenith_membership(value["membership"], self.membership_roots)
        except (KeyError, TypeError, ValueError, UnicodeError, OverflowError):
            raise ServiceError("forbidden") from None
        now = self.clock()
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise ServiceError("internal_error")
        issued_at = int(now.timestamp())
        if issued_at < 0 or issued_at > 2**53 - 1 - self.config.lifetime_seconds:
            raise ServiceError("internal_error")
        claims = {
            "schema": CREDENTIAL_SCHEMA,
            "issuer": self.config.issuer,
            "key_id": self.config.key_id,
            "holder_public_key": holder_key,
            "audience": self.config.audience,
            "caller": {"kind": caller[0], "id": caller[1]},
            "request_digest_sha256": request_digest,
            "disclosure_digest_sha256": disclosure_digest,
            "policy_digest_sha256": self.config.policy_digest_sha256,
            "nonce": nonce,
            "issued_at": issued_at,
            "expires_at": issued_at + self.config.lifetime_seconds,
        }
        transcript = CREDENTIAL_SIGNATURE_DOMAIN + canonical(claims).encode("utf-8")
        signature = self.signer.sign(transcript)
        if not isinstance(signature, bytes) or len(signature) != 64:
            raise ServiceError("internal_error")
        try:
            Ed25519PublicKey.from_public_bytes(bytes.fromhex(self.config.public_key_hex)).verify(signature, transcript)
        except (InvalidSignature, ValueError):
            raise ServiceError("internal_error") from None
        return {"claims": claims, "signature": signature.hex()}
