"""Service-owned native receiver; uses the verification-only helper wire contract.

No runtime implementation import, signing/custody API or caller-supplied trust.
Operation/opcode/descriptor pins are explicit receiver configuration.
"""
from dataclasses import asdict, dataclass
import hashlib
import json
import math
from pathlib import Path
import re
import subprocess
from typing import Callable

from .authority import AUDIENCE, ReplayScope, VerifiedCall
from .contracts import Command, MAX_BODY, OPERATIONS, canonical, identifier
from .errors import ServiceError
from .queries import QUERY_KINDS, Query

MAX_RECEIVER_POLICY_BYTES = 262_144
MAX_NATIVE_PROOF_BYTES = 16_384
NATIVE_PACKET_FIXED_BYTES = 69
MAX_NATIVE_PACKET_BYTES = MAX_BODY + MAX_NATIVE_PROOF_BYTES + NATIVE_PACKET_FIXED_BYTES
MAX_SIGNED_CONTEXT_BYTES = 65_536
NATIVE_ENVELOPE_FIXED_BYTES = len(canonical({"schema": "service.secs-envelope.v1",
    "packet_hex": "", "signed_context_hex": ""}).encode())
MAX_AUTHORITY_BYTES = 2 * MAX_NATIVE_PACKET_BYTES + 2 * MAX_SIGNED_CONTEXT_BYTES + NATIVE_ENVELOPE_FIXED_BYTES
MAX_HELPER_METADATA_BYTES = 65_536
MAX_HELPER_INPUT_BYTES = 2 * MAX_NATIVE_PACKET_BYTES + 2 * MAX_BODY + 2 * MAX_SIGNED_CONTEXT_BYTES + MAX_HELPER_METADATA_BYTES
MAX_CONTEXT_SECONDS = 60
OPERATION_NAMES = frozenset(f"service.{op}.v1" for op in (*OPERATIONS, *QUERY_KINDS))


def _hex(value, length):
    return type(value) is str and re.fullmatch(f"[a-f0-9]{{{length}}}", value) is not None


def resource_for(action: Command | Query) -> str:
    return ("requests/" if action.resource.kind == "ServiceRequest" else "cases/") + action.resource.id


def operation_name(action: Command | Query) -> str:
    return f"service.{action.operation}.v1"


def _object(raw: bytes, maximum=MAX_AUTHORITY_BYTES) -> dict:
    def unique(items):
        value = {}
        for key, item in items:
            if key in value:
                raise ValueError("duplicate field")
            value[key] = item
        return value
    if type(raw) is not bytes or not 0 < len(raw) <= maximum:
        raise ValueError("bounded receiver object required")
    value = json.loads(raw.decode(), object_pairs_hook=unique,
                       parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite")))
    if type(value) is not dict:
        raise ValueError("receiver object required")
    canonical(value)
    return value


@dataclass(frozen=True)
class VerifierKey:
    key_id: str
    public_key_hex: str
    status: str = "active"
    production_authority: bool = True
    not_before: int | None = None
    not_after: int | None = None
    revoked_at: int | None = None

    def __post_init__(self):
        if (not identifier(self.key_id) or not _hex(self.public_key_hex, 64)
                or self.status not in {"active", "revoked", "expired"}
                or type(self.production_authority) is not bool):
            raise ValueError("invalid receiver verifier key")
        if any(value is not None and (type(value) is not int or value < 0)
               for value in (self.not_before, self.not_after, self.revoked_at)):
            raise ValueError("key windows use integer Unix seconds")


@dataclass(frozen=True)
class Descriptor:
    operation: str
    opcode: int
    fingerprint: str
    handler_id: str

    def __post_init__(self):
        if (self.operation not in OPERATION_NAMES or type(self.opcode) is not int
                or not 0 <= self.opcode <= 255 or not _hex(self.fingerprint, 64)
                or not identifier(self.handler_id)):
            raise ValueError("invalid service descriptor")


@dataclass(frozen=True)
class PermissionRule:
    subject_id: str
    operation: str
    resource: str
    effect: str
    not_before_ms: int
    not_after_ms: int
    resource_match: str = "exact"
    key_id: str | None = None
    active: bool = True

    def __post_init__(self):
        if (not identifier(self.subject_id) or (self.key_id is not None and not identifier(self.key_id))
                or self.operation not in OPERATION_NAMES or self.effect not in {"allow", "deny"}
                or type(self.resource) is not str or not 1 <= len(self.resource) <= 4096
                or any(ord(c) < 32 for c in self.resource) or "*" in self.resource
                or self.resource_match not in {"exact", "prefix"}
                or (self.resource_match == "prefix" and not self.resource.endswith("/"))
                or type(self.active) is not bool or type(self.not_before_ms) is not int
                or type(self.not_after_ms) is not int or not 0 <= self.not_before_ms < self.not_after_ms):
            raise ValueError("invalid bounded service permission")


@dataclass(frozen=True)
class ReceiverPolicy:
    audience: str
    keys: tuple[VerifierKey, ...]
    descriptors: tuple[Descriptor, ...]
    rules: tuple[PermissionRule, ...]
    revoked_subject_keys: frozenset[tuple[str, str]] = frozenset()

    def __post_init__(self):
        if (self.audience != AUDIENCE or type(self.keys) is not tuple or not 1 <= len(self.keys) <= 32
                or not all(isinstance(key, VerifierKey) for key in self.keys)
                or type(self.descriptors) is not tuple or not self.descriptors
                or not all(isinstance(item, Descriptor) for item in self.descriptors)
                or type(self.rules) is not tuple or len(self.rules) > 4096
                or not all(isinstance(rule, PermissionRule) for rule in self.rules)
                or type(self.revoked_subject_keys) is not frozenset
                or len({key.key_id for key in self.keys}) != len(self.keys)
                or len({d.operation for d in self.descriptors}) != len(self.descriptors)
                or len({d.opcode for d in self.descriptors}) != len(self.descriptors)):
            raise ValueError("receiver pins must be immutable, unique and service-scoped")
        for subject, key in self.revoked_subject_keys:
            if not identifier(subject) or not identifier(key):
                raise ValueError("invalid subject key revocation")

    def require_permission(self, subject, key, operation, resource, now_ms):
        if (subject, key) in self.revoked_subject_keys:
            raise ServiceError("forbidden")
        matching = [rule for rule in self.rules if rule.active and rule.subject_id == subject
                    and (rule.key_id is None or rule.key_id == key) and rule.operation == operation
                    and rule.not_before_ms <= now_ms < rule.not_after_ms
                    and (rule.resource == resource if rule.resource_match == "exact" else resource.startswith(rule.resource))]
        if not any(rule.effect == "allow" for rule in matching) or any(rule.effect == "deny" for rule in matching):
            raise ServiceError("forbidden")
        # A native helper may block. The application's fresh clock must reject
        # a result when any relevant policy boundary passes during verification.
        scoped = [rule for rule in self.rules if rule.active and rule.subject_id == subject
                  and (rule.key_id is None or rule.key_id == key) and rule.operation == operation
                  and (rule.resource == resource if rule.resource_match == "exact" else resource.startswith(rule.resource))]
        return min(boundary for rule in scoped for boundary in (rule.not_before_ms, rule.not_after_ms) if boundary > now_ms) / 1000


class FileReceiverPolicy:
    """Operator-selected read-only policy file; reload each verification."""
    def __init__(self, path: str | Path):
        self.path = Path(path)
        if not self.path.is_absolute():
            raise ValueError("receiver policy path must be absolute")

    def __call__(self) -> ReceiverPolicy:
        if self.path.is_symlink():
            raise ValueError("receiver policy may not be a symlink")
        with self.path.open("rb") as source:
            value = _object(source.read(MAX_RECEIVER_POLICY_BYTES + 1), MAX_RECEIVER_POLICY_BYTES)
        if set(value) != {"schema", "audience", "keys", "descriptors", "rules", "revoked_subject_keys"} or value["schema"] != "service.receiver-policy.v1":
            raise ValueError("unsupported receiver policy")
        for name in ("keys", "descriptors", "rules", "revoked_subject_keys"):
            if type(value[name]) is not list:
                raise ValueError("explicit receiver policy arrays required")
        revoked = value["revoked_subject_keys"]
        if any(type(pair) is not list or len(pair) != 2 for pair in revoked):
            raise ValueError("invalid revocation pair")
        return ReceiverPolicy(value["audience"], tuple(VerifierKey(**item) for item in value["keys"]),
                              tuple(Descriptor(**item) for item in value["descriptors"]),
                              tuple(PermissionRule(**item) for item in value["rules"]),
                              frozenset(tuple(pair) for pair in revoked))


def _bounded_helper_input(value: dict) -> bytes:
    """Service-owned framing ceilings; cryptographic verification stays native."""
    fields = {"schema", "packet_hex", "signed_context_hex", "request_hex", "audience", "now_seconds", "keys"}
    if (type(value) is not dict or set(value) != fields
            or value["schema"] != "process-runtime.secs-check-input.v1" or value["audience"] != AUDIENCE):
        raise ValueError("closed service helper input required")
    for field, maximum in (("packet_hex", MAX_NATIVE_PACKET_BYTES),
                           ("signed_context_hex", MAX_SIGNED_CONTEXT_BYTES), ("request_hex", MAX_BODY)):
        text = value[field]
        if (type(text) is not str or not text or len(text) > 2 * maximum or len(text) % 2
                or re.fullmatch("[a-f0-9]+", text) is None):
            raise ValueError("bounded canonical native bytes required")
    packet = bytes.fromhex(value["packet_hex"])
    if len(packet) < NATIVE_PACKET_FIXED_BYTES:
        raise ValueError("invalid native Packet framing")
    proof_length = int.from_bytes(packet[29:37], "little")
    if proof_length > MAX_NATIVE_PROOF_BYTES or len(packet) < NATIVE_PACKET_FIXED_BYTES + proof_length:
        raise ValueError("native proof exceeds Service profile")
    payload_length = int.from_bytes(packet[45 + proof_length:53 + proof_length], "little")
    if payload_length > MAX_BODY or len(packet) != NATIVE_PACKET_FIXED_BYTES + proof_length + payload_length:
        raise ValueError("invalid bounded native Packet payload")
    metadata = {**value, "packet_hex": "", "signed_context_hex": "", "request_hex": ""}
    if len(canonical(metadata).encode()) > MAX_HELPER_METADATA_BYTES:
        raise ValueError("bounded native helper metadata required")
    encoded = canonical(value).encode()
    if len(encoded) > MAX_HELPER_INPUT_BYTES:
        raise ValueError("bounded Service helper stdin required")
    return encoded


class NativeSecSHelper:
    """Pinned executable public protocol; subprocess cannot issue credentials."""
    def __init__(self, executable: str | Path, sha256: str):
        self.executable = Path(executable)
        if not self.executable.is_absolute() or not _hex(sha256, 64):
            raise ValueError("absolute native helper path and SHA-256 required")
        self.sha256 = sha256

    def verify(self, value: dict) -> dict:
        try:
            if self.executable.is_symlink() or hashlib.sha256(self.executable.read_bytes()).hexdigest() != self.sha256:
                raise ValueError("native helper pin mismatch")
            result = subprocess.run([str(self.executable)], input=_bounded_helper_input(value),
                                    capture_output=True, timeout=5, env={}, check=False)
            if result.returncode != 0 or result.stderr:
                raise ValueError("native verification rejected")
            output = _object(result.stdout, 131_072)
            if set(output) != {"schema", "context", "signer_key_id", "authenticator_kind"} or output["schema"] != "process-runtime.secs-check-output.v1":
                raise ValueError("native response mismatch")
            return output
        except (OSError, ValueError, TypeError, RecursionError, subprocess.SubprocessError):
            raise ServiceError("forbidden") from None


class SecSServiceAuthorityVerifier:
    def __init__(self, native_helper: NativeSecSHelper, load_policy: Callable[[], ReceiverPolicy]):
        self.native_helper, self.load_policy = native_helper, load_policy

    def verify(self, action: Command | Query, evidence: bytes | None, now: float) -> VerifiedCall:
        try:
            if not isinstance(action, (Command, Query)) or type(now) not in {int, float} or not math.isfinite(now) or now <= 0:
                raise ValueError("invalid receiver request")
            supplied = _object(evidence)
            if set(supplied) != {"schema", "packet_hex", "signed_context_hex"} or supplied["schema"] != "service.secs-envelope.v1":
                raise ValueError("unsupported service evidence")
            for field, maximum in (("packet_hex", MAX_NATIVE_PACKET_BYTES), ("signed_context_hex", MAX_SIGNED_CONTEXT_BYTES)):
                if type(supplied[field]) is not str or not supplied[field] or len(supplied[field]) > 2 * maximum or len(supplied[field]) % 2 or not re.fullmatch("[a-f0-9]+", supplied[field]):
                    raise ValueError("canonical native bytes required")
            try:
                policy = self.load_policy()
            except Exception:
                raise ServiceError("forbidden") from None
            if not isinstance(policy, ReceiverPolicy):
                raise ValueError("receiver policy unavailable")
            output = self.native_helper.verify({"schema": "process-runtime.secs-check-input.v1",
                "packet_hex": supplied["packet_hex"], "signed_context_hex": supplied["signed_context_hex"],
                "request_hex": canonical(action.as_dict()).encode().hex(), "audience": AUDIENCE,
                "now_seconds": int(now), "keys": [asdict(key) for key in policy.keys]})
            c = output["context"]
            name, resource = operation_name(action), resource_for(action)
            descriptor = next((item for item in policy.descriptors if item.operation == name), None)
            if (output["authenticator_kind"] != "ed25519_node_and_verifier"
                    or type(c["schema_version"]) is not int or c["schema_version"] != 4
                    or c["audience"] != AUDIENCE or c["operation"] != name or c["resource"] != resource
                    or descriptor is None or c["opcode"] != descriptor.opcode
                    or c["descriptor_fingerprint"] not in (
                        descriptor.fingerprint, "descriptor:sha256:" + descriptor.fingerprint)
                    or c["handler_id"] != descriptor.handler_id
                    or c["replay_scope"] != "session:opcode:nonce"
                    or type(c["issued_at"]) is not int or type(c["expires_at"]) is not int
                    or not c["issued_at"] <= now < c["expires_at"]
                    or not 0 < c["expires_at"] - c["issued_at"] <= MAX_CONTEXT_SECONDS):
                raise ValueError("service descriptor/context mismatch")
            # Pin/policy changes during native verification require a new check.
            try:
                unchanged = self.load_policy() == policy
            except Exception:
                raise ServiceError("forbidden") from None
            if not unchanged:
                raise ValueError("receiver policy changed during verification")
            subject, key = c["subject"]["subject_id"], c["subject"]["key_id"]
            if not identifier(subject) or not identifier(key):
                raise ValueError("invalid native subject")
            for field, length in (("session_id", 16), ("nonce", 12)):
                if type(c[field]) is not list or len(c[field]) != length or any(type(item) is not int or not 0 <= item <= 255 for item in c[field]):
                    raise ValueError("invalid native replay bytes")
            if type(c["opcode"]) is not int:
                raise ValueError("invalid native opcode")
            replay = ReplayScope(bytes(c["session_id"]).hex(), c["opcode"], bytes(c["nonce"]).hex())
            policy_expiry = policy.require_permission(subject, key, name, resource, int(now * 1000))
            signer = next((key for key in policy.keys if key.key_id == output["signer_key_id"]), None)
            if signer is None:
                raise ValueError("unconfigured verifier")
            key_expiry = min(boundary for boundary in (c["expires_at"], signer.not_after, signer.revoked_at) if boundary is not None)
            return VerifiedCall(subject, AUDIENCE, action.digest, min(c["expires_at"], policy_expiry, key_expiry), "verified_call", replay)
        except ServiceError:
            raise
        except (OSError, ValueError, TypeError, KeyError, OverflowError, RecursionError):
            raise ServiceError("forbidden") from None
