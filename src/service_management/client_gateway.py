"""Bounded public intake gateway core and Vercel Queue publisher.

The gateway verifies a requester presentation, seals only deterministic public
evidence plus the exact canonical intake for the provider, and publishes with a
stable queue idempotency key. It never owns ServiceRequest or Case state.
"""

from __future__ import annotations

import hashlib
import math
import re
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Callable, Protocol

from .client_intake import Intake, MAX_EVIDENCE_BODY, MAX_INTAKE_BODY
from .contracts import identifier
from .errors import ServiceError


# secS `service.intake-envelope.v1`: maximum public header plus bounded
# ciphertext. Keep this synchronized with libsec-core and the interop contract.
MAX_ENCRYPTED_ENVELOPE = 328_032
MAX_REFERENCE_OBJECT_ENVELOPE = 787_203
MAX_QUEUE_PAYLOAD = MAX_REFERENCE_OBJECT_ENVELOPE
QUEUE_NAME = re.compile(r"^[A-Za-z0-9_-]+$", re.ASCII)
SHA256 = re.compile(r"^[a-f0-9]{64}$", re.ASCII)
INTAKE_ENVELOPE_MAGIC = b"SECSI01\0"
REFERENCE_OBJECT_ENVELOPE_MAGIC = b"SECSR01\0"
MAX_ENVELOPE_CIPHERTEXT = 327_712
MAX_REFERENCE_OBJECT_CIPHERTEXT = 786_883


def _time(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("gateway clock must be timezone-aware")
    return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")


@dataclass(frozen=True)
class VerifiedGatewayRequester:
    subject: str
    durable_evidence: bytes

    def __post_init__(self):
        if (not identifier(self.subject) or not isinstance(self.durable_evidence, bytes)
                or not 0 < len(self.durable_evidence) <= MAX_EVIDENCE_BODY):
            raise ValueError("invalid gateway requester evidence")


class GatewayRequesterVerifier(Protocol):
    def verify(self, intake: Intake, body_digest: str, presentation: bytes,
               *, now: datetime, required_until: datetime) -> VerifiedGatewayRequester:
        """Return deterministic evidence that remains valid through queue expiry."""
        ...


class IntakeEnvelopeSealer(Protocol):
    def seal(self, intake: bytes, requester_evidence: bytes, *,
             provider_id: str, expires_at: str) -> bytes:
        """Seal for the pinned provider key using the reviewed secS profile."""
        ...


class QueuePublisher(Protocol):
    async def send(self, payload: bytes, *, idempotency_key: str, retention_seconds: int) -> str | None: ...


class UnknownGatewayOutcome(Exception):
    """The queue may have accepted the stable publish; retry exact input."""


@dataclass(frozen=True)
class EncryptedGatewaySubmission:
    """Safe public routing metadata for one already-encrypted intake."""

    request_id: str
    idempotency_key: str
    provider_id: str
    intake_digest: str

    def __post_init__(self):
        if (not identifier(self.request_id) or not identifier(self.idempotency_key)
                or not identifier(self.provider_id) or SHA256.fullmatch(self.intake_digest) is None):
            raise ValueError("invalid encrypted intake metadata")


@dataclass(frozen=True)
class EncryptedReferenceSubmission:
    """Safe public routing metadata for one encrypted original reference."""

    request_id: str
    idempotency_key: str
    provider_id: str
    artifact_id: str
    content_hash: str

    def __post_init__(self):
        if (not identifier(self.request_id) or not identifier(self.idempotency_key)
                or not identifier(self.provider_id) or not identifier(self.artifact_id)
                or SHA256.fullmatch(self.content_hash) is None):
            raise ValueError("invalid encrypted reference metadata")


class EncryptedGatewayRequesterVerifier(Protocol):
    def verify(self, submission: EncryptedGatewaySubmission, envelope_digest: str,
               presentation: bytes, *, now: datetime, required_until: datetime
               ) -> VerifiedGatewayRequester:
        """Verify membership and exact public submission metadata before publish."""
        ...


class EncryptedReferenceRequesterVerifier(Protocol):
    def verify(self, submission: EncryptedReferenceSubmission, envelope_digest: str,
               presentation: bytes, *, now: datetime, required_until: datetime
               ) -> VerifiedGatewayRequester:
        """Verify membership and exact reference metadata before publish."""
        ...


@dataclass(frozen=True)
class EncryptedGatewayConfig:
    provider_id: str
    recipient_key_id: str
    retention_seconds: int = 604_800

    def __post_init__(self):
        if not isinstance(self.recipient_key_id, str):
            raise ValueError("invalid encrypted gateway configuration")
        key = self.recipient_key_id.encode("ascii", errors="ignore")
        if (not identifier(self.provider_id) or not 1 <= len(key) <= 255
                or key.decode("ascii") != self.recipient_key_id
                or any(byte < 0x21 or byte > 0x7e for byte in key)
                or type(self.retention_seconds) is not int
                or not 60 <= self.retention_seconds <= 604_800):
            raise ValueError("invalid encrypted gateway configuration")


@dataclass(frozen=True)
class IntakeEnvelopeHeader:
    expires_at_ms: int
    recipient_key_id: str


def _parse_envelope_header(envelope: bytes, *, magic: bytes, maximum: int,
                           max_ciphertext: int) -> IntakeEnvelopeHeader:
    if not isinstance(envelope, bytes) or not 0 < len(envelope) <= maximum:
        raise ServiceError("invalid_command")
    if len(envelope) < 17 + 32 + 12 + 4 + 16 or envelope[:8] != magic:
        raise ServiceError("invalid_command")
    expires_at_ms = int.from_bytes(envelope[8:16], "big")
    key_length = envelope[16]
    key_end = 17 + key_length
    ciphertext_length_offset = key_end + 32 + 12
    if key_length == 0 or ciphertext_length_offset + 4 > len(envelope):
        raise ServiceError("invalid_command")
    try:
        key_id = envelope[17:key_end].decode("ascii")
    except UnicodeDecodeError:
        raise ServiceError("invalid_command") from None
    if any(byte < 0x21 or byte > 0x7e for byte in envelope[17:key_end]):
        raise ServiceError("invalid_command")
    ciphertext_length = int.from_bytes(
        envelope[ciphertext_length_offset:ciphertext_length_offset + 4], "big")
    if (not 16 <= ciphertext_length <= max_ciphertext
            or len(envelope) != ciphertext_length_offset + 4 + ciphertext_length):
        raise ServiceError("invalid_command")
    return IntakeEnvelopeHeader(expires_at_ms, key_id)


def parse_intake_envelope_header(envelope: bytes) -> IntakeEnvelopeHeader:
    """Validate the closed public intake frame without opening ciphertext."""
    return _parse_envelope_header(
        envelope, magic=INTAKE_ENVELOPE_MAGIC, maximum=MAX_ENCRYPTED_ENVELOPE,
        max_ciphertext=MAX_ENVELOPE_CIPHERTEXT)


def parse_reference_object_envelope_header(envelope: bytes) -> IntakeEnvelopeHeader:
    """Validate the closed public reference frame without opening ciphertext."""
    return _parse_envelope_header(
        envelope, magic=REFERENCE_OBJECT_ENVELOPE_MAGIC,
        maximum=MAX_REFERENCE_OBJECT_ENVELOPE,
        max_ciphertext=MAX_REFERENCE_OBJECT_CIPHERTEXT)


class EncryptedIntakeGateway:
    """Publish a browser-sealed secS envelope without receiving intake plaintext."""

    def __init__(self, config: EncryptedGatewayConfig,
                 verifier: EncryptedGatewayRequesterVerifier, publisher: QueuePublisher,
                 *, clock: Callable[[], datetime] = lambda: datetime.now(UTC)):
        self.config, self.verifier, self.publisher, self.clock = config, verifier, publisher, clock

    async def submit(self, envelope: bytes, *, submission: EncryptedGatewaySubmission,
                     requester_presentation: bytes) -> dict:
        if submission.provider_id != self.config.provider_id:
            raise ServiceError("invalid_command")
        header = parse_intake_envelope_header(envelope)
        if header.recipient_key_id != self.config.recipient_key_id:
            raise ServiceError("invalid_command")
        now = self.clock()
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise ServiceError("internal_error")
        now_ms = math.floor(now.timestamp() * 1000)
        remaining_ms = header.expires_at_ms - now_ms
        if not 60_000 <= remaining_ms <= self.config.retention_seconds * 1000:
            raise ServiceError("invalid_command")
        expires = datetime.fromtimestamp(header.expires_at_ms / 1000, tz=UTC)
        envelope_digest = hashlib.sha256(envelope).hexdigest()
        self.verifier.verify(submission, envelope_digest, requester_presentation,
                             now=now, required_until=expires)
        dedup = "seiv1." + hashlib.sha256(
            f"{submission.provider_id}\0{submission.request_id}\0{submission.idempotency_key}\0"
            f"{submission.intake_digest}".encode("utf-8")).hexdigest()
        retention_seconds = math.ceil(remaining_ms / 1000)
        try:
            message_id = await self.publisher.send(
                envelope, idempotency_key=dedup, retention_seconds=retention_seconds)
        except Exception as error:
            raise UnknownGatewayOutcome() from error
        receipt_source = message_id if isinstance(message_id, str) and message_id else dedup
        return {
            "schema": "service.intake-result.v1",
            "request_id": submission.request_id,
            "idempotency_key": submission.idempotency_key,
            "state": "pending",
            "transport_receipt": {
                "transport": "vercel-queue",
                "receipt_id": "vqs." + hashlib.sha256(receipt_source.encode("utf-8")).hexdigest(),
                "recorded_at": _time(now),
                "expires_at": _time(expires),
            },
            "service_request_id": None,
            "service_request_version": None,
            "status_url": f"/v1/client/requests/{submission.request_id}",
        }


class EncryptedReferenceGateway:
    """Publish one browser-sealed original reference without seeing plaintext."""

    def __init__(self, config: EncryptedGatewayConfig,
                 verifier: EncryptedReferenceRequesterVerifier, publisher: QueuePublisher,
                 *, clock: Callable[[], datetime] = lambda: datetime.now(UTC)):
        self.config, self.verifier, self.publisher, self.clock = config, verifier, publisher, clock

    async def submit(self, envelope: bytes, *, submission: EncryptedReferenceSubmission,
                     requester_presentation: bytes) -> dict:
        if submission.provider_id != self.config.provider_id:
            raise ServiceError("invalid_command")
        header = parse_reference_object_envelope_header(envelope)
        if header.recipient_key_id != self.config.recipient_key_id:
            raise ServiceError("invalid_command")
        now = self.clock()
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise ServiceError("internal_error")
        now_ms = math.floor(now.timestamp() * 1000)
        remaining_ms = header.expires_at_ms - now_ms
        if not 60_000 <= remaining_ms <= self.config.retention_seconds * 1000:
            raise ServiceError("invalid_command")
        expires = datetime.fromtimestamp(header.expires_at_ms / 1000, tz=UTC)
        envelope_digest = hashlib.sha256(envelope).hexdigest()
        self.verifier.verify(submission, envelope_digest, requester_presentation,
                             now=now, required_until=expires)
        dedup = "serv1." + hashlib.sha256(
            f"{submission.provider_id}\0{submission.request_id}\0{submission.idempotency_key}\0"
            f"{submission.artifact_id}\0{submission.content_hash}".encode("utf-8")).hexdigest()
        retention_seconds = math.ceil(remaining_ms / 1000)
        try:
            message_id = await self.publisher.send(
                envelope, idempotency_key=dedup, retention_seconds=retention_seconds)
        except Exception as error:
            raise UnknownGatewayOutcome() from error
        receipt_source = message_id if isinstance(message_id, str) and message_id else dedup
        return {
            "schema": "service.reference-object-result.v1",
            "request_id": submission.request_id,
            "idempotency_key": submission.idempotency_key,
            "artifact_id": submission.artifact_id,
            "content_hash": submission.content_hash,
            "state": "pending",
            "transport_receipt": {
                "transport": "vercel-queue",
                "receipt_id": "vqs." + hashlib.sha256(receipt_source.encode("utf-8")).hexdigest(),
                "recorded_at": _time(now),
                "expires_at": _time(expires),
            },
        }


@dataclass(frozen=True)
class GatewayConfig:
    provider_id: str
    retention_seconds: int = 604_800

    def __post_init__(self):
        if not identifier(self.provider_id) or type(self.retention_seconds) is not int or not 60 <= self.retention_seconds <= 604_800:
            raise ValueError("invalid provider gateway configuration")


class PublicIntakeGateway:
    def __init__(self, config: GatewayConfig, verifier: GatewayRequesterVerifier,
                 sealer: IntakeEnvelopeSealer, publisher: QueuePublisher,
                 *, clock: Callable[[], datetime] = lambda: datetime.now(UTC)):
        self.config, self.verifier, self.sealer, self.publisher = config, verifier, sealer, publisher
        self.clock = clock

    async def submit(self, body: bytes, *, idempotency_key: str,
                     requester_presentation: bytes) -> dict:
        if not isinstance(body, bytes) or not 0 < len(body) <= MAX_INTAKE_BODY:
            raise ServiceError("invalid_command")
        intake = Intake.parse(body)
        if (body != intake.raw_json.encode("utf-8")
                or idempotency_key != intake.idempotency_key
                or intake.provider_id != self.config.provider_id):
            raise ServiceError("invalid_command")
        now = self.clock()
        if not isinstance(now, datetime) or now.tzinfo is None:
            raise ServiceError("internal_error")
        expires = now + timedelta(seconds=self.config.retention_seconds)
        body_digest = hashlib.sha256(body).hexdigest()
        requester = self.verifier.verify(intake, body_digest, requester_presentation,
                                         now=now, required_until=expires)
        envelope = self.sealer.seal(body, requester.durable_evidence,
                                    provider_id=intake.provider_id, expires_at=_time(expires))
        if not isinstance(envelope, bytes) or not 0 < len(envelope) <= MAX_ENCRYPTED_ENVELOPE:
            raise ServiceError("internal_error")
        # Do not reveal the client key to the queue. Vercel hashes this key again
        # and deduplicates publishes during its retention window.
        dedup = "siv1." + hashlib.sha256(
            f"{intake.provider_id}\0{intake.idempotency_key}\0{body_digest}".encode("utf-8")).hexdigest()
        try:
            message_id = await self.publisher.send(
                envelope, idempotency_key=dedup, retention_seconds=self.config.retention_seconds)
        except Exception as error:
            raise UnknownGatewayOutcome() from error
        receipt_source = message_id if isinstance(message_id, str) and message_id else dedup
        return {
            "schema": "service.intake-result.v1",
            "request_id": intake.request_id,
            "idempotency_key": intake.idempotency_key,
            "state": "pending",
            "transport_receipt": {
                "transport": "vercel-queue",
                "receipt_id": "vqs." + hashlib.sha256(receipt_source.encode("utf-8")).hexdigest(),
                "recorded_at": _time(now),
                "expires_at": _time(expires),
            },
            "service_request_id": None,
            "service_request_version": None,
            "status_url": f"/v1/client/requests/{intake.request_id}",
        }


class VercelQueuePublisher:
    """Official Python SDK byte-topic publisher with deploymentless routing."""

    def __init__(self, queue, topic):
        self.queue, self.topic = queue, topic

    async def send(self, payload: bytes, *, idempotency_key: str, retention_seconds: int) -> str | None:
        if (not isinstance(payload, bytes) or not 0 < len(payload) <= MAX_QUEUE_PAYLOAD
                or not isinstance(idempotency_key, str) or not 1 <= len(idempotency_key) <= 256
                or type(retention_seconds) is not int or not 60 <= retention_seconds <= 604_800):
            raise ValueError("invalid queue publish")
        result = await self.queue.send(self.topic, payload, idempotency_key=idempotency_key,
                                       retention=retention_seconds)
        return None if result is None else str(result)

    @classmethod
    def from_sdk(cls, *, region: str, token: str | None, topic: str) -> "VercelQueuePublisher":
        if (not isinstance(region, str) or re.fullmatch(r"^[a-z0-9]+$", region, re.ASCII) is None
                or not isinstance(topic, str) or QUEUE_NAME.fullmatch(topic) is None):
            raise ValueError("invalid Vercel queue configuration")
        if token is not None and (not isinstance(token, str) or token.count(".") != 2 or len(token) > 16_384):
            raise ValueError("invalid Vercel OIDC token")
        try:
            from vercel.queue import ALL_DEPLOYMENTS, ByteBufferTransport, QueueClient, Topic
        except ImportError as error:
            raise RuntimeError("install the optional vercel-queue dependency") from error
        queue = QueueClient(region=region, token=token, deployment=ALL_DEPLOYMENTS)
        return cls(queue, Topic[bytes](topic, transport=ByteBufferTransport()))
