"""Pinned native secS opener for ``service.intake-envelope.v1``.

The provider secret remains in secS canonical custody.  Service Management
sends only opaque envelope bytes to the fixed-purpose executable and accepts
one closed binary response frame containing the opened intake and exact
requester evidence.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
import re
import subprocess

from .client_intake import (
    MAX_EVIDENCE_BODY,
    MAX_INTAKE_BODY,
    MAX_REFERENCE_OBJECT,
    OpenedEnvelope,
    OpenedReferenceObject,
)
from .contracts import identifier
from .errors import ServiceError


OPENED_FRAME_MAGIC = b"SECSO01\0"
OPENED_REFERENCE_FRAME_MAGIC = b"SECSOR1\0"
MAX_ENCRYPTED_ENVELOPE = 328_032
MAX_REFERENCE_OBJECT_ENVELOPE = 787_203
MAX_OPENED_FRAME = 16 + MAX_INTAKE_BODY + MAX_EVIDENCE_BODY
MAX_OPENED_REFERENCE_FRAME = 8 + 3 + 32 + 8 + (3 * 128) + MAX_REFERENCE_OBJECT + MAX_EVIDENCE_BODY
SHA256 = re.compile(r"^[a-f0-9]{64}$", re.ASCII)


class NativeSecSIntakeOpener:
    """Use a content-pinned secS binary without exposing its recipient key."""

    def __init__(self, executable: str | Path, sha256: str, *, timeout: float = 5.0):
        self.executable = Path(executable)
        if (not self.executable.is_absolute() or not isinstance(sha256, str)
                or SHA256.fullmatch(sha256) is None or type(timeout) not in {int, float}
                or not 0 < timeout <= 30):
            raise ValueError("absolute secS executable, SHA-256 and bounded timeout required")
        self.sha256, self.timeout = sha256, timeout

    def _pinned(self) -> None:
        try:
            if (self.executable.is_symlink() or not self.executable.is_file()
                    or hashlib.sha256(self.executable.read_bytes()).hexdigest() != self.sha256):
                raise ServiceError("storage_unavailable")
        except OSError:
            raise ServiceError("storage_unavailable") from None

    @staticmethod
    def _failure(stderr: bytes) -> ServiceError:
        try:
            if not isinstance(stderr, bytes) or not 0 < len(stderr) <= 4_096:
                raise ValueError
            value = json.loads(stderr.decode("utf-8"))
            if (not isinstance(value, dict) or set(value) != {"error", "ok"}
                    or value["ok"] is not False or not isinstance(value["error"], str)):
                raise ValueError
            if value["error"] in {"envelope_rejected", "envelope_too_large", "input_failed"}:
                return ServiceError("invalid_command")
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError, TypeError):
            pass
        return ServiceError("storage_unavailable")

    def open(self, payload: bytes) -> OpenedEnvelope:
        if not isinstance(payload, bytes) or not 0 < len(payload) <= MAX_ENCRYPTED_ENVELOPE:
            raise ServiceError("invalid_command")
        self._pinned()
        try:
            result = subprocess.run(
                [str(self.executable), "open"],
                input=payload,
                capture_output=True,
                timeout=self.timeout,
                env={},
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            raise ServiceError("storage_unavailable") from None
        if result.returncode != 0:
            raise self._failure(result.stderr)
        if result.stderr or not 16 <= len(result.stdout) <= MAX_OPENED_FRAME:
            raise ServiceError("storage_unavailable")
        if result.stdout[:8] != OPENED_FRAME_MAGIC:
            raise ServiceError("storage_unavailable")
        intake_length = int.from_bytes(result.stdout[8:12], "big")
        evidence_length = int.from_bytes(result.stdout[12:16], "big")
        if (not 0 < intake_length <= MAX_INTAKE_BODY
                or not 0 < evidence_length <= MAX_EVIDENCE_BODY
                or len(result.stdout) != 16 + intake_length + evidence_length):
            raise ServiceError("storage_unavailable")
        return OpenedEnvelope(
            result.stdout[16:16 + intake_length],
            result.stdout[16 + intake_length:],
        )

    def open_reference(self, payload: bytes) -> OpenedReferenceObject:
        if not isinstance(payload, bytes) or not 0 < len(payload) <= MAX_REFERENCE_OBJECT_ENVELOPE:
            raise ServiceError("invalid_command")
        self._pinned()
        try:
            result = subprocess.run(
                [str(self.executable), "open-reference-object"], input=payload,
                capture_output=True, timeout=self.timeout, env={}, check=False)
        except (OSError, subprocess.SubprocessError):
            raise ServiceError("storage_unavailable") from None
        if result.returncode != 0:
            raise self._failure(result.stderr)
        raw = result.stdout
        if (result.stderr or not 51 <= len(raw) <= MAX_OPENED_REFERENCE_FRAME
                or raw[:8] != OPENED_REFERENCE_FRAME_MAGIC):
            raise ServiceError("storage_unavailable")
        lengths = raw[8:11]
        if any(length == 0 or length > 128 for length in lengths):
            raise ServiceError("storage_unavailable")
        content_hash = raw[11:43].hex()
        object_length = int.from_bytes(raw[43:47], "big")
        evidence_length = int.from_bytes(raw[47:51], "big")
        identifiers_end = 51 + sum(lengths)
        if (not 0 < object_length <= MAX_REFERENCE_OBJECT
                or not 0 < evidence_length <= MAX_EVIDENCE_BODY
                or len(raw) != identifiers_end + object_length + evidence_length):
            raise ServiceError("storage_unavailable")
        offset = 51
        values = []
        try:
            for length in lengths:
                value = raw[offset:offset + length].decode("ascii")
                if not identifier(value):
                    raise ValueError
                values.append(value); offset += length
        except (UnicodeDecodeError, ValueError):
            raise ServiceError("storage_unavailable") from None
        content = raw[offset:offset + object_length]
        evidence = raw[offset + object_length:]
        if hashlib.sha256(content).hexdigest() != content_hash:
            raise ServiceError("storage_unavailable")
        return OpenedReferenceObject(
            values[0], values[1], values[2], content_hash, content, evidence)
