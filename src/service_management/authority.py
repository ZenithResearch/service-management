"""Receiver authority port; no Matrix, Hermes, bearer or caller-key authority."""

from dataclasses import dataclass
from math import isfinite
from typing import Protocol

from .contracts import Command, identifier
from .errors import ServiceError

AUDIENCE = "service-management"


@dataclass(frozen=True)
class ReplayScope:
    session_id: str
    opcode: int
    nonce: str

    def __post_init__(self):
        import re
        if (type(self.session_id) is not str or re.fullmatch("[a-f0-9]{32}", self.session_id) is None
                or type(self.nonce) is not str or re.fullmatch("[a-f0-9]{24}", self.nonce) is None
                or type(self.opcode) is not int or not 0 <= self.opcode <= 255):
            raise ValueError("invalid native replay binding")


@dataclass(frozen=True)
class VerifiedCall:
    subject: str
    audience: str
    command_digest: str
    expires_at: float
    mode: str
    replay: ReplayScope | None = None


class AuthorityVerifier(Protocol):
    def verify(self, command: Command, evidence: bytes | None, now: float) -> VerifiedCall:
        """Verify authority for this exact command; reject without side effects.

        Each invocation must reload current receiver-local permissions and
        revocation, and validate replay policy before returning this internal
        value. Verification must allow rechecking the same exact intent without
        consuming its replay identity: Service admits native replay through its
        transaction port with state/result commits. Plan preparation verifies again after
        external reads, inside the final writer transaction. Exact successful
        command replay is handled by the application's retained result. This
        value is never decoded from caller JSON or treated as a signature itself.
        """
        ...


class DenyAllVerifier:
    def verify(self, command: Command, evidence: bytes | None, now: float) -> VerifiedCall:
        raise ServiceError("forbidden")


class LocalDevUntrustedVerifier:
    """Explicit test/development adapter, not identity or production authority."""
    def __init__(self, subject: str = "local-dev-untrusted"):
        if not identifier(subject):
            raise ValueError("invalid local development subject")
        self.subject = subject

    def verify(self, command: Command, evidence: bytes | None, now: float) -> VerifiedCall:
        if evidence is not None:
            raise ServiceError("forbidden")
        return VerifiedCall(self.subject, AUDIENCE, command.digest, now + 60, "local_dev_untrusted")


def authorize(call: VerifiedCall, command: Command, now: float, *, allow_local_dev: bool) -> None:
    if (not isinstance(call, VerifiedCall) or not identifier(call.subject)
            or call.audience != AUDIENCE or call.command_digest != command.digest
            or type(call.expires_at) not in {int, float} or not isfinite(call.expires_at)
            or call.expires_at <= now):
        raise ServiceError("forbidden")
    if call.replay is not None and not isinstance(call.replay, ReplayScope):
        raise ServiceError("forbidden")
    if not isinstance(call.mode, str) or call.mode not in {"verified_call", "local_dev_untrusted"} or (call.mode == "local_dev_untrusted" and not allow_local_dev):
        raise ServiceError("forbidden")
