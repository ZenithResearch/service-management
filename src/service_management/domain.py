"""Storage-neutral service aggregates. No runtime, SQL, transport or auth types."""

from dataclasses import asdict, dataclass, replace
from typing import Literal

from .errors import ServiceError


@dataclass(frozen=True)
class ServiceRequest:
    id: str
    summary: str
    details: str
    state: Literal["intake", "qualified", "accepted", "rejected"]
    version: int
    created_at: str
    updated_at: str
    qualification: str | None = None
    acceptance: str | None = None
    rejection_reason: str | None = None
    case_id: str | None = None

    def __post_init__(self):
        if self.state not in {"intake", "qualified", "accepted", "rejected"} or type(self.version) is not int or self.version < 1:
            raise ValueError("invalid stored ServiceRequest")
        if self.state in {"qualified", "accepted"} and not self.qualification:
            raise ValueError("qualification evidence required")
        if self.state == "accepted" and not self.acceptance:
            raise ValueError("acceptance evidence required")
        if self.state == "rejected" and not self.rejection_reason:
            raise ValueError("rejection evidence required")
        if self.case_id is not None and self.state != "accepted":
            raise ValueError("only an accepted request may reference a Case")

    def as_dict(self) -> dict:
        return asdict(self)

    def qualify(self, qualification: str, now: str) -> "ServiceRequest":
        if self.state != "intake":
            raise ServiceError("invalid_transition")
        return replace(self, state="qualified", qualification=qualification, version=self.version + 1, updated_at=now)

    def accept(self, acceptance: str, now: str) -> "ServiceRequest":
        if self.state != "qualified":
            raise ServiceError("invalid_transition")
        return replace(self, state="accepted", acceptance=acceptance, version=self.version + 1, updated_at=now)

    def reject(self, reason: str, now: str) -> "ServiceRequest":
        if self.state not in {"intake", "qualified"}:
            raise ServiceError("invalid_transition")
        return replace(self, state="rejected", rejection_reason=reason, version=self.version + 1, updated_at=now)

    def convert(self, case_id: str, obligation: str, now: str) -> tuple["ServiceRequest", "Case"]:
        if self.state != "accepted":
            raise ServiceError("invalid_transition")
        if self.case_id is not None:
            raise ServiceError("already_converted")
        return (replace(self, case_id=case_id, version=self.version + 1, updated_at=now),
                Case(case_id, self.id, obligation, "open", 1, now, now))


@dataclass(frozen=True)
class Case:
    id: str
    service_request_id: str
    obligation: str
    state: Literal["open", "planned", "closed"]
    version: int
    created_at: str
    updated_at: str
    plan_scope: str | None = None
    closure_resolution: str | None = None
    current_plan_revision_id: str | None = None

    def __post_init__(self):
        if self.state not in {"open", "planned", "closed"} or type(self.version) is not int or self.version < 1:
            raise ValueError("invalid stored Case")
        if self.state in {"planned", "closed"} and not self.plan_scope:
            raise ValueError("initial plan required")
        if self.state == "closed" and not self.closure_resolution:
            raise ValueError("closure evidence required")

    def as_dict(self) -> dict:
        return asdict(self)

    def plan(self, scope: str, now: str) -> "Case":
        if self.state != "open":
            raise ServiceError("invalid_transition")
        return replace(self, state="planned", plan_scope=scope, version=self.version + 1, updated_at=now)

    def close(self, resolution: str, now: str) -> "Case":
        if self.state != "planned":
            raise ServiceError("invalid_transition")
        return replace(self, state="closed", closure_resolution=resolution, version=self.version + 1, updated_at=now)
