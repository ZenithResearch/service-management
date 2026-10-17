"""Stable public failures; storage and authority details never become wire text."""

ERRORS = {
    "invalid_command": (400, "The command does not match service.command.v1."),
    "invalid_json": (400, "The request must contain bounded, unambiguous UTF-8 JSON."),
    "forbidden": (403, "The command is not authorized."),
    "not_found": (404, "The service resource does not exist."),
    "version_conflict": (409, "The expected resource version is stale."),
    "resource_conflict": (409, "The resource identity is already in use."),
    "idempotency_conflict": (409, "The request identity was committed with different content."),
    "invalid_transition": (409, "The command is not valid in the current lifecycle state."),
    "already_converted": (409, "The accepted request already has a Case."),
    "storage_unavailable": (503, "Canonical service storage is unavailable."),
    "internal_error": (500, "The command could not be completed."),
    "runtime_unavailable": (503, "The runtime boundary is unavailable."),
    "runtime_rejected": (409, "The runtime boundary rejected this operation."),
    "runtime_contract": (502, "The runtime response does not match the required contract."),
    "handoff_unresolved": (409, "The previous runtime handoff must be reconciled first."),
    "invalid_carry_forward": (409, "Selected output evidence cannot satisfy this replacement plan."),
    "invalid_plan_inputs": (400, "Inputs do not match the selected published process."),
    "projection_gap": (409, "The progress projection requires replay from retained runtime events."),
}


class ServiceError(Exception):
    def __init__(self, code: str, *, details: dict | None = None):
        self.code = code
        self.status, self.message = ERRORS[code]
        self.details = details or {}
        self.request_id = None
        super().__init__(self.message)

    def envelope(self, request_id: str | None = None) -> dict:
        return {
            "schema": "service.error.v1", "request_id": request_id or self.request_id,
            "error": {"code": self.code, "message": self.message, "details": self.details},
        }
