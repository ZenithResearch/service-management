"""Authorized bounded reads distinguish canonical service state from progress."""

from dataclasses import dataclass
import hashlib

from .contracts import Resource, canonical, identifier, load_json
from .delivery import public_handoff
from .errors import ServiceError

QUERY_KINDS = {"request.execution": "ServiceRequest", "case.summary": "Case", "case.plan-history": "Case"}


@dataclass(frozen=True)
class Query:
    request_id: str
    operation: str
    resource: Resource
    payload_json: str

    @property
    def payload(self):
        import json
        return json.loads(self.payload_json)

    @classmethod
    def parse(cls, raw):
        data = load_json(raw)
        if set(data) != {"schema", "request_id", "operation", "resource", "payload"} or data["schema"] != "service.query.v1" or not identifier(data["request_id"]):
            raise ServiceError("invalid_command")
        operation, resource, payload = data["operation"], data["resource"], data["payload"]
        if not isinstance(operation, str) or operation not in QUERY_KINDS or not isinstance(resource, dict) or set(resource) != {"kind", "id"} or resource["kind"] != QUERY_KINDS[operation] or not identifier(resource["id"]):
            raise ServiceError("invalid_command")
        if operation == "case.plan-history":
            if (not isinstance(payload, dict) or set(payload) != {"after_revision", "limit"}
                    or type(payload["after_revision"]) is not int or payload["after_revision"] < 0
                    or type(payload["limit"]) is not int or not 1 <= payload["limit"] <= 100):
                raise ServiceError("invalid_command")
        elif payload != {}: raise ServiceError("invalid_command")
        return cls(data["request_id"], operation, Resource(resource["kind"], resource["id"]), canonical(payload))

    def as_dict(self):
        return {"schema": "service.query.v1", "request_id": self.request_id, "operation": self.operation, "resource": self.resource.as_dict(), "payload": self.payload}

    @property
    def digest(self):
        return hashlib.sha256(("service.query.v1\0" + canonical(self.as_dict())).encode()).hexdigest()


def execute_query(tx, query, projection):
    if query.operation == "request.execution":
        request = tx.get_request(query.resource.id)
        if request is None: raise ServiceError("not_found")
        case = tx.get_case(request.case_id) if request.case_id else None
        handoff = tx.handoff_for_revision(case.current_plan_revision_id) if case and case.current_plan_revision_id else None
        state = handoff["state"] if handoff else "awaiting_plan" if request.state == "accepted" else "not_accepted"
        return {"request_id": request.id, "request_state": request.state, "request_version": request.version,
                "case_id": request.case_id, "execution_state": state, "handoff": public_handoff(handoff)}
    case = tx.get_case(query.resource.id)
    if case is None: raise ServiceError("not_found")
    if query.operation == "case.plan-history":
        payload = query.payload
        revisions = tx.revision_history(case.id, payload["after_revision"], payload["limit"])
        return {"case_id": case.id, "revisions": revisions, "next_revision": revisions[-1]["revision_number"] if revisions else payload["after_revision"]}
    handoff = tx.handoff_for_revision(case.current_plan_revision_id) if case.current_plan_revision_id else None
    summary = projection.run(handoff["run_id"]) if projection and handoff and handoff["run_id"] else None
    return {"canonical_service": {"case_id": case.id, "state": case.state, "version": case.version, "current_plan_revision_id": case.current_plan_revision_id},
            "execution_state": handoff["state"] if handoff else "awaiting_plan", "handoff": public_handoff(handoff),
            "derived_runtime": summary, "projection": projection.health() if projection else {"cursor": 0, "freshness": "unavailable", "observed_at": None, "age_seconds": None, "last_rebuild": None},
            "canonical_runtime": False, "redaction": {"applied": True, "omitted": ["inputs", "outputs", "credentials", "raw_event_data", "blocker_text"]}}
