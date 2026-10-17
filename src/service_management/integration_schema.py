"""Published service-owned integration shapes; runtime remains a separate owner."""

from .contracts import _closed, IDENTIFIER

ID = {"type": "string", "pattern": IDENTIFIER}
RID = {"type": "string", "pattern": r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$"}
HASH = {"type": "string", "pattern": "^[a-f0-9]{64}$"}
TEXT = {"type": "string", "minLength": 1, "maxLength": 4096}
PIN = _closed({"process_id": RID, "process_version": RID, "compilation_hash": HASH})
SELECTION = _closed({"run_id": RID, "step_id": RID, "attempt_id": RID, "output_name": RID, "target_input": RID, "expected_output_digest": HASH})
VALUES = {"type": "object", "maxProperties": 128, "propertyNames": RID}


def plan_payload_schema(operation):
    fields = {"revision_id": ID, "reason": TEXT, "pin": PIN, "inputs": VALUES,
              "carry_forward": {"type": "array", "maxItems": 128 if operation == "case.plan.revise" else 0, "items": SELECTION}}
    if operation == "case.plan.revise": fields["superseded_run_id"] = RID
    return _closed(fields)


def public_handoff_schema():
    return _closed({"event_id": ID, "revision_id": ID, "state": {"enum": ["pending", "started", "failed"]},
                    "attempts": {"type": "integer", "minimum": 0}, "last_error": {"type": ["string", "null"]}, "uncertain": {"type": "boolean"}, "run_id": {"anyOf": [RID, {"type": "null"}]}})


def handoff_schema():
    return {"$schema": "https://json-schema.org/draft/2020-12/schema", "$id": "urn:service-management:runtime-handoff:v1", **_closed({
        "schema": {"const": "service.runtime-handoff.v1"}, "event_id": ID, "source": {"const": "service-management"},
        "request_id": ID, "case_id": ID, "plan_revision_id": ID, "pin": PIN, "inputs": VALUES, "idempotency_key": ID})}


def revision_schema():
    provenance = {**SELECTION["properties"], "output_id": RID, "receipt_id": RID, "actor_id": RID, "fence": {"type": "integer", "minimum": 1},
                  "source_pin": PIN, "output_type": {"type": "object"}, "committed_at_ms": {"type": "integer", "minimum": 1}}
    return _closed({"schema": {"const": "service.case-plan-revision.v1"}, "id": ID, "case_id": ID,
                    "revision_number": {"type": "integer", "minimum": 1}, "reason": TEXT, "author": ID,
                    "authority_mode": {"enum": ["verified_call", "local_dev_untrusted"]}, "created_at": TEXT,
                    "command_id": ID, "case_version_before": {"type": "integer", "minimum": 1},
                    "prior_revision_id": {"anyOf": [ID, {"type": "null"}]}, "prior_pin": {"anyOf": [PIN, {"type": "null"}]},
                    "new_pin": PIN, "superseded_run_id": {"anyOf": [RID, {"type": "null"}]}, "inputs": VALUES,
                    "carry_forward": {"type": "array", "maxItems": 128, "items": _closed(provenance)}})


def query_schema():
    variants = []
    for operation, kind in [("request.execution", "ServiceRequest"), ("case.summary", "Case"), ("case.plan-history", "Case")]:
        payload = _closed({"after_revision": {"type": "integer", "minimum": 0}, "limit": {"type": "integer", "minimum": 1, "maximum": 100}}) if operation == "case.plan-history" else _closed({})
        variants.append(_closed({"schema": {"const": "service.query.v1"}, "request_id": ID, "operation": {"const": operation},
                                "resource": _closed({"kind": {"const": kind}, "id": ID}), "payload": payload}))
    return {"$schema": "https://json-schema.org/draft/2020-12/schema", "$id": "urn:service-management:query:v1", "oneOf": variants}


def query_result_schema():
    nullable = lambda schema: {"anyOf": [schema, {"type": "null"}]}
    natural = {"type": "integer", "minimum": 0}
    positive = {"type": "integer", "minimum": 1}
    states = {"enum": ["awaiting_plan", "pending", "started", "failed"]}
    health = _closed({"cursor": natural, "freshness": {"enum": ["current", "catching_up", "stale", "gap", "unavailable"]},
                      "observed_at": {"type": ["number", "null"]}, "age_seconds": {"type": ["number", "null"], "minimum": 0},
                      "last_rebuild": nullable(_closed({"cursor_before": natural, "cursor_after": natural, "hash_before": HASH, "hash_after": HASH, "drift_detected": {"type": "boolean"}}))})
    step = _closed({"step_id": RID, "state": {"enum": ["waiting", "ready", "running", "blocked", "succeeded", "failed", "cancelled"]}})
    view = _closed({"run_id": RID, "state": {"enum": ["unknown", "pending", "running", "blocked", "succeeded", "failed", "cancelled"]},
                    "steps": {"type": "array", "maxItems": 1000, "items": step}, "source_version": natural, "source_sequence": natural,
                    "source_resource": TEXT, "completion": _closed({"observed_steps": natural, "succeeded_steps": natural}),
                    "blockers": _closed({"run_blocked": {"type": "boolean"}, "observed_failed_steps": natural})})
    data = {
        "request.execution": _closed({"request_id": ID, "request_state": {"enum": ["intake", "qualified", "accepted", "rejected"]}, "request_version": positive,
                                      "case_id": nullable(ID), "execution_state": {"enum": states["enum"] + ["not_accepted"]}, "handoff": nullable(public_handoff_schema())}),
        "case.plan-history": _closed({"case_id": ID, "revisions": {"type": "array", "maxItems": 100, "items": revision_schema()}, "next_revision": natural}),
        "case.summary": _closed({"canonical_service": _closed({"case_id": ID, "state": {"enum": ["open", "planned", "closed"]}, "version": positive, "current_plan_revision_id": nullable(ID)}),
                                 "execution_state": states, "handoff": nullable(public_handoff_schema()), "derived_runtime": nullable(view), "projection": health,
                                 "canonical_runtime": {"const": False}, "redaction": _closed({"applied": {"const": True}, "omitted": {"const": ["inputs", "outputs", "credentials", "raw_event_data", "blocker_text"]}})}),
    }
    return {"$schema": "https://json-schema.org/draft/2020-12/schema", "$id": "urn:service-management:query-result:v1", "oneOf": [
        _closed({"schema": {"const": "service.query-result.v1"}, "request_id": ID, "operation": {"const": operation}, "data": shape}) for operation, shape in data.items()]}
