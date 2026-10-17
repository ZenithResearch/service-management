"""Explicit immutable service plan decisions and trusted carry-forward checks."""

from dataclasses import replace
import json
import re
import uuid

from .contracts import canonical, identifier
from .errors import ServiceError
from .runtime_port import (RuntimeClient, RuntimeCallError, content_digest, json_value, matches, pin,
                           published_inputs, query_data, runtime_id, validate_type)

PLAN_OPERATIONS = {"case.plan.approve", "case.plan.revise"}
SELECTION_FIELDS = {"run_id", "step_id", "attempt_id", "output_name", "target_input", "expected_output_digest"}


def validate_plan_payload(operation: str, payload: dict):
    fields = {"revision_id", "reason", "pin", "inputs", "carry_forward"}
    if operation == "case.plan.revise": fields.add("superseded_run_id")
    if not isinstance(payload, dict) or set(payload) != fields or not identifier(payload.get("revision_id")):
        raise ServiceError("invalid_command")
    if not isinstance(payload["reason"], str) or not payload["reason"].strip() or len(payload["reason"]) > 4096:
        raise ServiceError("invalid_command")
    pin(payload["pin"])
    json_value(payload)
    if not isinstance(payload["inputs"], dict) or len(payload["inputs"]) > 128 or any(not runtime_id(key) for key in payload["inputs"]):
        raise ServiceError("invalid_command")
    selections = payload["carry_forward"]
    if not isinstance(selections, list) or len(selections) > 128:
        raise ServiceError("invalid_command")
    targets = set()
    for selection in selections:
        if not isinstance(selection, dict) or set(selection) != SELECTION_FIELDS or any(not runtime_id(selection[key]) for key in SELECTION_FIELDS - {"expected_output_digest"}):
            raise ServiceError("invalid_command")
        if not isinstance(selection["expected_output_digest"], str) or re.fullmatch(r"[a-f0-9]{64}", selection["expected_output_digest"]) is None or selection["target_input"] in targets or selection["target_input"] in payload["inputs"]:
            raise ServiceError("invalid_command")
        targets.add(selection["target_input"])
    if operation == "case.plan.approve" and selections:
        raise ServiceError("invalid_command")
    if operation == "case.plan.revise" and not runtime_id(payload["superseded_run_id"]):
        raise ServiceError("invalid_command")


def prepare_plan(client: RuntimeClient, command, case, prior: dict | None, prior_handoff: dict | None) -> dict:
    if case is None:
        raise ServiceError("not_found")
    if case.version != command.expected_version:
        raise ServiceError("version_conflict", details={"expected_version": command.expected_version, "actual_version": case.version})
    if case.state != "planned":
        raise ServiceError("invalid_transition")
    payload = command.payload
    if command.operation == "case.plan.approve":
        if prior is not None:
            raise ServiceError("invalid_transition")
    elif prior is None or prior_handoff is None or prior_handoff["state"] != "started":
        # A timed-out original create must be reconciled before replacing it.
        raise ServiceError("handoff_unresolved")
    elif prior_handoff["run_id"] != payload["superseded_run_id"]:
        raise ServiceError("invalid_command")
    types = published_inputs(client, payload["pin"])
    inputs = json.loads(canonical(payload["inputs"]))
    provenance = []
    prior_run = None
    if prior is not None:
        prior_run = query_data(client, "run.get", {"run_id": payload["superseded_run_id"]})
        if prior_run.get("run_id") != payload["superseded_run_id"] or prior_run.get("pin") != prior["new_pin"]:
            raise ServiceError("runtime_contract")
    for selection in payload["carry_forward"]:
        if selection["run_id"] != payload["superseded_run_id"]:
            raise ServiceError("invalid_carry_forward")
        output = query_data(client, "output.get", {key: selection[key] for key in ("run_id", "step_id", "attempt_id")})
        if not runtime_id(output.get("receipt_id")):
            raise ServiceError("invalid_carry_forward")
        receipt = query_data(client, "receipt.get", {"receipt_id": output.get("receipt_id")})
        source_name, target = selection["output_name"], selection["target_input"]
        source_types, values = output.get("output_types"), output.get("outputs")
        if (not isinstance(source_types, dict) or not isinstance(values, dict) or source_name not in source_types or source_name not in values or target not in types
                or any(output.get(key) != selection[key] for key in ("run_id", "step_id", "attempt_id"))
                or output.get("pin") != prior["new_pin"] or output.get("output_digest") != selection["expected_output_digest"]
                or content_digest(values) != output["output_digest"] or not runtime_id(output.get("output_id"))
                or type(output.get("fence")) is not int or output["fence"] < 1
                or type(output.get("committed_at_ms")) is not int or output["committed_at_ms"] < 1):
            raise ServiceError("invalid_carry_forward")
        validate_type(source_types[source_name])
        if source_types[source_name] != types[target] or not matches(types[target], values[source_name]):
            raise ServiceError("invalid_carry_forward")
        # An output record and its retained receipt must describe the same commit.
        if (receipt.get("schema") != "runtime.receipt.v1" or receipt.get("outcome") != "succeeded"
                or any(receipt.get(key) != output.get(key) for key in ("receipt_id", "pin", "run_id", "step_id", "attempt_id", "fence", "actor_id", "output_digest"))
                or receipt.get("input_digest") != output.get("inputs_digest")):
            raise ServiceError("invalid_carry_forward")
        steps = prior_run.get("steps")
        selected_step = next((step for step in steps if step.get("step_id") == selection["step_id"]), None) if isinstance(steps, list) else None
        if selected_step is None or selected_step.get("state") != "succeeded" or selected_step.get("attempt_id") != selection["attempt_id"] or selected_step.get("fence") != output["fence"]:
            raise ServiceError("invalid_carry_forward")
        inputs[target] = values[source_name]
        provenance.append({**selection, "output_id": output["output_id"], "receipt_id": output["receipt_id"],
                           "actor_id": output["actor_id"], "fence": output["fence"], "source_pin": output["pin"],
                           "output_type": source_types[source_name], "committed_at_ms": output["committed_at_ms"]})
    if set(inputs) != set(types) or any(not matches(types[key], value) for key, value in inputs.items()):
        raise ServiceError("invalid_plan_inputs")
    json_value(inputs)
    event_id = str(uuid.uuid4())
    event = {"schema": "service.runtime-handoff.v1", "event_id": event_id, "source": "service-management",
             "request_id": case.service_request_id, "case_id": case.id, "plan_revision_id": payload["revision_id"],
             "pin": payload["pin"], "inputs": inputs, "idempotency_key": event_id}
    try:
        envelope = client.new_command("handoff.consume", request_id="handoff-" + event_id, expected_version=None, payload=json.loads(canonical(event)))
    except RuntimeCallError:
        raise ServiceError("runtime_contract") from None
    expected = {"schema": "runtime.command.v1", "operation": "handoff.consume", "request_id": "handoff-" + event_id,
                "resource": "handoffs/" + content_digest({"source": event["source"], "event_id": event_id}), "expected_version": None, "payload": event}
    if envelope != expected: raise ServiceError("runtime_contract")
    return {"inputs": inputs, "carry_forward": provenance, "prior_revision_id": prior["id"] if prior else None,
            "prior_pin": prior["new_pin"] if prior else None, "revision_number": prior["revision_number"] + 1 if prior else 1,
            "handoff_command": json.loads(canonical(envelope))}


def apply_plan(tx, command, actor, now, case, prepared):
    if case.state != "planned" or case.current_plan_revision_id != prepared["prior_revision_id"]:
        raise ServiceError("invalid_transition")
    payload = command.payload
    revision = {"schema": "service.case-plan-revision.v1", "id": payload["revision_id"], "case_id": case.id,
                "revision_number": prepared["revision_number"], "reason": payload["reason"], "author": actor.subject,
                "authority_mode": actor.mode, "created_at": now, "command_id": command.request_id,
                "case_version_before": case.version, "prior_revision_id": prepared["prior_revision_id"],
                "prior_pin": prepared["prior_pin"], "new_pin": payload["pin"],
                "superseded_run_id": payload.get("superseded_run_id"), "inputs": prepared["inputs"],
                "carry_forward": prepared["carry_forward"]}
    envelope = prepared["handoff_command"]
    event_id = envelope["payload"]["event_id"]
    handoff = {"event_id": event_id, "case_id": case.id, "revision_id": revision["id"], "state": "pending",
               "version": 1, "attempts": 0, "last_error": None, "uncertain": False, "run_id": None, "command": envelope, "receipt": None}
    tx.insert_revision(revision)
    tx.insert_handoff(handoff)
    updated = replace(case, current_plan_revision_id=revision["id"], version=case.version + 1, updated_at=now)
    tx.update_case(updated, case.version)
    return updated, revision, handoff
