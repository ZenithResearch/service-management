"""Closed v1 wire contract, canonical digest and matching published JSON Schema."""

import hashlib
import json
import re
from dataclasses import dataclass

from .errors import ServiceError

MAX_BODY = 65_536
MAX_VERSION = 2**53 - 1
IDENTIFIER = r"^[a-z0-9][a-z0-9._-]{0,127}$"
ROOT_FIELDS = {"schema", "operation", "request_id", "resource", "expected_version", "payload"}
# operation: resource kind, required payload fields and their string limits
OPERATIONS = {
    "request.create": ("ServiceRequest", {"summary": 2048}),
    "request.qualify": ("ServiceRequest", {"qualification": 4096}),
    "request.accept": ("ServiceRequest", {"acceptance": 4096}),
    "request.reject": ("ServiceRequest", {"reason": 4096}),
    "request.convert": ("ServiceRequest", {"case_id": 128, "obligation": 4096}),
    "case.plan": ("Case", {"scope": 8192}),
    "case.close": ("Case", {"resolution": 8192}),
    "case.plan.approve": ("Case", {}),
    "case.plan.revise": ("Case", {}),
}


def identifier(value: object) -> bool:
    return isinstance(value, str) and re.fullmatch(IDENTIFIER, value, re.ASCII) is not None


def canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def _unique_pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def _reject_number(value):
    raise ValueError("noninteger JSON number")


def load_json(raw: bytes) -> dict:
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_BODY:
        raise ServiceError("invalid_json")
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_pairs,
                           parse_constant=_reject_number)
    except (ValueError, UnicodeError, RecursionError):
        raise ServiceError("invalid_json") from None
    if not isinstance(value, dict):
        raise ServiceError("invalid_command")
    return value


@dataclass(frozen=True)
class Resource:
    kind: str
    id: str

    def as_dict(self) -> dict:
        return {"kind": self.kind, "id": self.id}


@dataclass(frozen=True)
class Command:
    operation: str
    request_id: str
    resource: Resource
    expected_version: int | None
    payload_json: str

    @property
    def payload(self) -> dict:
        return json.loads(self.payload_json)

    @classmethod
    def parse(cls, raw: bytes) -> "Command":
        value = load_json(raw)
        if set(value) != ROOT_FIELDS or value["schema"] != "service.command.v1":
            raise ServiceError("invalid_command")
        operation, resource, payload = value["operation"], value["resource"], value["payload"]
        if not isinstance(operation, str) or operation not in OPERATIONS or not identifier(value["request_id"]):
            raise ServiceError("invalid_command")
        kind, fields = OPERATIONS[operation]
        if not isinstance(resource, dict) or set(resource) != {"kind", "id"} or resource["kind"] != kind or not identifier(resource["id"]):
            raise ServiceError("invalid_command")
        version = value["expected_version"]
        if operation == "request.create":
            if version is not None:
                raise ServiceError("invalid_command")
        elif type(version) is not int or not 1 <= version <= MAX_VERSION:
            raise ServiceError("invalid_command")
        if operation in {"case.plan.approve", "case.plan.revise"}:
            from .planning import validate_plan_payload
            validate_plan_payload(operation, payload)
            return cls(operation, value["request_id"], Resource(kind, resource["id"]), version, canonical(payload))
        optional = {"details": 16384} if operation == "request.create" else {}
        if not isinstance(payload, dict) or not set(fields) <= set(payload) or set(payload) - (set(fields) | set(optional)):
            raise ServiceError("invalid_command")
        for field, text in payload.items():
            limit = fields.get(field, optional.get(field))
            if not isinstance(text, str) or len(text) > limit or "\x00" in text or (field not in optional and not text.strip()):
                raise ServiceError("invalid_command")
            try:
                text.encode("utf-8")
            except UnicodeEncodeError:
                raise ServiceError("invalid_command") from None
        if "case_id" in payload and not identifier(payload["case_id"]):
            raise ServiceError("invalid_command")
        return cls(operation, value["request_id"], Resource(kind, resource["id"]), version, canonical(payload))

    def as_dict(self) -> dict:
        return {"schema": "service.command.v1", "operation": self.operation, "request_id": self.request_id,
                "resource": self.resource.as_dict(), "expected_version": self.expected_version, "payload": self.payload}

    @property
    def digest(self) -> str:
        return hashlib.sha256(("service.command.v1\0" + canonical(self.as_dict())).encode()).hexdigest()


def command_schema() -> dict:
    variants = []
    for operation, (kind, fields) in OPERATIONS.items():
        payload = {name: {"type": "string", "minLength": 1, "maxLength": maximum, "pattern": IDENTIFIER if name == "case_id" else r"\S"} for name, maximum in fields.items()}
        if operation == "request.create":
            payload["details"] = {"type": "string", "maxLength": 16384}
        payload_schema = {"type": "object", "additionalProperties": False, "required": list(fields), "properties": payload}
        if operation in {"case.plan.approve", "case.plan.revise"}:
            from .integration_schema import plan_payload_schema
            payload_schema = plan_payload_schema(operation)
        variants.append({"type": "object", "additionalProperties": False, "required": sorted(ROOT_FIELDS), "properties": {
            "schema": {"const": "service.command.v1"}, "operation": {"const": operation},
            "request_id": {"type": "string", "pattern": IDENTIFIER},
            "resource": {"type": "object", "additionalProperties": False, "required": ["kind", "id"], "properties": {"kind": {"const": kind}, "id": {"type": "string", "pattern": IDENTIFIER}}},
            "expected_version": {"type": "null"} if operation == "request.create" else {"type": "integer", "minimum": 1, "maximum": MAX_VERSION},
            "payload": payload_schema,
        }})
    return {"$schema": "https://json-schema.org/draft/2020-12/schema", "$id": "urn:service-management:command:v1", "title": "service.command.v1", "oneOf": variants,
            "$comment": "Wire reader additionally rejects duplicate keys, non-finite numbers, NUL in payload strings, invalid Unicode, non-ASCII identifiers and bodies over 65536 bytes. Versions must use integer JSON tokens. Identifiers use a full-string match. No Unicode normalization is performed."}


def _closed(properties: dict) -> dict:
    return {"type": "object", "additionalProperties": False, "required": list(properties), "properties": properties}


def result_schema() -> dict:
    identifier_schema = {"type": "string", "pattern": IDENTIFIER}
    text = {"type": "string"}
    nullable_text = {"type": ["string", "null"]}
    version = {"type": "integer", "minimum": 1, "maximum": MAX_VERSION}
    request = _closed({
        "id": identifier_schema, "summary": text, "details": text,
        "state": {"enum": ["intake", "qualified", "accepted", "rejected"]}, "version": version,
        "created_at": text, "updated_at": text, "qualification": nullable_text,
        "acceptance": nullable_text, "rejection_reason": nullable_text,
        "case_id": {"anyOf": [identifier_schema, {"type": "null"}]},
    })
    case = _closed({
        "id": identifier_schema, "service_request_id": identifier_schema, "obligation": text,
        "state": {"enum": ["open", "planned", "closed"]}, "version": version,
        "created_at": text, "updated_at": text, "plan_scope": nullable_text, "closure_resolution": nullable_text,
        "current_plan_revision_id": {"anyOf": [identifier_schema, {"type": "null"}]},
    })
    case["required"].remove("current_plan_revision_id")
    from .integration_schema import revision_schema, public_handoff_schema
    result = _closed({
        "schema": {"const": "service.result.v1"}, "request_id": identifier_schema,
        "operation": {"enum": list(OPERATIONS)},
        "authority": _closed({"subject": identifier_schema, "mode": {"enum": ["verified_call", "local_dev_untrusted"]}}),
        "service_request": {"anyOf": [request, {"type": "null"}]},
        "case": {"anyOf": [case, {"type": "null"}]},
        "plan_revision": {"anyOf": [revision_schema(), {"type": "null"}]},
        "handoff": {"anyOf": [public_handoff_schema(), {"type": "null"}]},
        "audit_event_ids": {"type": "array", "minItems": 1, "maxItems": 2, "uniqueItems": True, "items": {"type": "string", "format": "uuid"}},
    })
    # Retained successful v1 results are returned byte-for-byte in meaning after
    # storage migration; initial foundation receipts lacked these additions.
    result["required"].remove("plan_revision")
    result["required"].remove("handoff")
    return {"$schema": "https://json-schema.org/draft/2020-12/schema", "$id": "urn:service-management:result:v1", **result}


def error_schema() -> dict:
    from .errors import ERRORS
    details = {"oneOf": [
        _closed({}),
        _closed({"expected_version": {"type": "integer", "minimum": 1}, "actual_version": {"type": "integer", "minimum": 1}}),
    ]}
    return {"$schema": "https://json-schema.org/draft/2020-12/schema", "$id": "urn:service-management:error:v1", **_closed({
        "schema": {"const": "service.error.v1"}, "request_id": {"type": ["string", "null"], "pattern": IDENTIFIER},
        "error": _closed({"code": {"enum": list(ERRORS)}, "message": {"type": "string"}, "details": details}),
    })}
