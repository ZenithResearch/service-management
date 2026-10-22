"""Consumer-owned public runtime API port; no runtime implementation imports."""

import hashlib
import json
import math
import re
from typing import Protocol

from .contracts import canonical
from .errors import ServiceError

RUNTIME_ID = r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}"


class RuntimeCallError(Exception):
    def __init__(self, code: str, *, retryable: bool = False, uncertain: bool = False):
        self.code, self.retryable, self.uncertain = code, retryable, uncertain
        super().__init__(code)


class RuntimeClient(Protocol):
    """Authenticated adapter; returned envelopes must be from the pinned receiver.

    Plain dictionaries are public wire values, never runtime domain/storage types.
    The adapter owns authority evidence and timeout classification. It must not
    present an unauthenticated HTTP response as a trusted query result.
    """
    def command(self, envelope: dict) -> dict: ...
    def resume_command(self, envelope: dict) -> dict: ...
    def query(self, envelope: dict) -> dict: ...
    def new_command(self, operation: str, *, request_id: str, expected_version: int | None, payload: dict) -> dict: ...


class UnavailableRuntime:
    def command(self, envelope: dict) -> dict:
        raise RuntimeCallError("storage_unavailable", retryable=True)

    def query(self, envelope: dict) -> dict:
        raise RuntimeCallError("storage_unavailable", retryable=True)

    def resume_command(self, envelope: dict) -> dict:
        raise RuntimeCallError("storage_unavailable", retryable=True, uncertain=True)

    def new_command(self, operation, **kwargs):
        raise RuntimeCallError("storage_unavailable", retryable=True)


def runtime_id(value) -> bool:
    return isinstance(value, str) and re.fullmatch(RUNTIME_ID, value) is not None


def content_digest(value) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def pin(value) -> dict:
    if (not isinstance(value, dict) or set(value) != {"process_id", "process_version", "compilation_hash"}
            or not runtime_id(value["process_id"]) or not runtime_id(value["process_version"])
            or not isinstance(value["compilation_hash"], str) or not re.fullmatch(r"[a-f0-9]{64}", value["compilation_hash"])):
        raise ServiceError("invalid_command")
    return dict(value)


def json_value(value, depth=0):
    if depth > 32:
        raise ServiceError("invalid_command")
    if value is None or type(value) in {bool, int}:
        return
    if type(value) is float and math.isfinite(value):
        return
    if type(value) is str:
        try:
            value.encode("utf-8")
        except UnicodeError:
            raise ServiceError("invalid_command") from None
        if "\0" in value:
            raise ServiceError("invalid_command")
        return
    if type(value) is list:
        for item in value:
            json_value(item, depth + 1)
        return
    if type(value) is dict and all(type(key) is str for key in value):
        for key, item in value.items():
            json_value(key, depth + 1)
            json_value(item, depth + 1)
        return
    raise ServiceError("invalid_command")


def query_data(client: RuntimeClient, operation: str, payload: dict) -> dict:
    try:
        result = json.loads(canonical(client.query({"schema": "runtime.query.v1", "operation": operation, "payload": json.loads(canonical(payload))})))
    except RuntimeCallError as error:
        if error.code == "cursor_gap": raise ServiceError("projection_gap") from None
        code = "runtime_unavailable" if error.retryable or error.uncertain else "runtime_rejected"
        raise ServiceError(code) from None
    except (ValueError, TypeError, UnicodeError):
        raise ServiceError("runtime_contract") from None
    if not isinstance(result, dict) or set(result) != {"schema", "operation", "data"} or result["schema"] != "runtime.query-result.v1" or result["operation"] != operation or not isinstance(result["data"], dict):
        raise ServiceError("runtime_contract")
    return result["data"]


def validate_type(spec, depth=0):
    if depth > 32 or not isinstance(spec, dict):
        raise ServiceError("runtime_contract")
    kind = spec.get("kind")
    if not isinstance(kind, str): raise ServiceError("runtime_contract")
    if kind in {"string", "integer", "number", "boolean", "artifact"} and set(spec) == {"kind"}:
        return
    if kind == "array" and set(spec) == {"kind", "items"}:
        validate_type(spec["items"], depth + 1)
        return
    if kind == "object" and set(spec) == {"kind", "properties", "required"} and isinstance(spec["properties"], dict) and isinstance(spec["required"], list):
        if len(spec["properties"]) > 128 or any(not runtime_id(key) for key in spec["properties"]) or any(not isinstance(key, str) for key in spec["required"]) or len(set(spec["required"])) != len(spec["required"]) or not set(spec["required"]) <= set(spec["properties"]):
            raise ServiceError("runtime_contract")
        for item in spec["properties"].values():
            validate_type(item, depth + 1)
        return
    raise ServiceError("runtime_contract")


def matches(spec: dict, value) -> bool:
    kind = spec["kind"]
    if kind == "string": return type(value) is str
    if kind == "integer": return type(value) is int
    if kind == "number": return type(value) is int or (type(value) is float and math.isfinite(value))
    if kind == "boolean": return type(value) is bool
    if kind == "array": return type(value) is list and all(matches(spec["items"], item) for item in value)
    if kind == "object":
        return (type(value) is dict and set(spec["required"]) <= set(value) <= set(spec["properties"])
                and all(matches(spec["properties"][key], item) for key, item in value.items()))
    if kind == "artifact":
        return (type(value) is dict and set(value) == {"content_hash", "byte_length", "media_type"}
                and isinstance(value["content_hash"], str) and re.fullmatch(r"[a-f0-9]{64}", value["content_hash"]) is not None
                and type(value["byte_length"]) is int and value["byte_length"] >= 0 and isinstance(value["media_type"], str) and bool(value["media_type"]))
    return False


def published_inputs(client: RuntimeClient, expected_pin: dict) -> dict:
    data = query_data(client, "version.get", {"process_version": expected_pin["process_version"]})
    compiled = data.get("compiled")
    if data.get("pin") != expected_pin or not isinstance(compiled, dict) or content_digest(compiled) != expected_pin["compilation_hash"]:
        raise ServiceError("runtime_contract")
    inputs = compiled.get("inputs")
    if not isinstance(inputs, dict) or len(inputs) > 128 or any(not runtime_id(key) for key in inputs):
        raise ServiceError("runtime_contract")
    for spec in inputs.values():
        validate_type(spec)
    return inputs


def expected_run_id(event: dict) -> str:
    return "handoff-" + content_digest({"source": event["source"], "event_id": event["event_id"]})[:48]
