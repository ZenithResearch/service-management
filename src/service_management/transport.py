"""Additive bounded HTTP envelope for native evidence larger than a header."""
import base64
import binascii

from .contracts import MAX_BODY, _unique_pairs, canonical
from .errors import ServiceError
from .native_authority import MAX_AUTHORITY_BYTES

MAX_AUTHORITY_BASE64 = 4 * ((MAX_AUTHORITY_BYTES + 2) // 3)
TRANSPORT_FIXED_BYTES = len(canonical({"schema": "service.transport.v1", "request": {}, "authority_base64": ""}).encode()) - 2
# Covers compact canonical and ensure_ascii=True producers. Extra whitespace or
# generic JSON escaping remains subject to this explicit outer wire ceiling.
MAX_TRANSPORT_BODY = 6 * MAX_BODY + MAX_AUTHORITY_BASE64 + TRANSPORT_FIXED_BYTES


def decode_http_request(raw: bytes, header_evidence: bytes | None) -> tuple[bytes, bytes | None]:
    import json
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_TRANSPORT_BODY:
        raise ServiceError("invalid_json")
    try:
        value = json.loads(raw.decode(), object_pairs_hook=_unique_pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite")))
    except (ValueError, UnicodeError, RecursionError):
        raise ServiceError("invalid_json") from None
    if not isinstance(value, dict) or value.get("schema") != "service.transport.v1":
        if len(raw) > MAX_BODY:
            raise ServiceError("invalid_json")
        return raw, header_evidence
    if set(value) != {"schema", "request", "authority_base64"} or header_evidence is not None or not isinstance(value["request"], dict) or type(value["authority_base64"]) is not str:
        raise ServiceError("invalid_command")
    try:
        evidence = base64.b64decode(value["authority_base64"], validate=True)
        if not 0 < len(evidence) <= MAX_AUTHORITY_BYTES or base64.b64encode(evidence).decode() != value["authority_base64"]:
            raise ValueError("invalid evidence encoding")
        request = canonical(value["request"]).encode()
        if len(request) > MAX_BODY:
            raise ValueError("request too large")
        return request, evidence
    except (ValueError, UnicodeError, binascii.Error, RecursionError):
        raise ServiceError("invalid_command") from None


def transport_schema() -> dict:
    from .contracts import command_schema
    from .integration_schema import query_schema
    return {"$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": "urn:service-management:transport:v1", "type": "object",
            "additionalProperties": False, "required": ["schema", "request", "authority_base64"],
            "properties": {"schema": {"const": "service.transport.v1"},
                "request": {"oneOf": [command_schema(), query_schema()]},
                "authority_base64": {"type": "string", "minLength": 4, "maxLength": MAX_AUTHORITY_BASE64,
                                     "pattern": "^[A-Za-z0-9+/]+={0,2}$"}},
            "$comment": f"The HTTP decoder additionally enforces strict canonical base64, decoded evidence 1..{MAX_AUTHORITY_BYTES} bytes, inner request at most {MAX_BODY} bytes, outer body at most {MAX_TRANSPORT_BODY} bytes, unique JSON fields and no simultaneous header evidence. The outer ceiling covers compact canonical and ensure_ascii=True producers; additional whitespace/escapes remain bounded by the same wire ceiling."}
