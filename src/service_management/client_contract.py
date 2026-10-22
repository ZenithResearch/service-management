"""Provider-neutral browser contract over canonical Service/Runtime owners."""

from .contracts import IDENTIFIER, MAX_VERSION, _closed

ID = {"type": "string", "pattern": IDENTIFIER}
TEXT = {"type": "string", "minLength": 1, "maxLength": 16384}
URI = {"type": "string", "minLength": 1, "maxLength": 4096}
HASH = {"type": "string", "pattern": "^[a-f0-9]{64}$"}
VERSION = {"type": "integer", "minimum": 1, "maximum": MAX_VERSION}
NATURAL = {"type": "integer", "minimum": 0, "maximum": MAX_VERSION}
NULLABLE_TEXT = {"type": ["string", "null"], "maxLength": 4096}


def _artifact():
    return _closed({"schema": {"const": "service.artifact-manifest.v1"}, "artifact_id": ID,
                    "content_hash": HASH, "byte_length": NATURAL, "media_type": TEXT, "filename": TEXT})


def _transport_receipt():
    return _closed({"transport": TEXT, "receipt_id": ID, "recorded_at": TEXT, "expires_at": NULLABLE_TEXT})


def client_schema(version: int = 4) -> dict:
    pin = _closed({"process_id": TEXT, "process_version": TEXT, "compilation_hash": HASH})
    input_field = _closed({"id": ID, "label": TEXT, "type": {"enum": ["string", "integer", "number", "boolean"]},
                           "required": {"type": "boolean"}, "description": {"type": "string", "maxLength": 4096},
                           "max_length": {"type": ["integer", "null"], "minimum": 0, "maximum": 16384}})
    reference = _closed({"id": ID, "label": TEXT, "required": {"type": "boolean"},
                         "media_types": {"type": "array", "minItems": 1, "maxItems": 32, "uniqueItems": True, "items": TEXT},
                         "max_bytes": {"type": "integer", "minimum": 1, "maximum": 1_073_741_824}})
    expected = _closed({"id": ID, "label": TEXT,
                        "media_types": {"type": "array", "minItems": 1, "maxItems": 32, "uniqueItems": True, "items": TEXT},
                        "multiple": {"type": "boolean"}})
    service = _closed({"id": ID, "version": TEXT, "name": TEXT, "summary": TEXT,
                       "availability": {"enum": ["available", "paused", "preview"]},
                       "inputs": {"type": "array", "maxItems": 128, "items": input_field},
                       "accepted_references": {"type": "array", "maxItems": 128, "items": reference},
                       "expected_deliverables": {"type": "array", "maxItems": 128, "items": expected},
                       "process": {"anyOf": [pin, {"type": "null"}]},
                       "communication": {"type": "array", "maxItems": 2, "uniqueItems": True,
                                         "items": {"enum": ["provider-status", "matrix"]}}})
    provider = _closed({"id": ID, "name": TEXT, "version": TEXT})
    authority = _closed({"submission": {"const": "receiver-issued"},
                         "status": {"const": "receiver-issued"},
                         "artifacts": {"const": "receiver-issued"}})
    catalog_v1 = _closed({"schema": {"const": "service.provider-catalog.v1"},
                          "provider": provider,
                          "services": {"type": "array", "maxItems": 100, "items": service},
                          "authority": authority})
    envelope = _closed({"schema": {"const": "service.intake-envelope.v1"},
                        "algorithm": {"const": "x25519-hkdf-sha256-chacha20poly1305"},
                        "recipient_key_id": {"type": "string", "minLength": 1, "maxLength": 255,
                                             "pattern": "^[!-~]+$"},
                        "recipient_public_key_hex": HASH,
                        "not_before": TEXT, "not_after": TEXT})
    intake_delivery = _closed({"endpoint": URI,
                               "max_retention_seconds": {"type": "integer", "minimum": 60, "maximum": 604800},
                               "envelope": envelope})
    catalog_v2 = _closed({"schema": {"const": "service.provider-catalog.v2"},
                          "provider": provider,
                          "services": {"type": "array", "maxItems": 100, "items": service},
                          "authority": authority, "intake": intake_delivery})
    caller = _closed({"kind": {"enum": ["browser", "terminal"]}, "id": TEXT})
    membership_root = _closed({"issuer_id": ID, "key_id": ID, "public_key_hex": HASH})
    requester = _closed({
        "evidence_schema": {"const": "service.castalia-requester-evidence.v1"},
        "membership": _closed({
            "credential_schema": {"const": "castalia.zenith-membership-credential.v3"},
            "issuer_origin": URI,
            "roots": {"type": "array", "minItems": 1, "maxItems": 16, "items": membership_root},
        }),
        "credential": _closed({
            "endpoint": URI,
            "issuance_schema": {"const": "service.castalia-credential-issuance.v1"},
            "credential_schema": {"const": "castalia.request-credential.v1"},
            "presentation_protocol": {"const": "castalia.wallet-auth.v2"},
            "issuer": TEXT,
            "key_id": ID,
            "public_key_hex": HASH,
            "audience": TEXT,
            "policy_digest_sha256": HASH,
            "callers": {"type": "array", "minItems": 1, "maxItems": 16, "items": caller},
        }),
    })
    catalog_v3 = _closed({"schema": {"const": "service.provider-catalog.v3"},
                          "provider": provider,
                          "services": {"type": "array", "maxItems": 100, "items": service},
                          "authority": authority, "intake": intake_delivery, "requester": requester})
    reference_envelope = _closed({"schema": {"const": "service.reference-object-envelope.v1"},
                                  "algorithm": {"const": "x25519-hkdf-sha256-chacha20poly1305"},
                                  "recipient_key_id": {"type": "string", "minLength": 1,
                                                       "maxLength": 255, "pattern": "^[!-~]+$"},
                                  "recipient_public_key_hex": HASH,
                                  "not_before": TEXT, "not_after": TEXT})
    reference_delivery = _closed({"endpoint": URI,
                                  "max_retention_seconds": {"type": "integer", "minimum": 60,
                                                            "maximum": 604800},
                                  "max_object_bytes": {"const": 524288},
                                  "max_objects_per_request": {"const": 1},
                                  "envelope": reference_envelope})
    catalog_v4 = _closed({"schema": {"const": "service.provider-catalog.v4"},
                          "provider": provider,
                          "services": {"type": "array", "maxItems": 100, "items": service},
                          "authority": authority, "intake": intake_delivery,
                          "requester": requester, "reference_objects": reference_delivery})
    catalog_versions = [{"$ref": "#/$defs/provider_catalog_v1"},
                        {"$ref": "#/$defs/provider_catalog_v2"}]
    if version >= 3:
        catalog_versions.append({"$ref": "#/$defs/provider_catalog_v3"})
    if version >= 4:
        catalog_versions.append({"$ref": "#/$defs/provider_catalog_v4"})
    catalog = {"oneOf": catalog_versions}
    brief = _closed({"schema": {"const": "service.reviewed-brief.v1"}, "revision": VERSION,
                     "content_hash": HASH, "values": {"type": "object", "maxProperties": 128}})
    intake = _closed({"schema": {"const": "service.intake.v1"}, "request_id": ID, "idempotency_key": ID,
                      "service": _closed({"provider_id": ID, "service_id": ID, "service_version": TEXT}),
                      "brief": brief, "references": {"type": "array", "maxItems": 128, "items": _artifact()},
                      "submitted_at": TEXT})
    intake_result = _closed({"schema": {"const": "service.intake-result.v1"}, "request_id": ID,
                             "idempotency_key": ID, "state": {"enum": ["pending", "admitted", "rejected"]},
                             "transport_receipt": {"anyOf": [_transport_receipt(), {"type": "null"}]},
                             "service_request_id": {"anyOf": [ID, {"type": "null"}]},
                             "service_request_version": {"anyOf": [VERSION, {"type": "null"}]}, "status_url": URI})
    reference_result = _closed({"schema": {"const": "service.reference-object-result.v1"},
                                "request_id": ID, "idempotency_key": ID, "artifact_id": ID,
                                "content_hash": HASH, "state": {"const": "pending"},
                                "transport_receipt": _transport_receipt()})
    receipt = _closed({"schema": {"const": "service.receipt-reference.v1"},
                       "owner": {"enum": ["service-management", "process-runtime", "secs"]},
                       "receipt_schema": TEXT, "receipt_id": ID, "content_hash": HASH, "recorded_at": TEXT,
                       "verification": _closed({"state": {"enum": ["verified", "unverified", "failed"]},
                                                "verifier": NULLABLE_TEXT, "detail": NULLABLE_TEXT}), "href": URI})
    deliverable = _closed({"id": ID, "version": VERSION, "label": TEXT, "artifact": _artifact(), "href": URI,
                           "receipt_ids": {"type": "array", "maxItems": 128, "uniqueItems": True, "items": ID}})
    service_request = _closed({"id": ID, "state": {"enum": ["intake", "qualified", "accepted", "rejected"]},
                               "version": VERSION, "case_id": {"anyOf": [ID, {"type": "null"}]}})
    case = _closed({"id": ID, "state": {"enum": ["open", "planned", "closed"]}, "version": VERSION,
                    "current_plan_revision_id": {"anyOf": [ID, {"type": "null"}]}})
    execution = _closed({"run_id": {"type": ["string", "null"], "maxLength": 128},
                         "state": {"enum": ["awaiting_plan", "pending", "running", "blocked", "succeeded", "failed", "cancelled", "unknown"]},
                         "freshness": {"enum": ["current", "catching_up", "stale", "gap", "unavailable"]},
                         "observed_at": NULLABLE_TEXT})
    projection = _closed({"schema": {"const": "service.client-projection.v1"}, "request_id": ID,
                          "idempotency_key": ID, "provider_id": ID, "service_id": ID,
                          "transport": _closed({"state": {"enum": ["pending", "consumed", "expired", "failed"]},
                                                "receipt": {"anyOf": [_transport_receipt(), {"type": "null"}]}}),
                          "service_request": {"anyOf": [service_request, {"type": "null"}]},
                          "case": {"anyOf": [case, {"type": "null"}]},
                          "execution": {"anyOf": [execution, {"type": "null"}]},
                          "deliverables": {"type": "array", "maxItems": 128, "items": deliverable},
                          "receipts": {"type": "array", "maxItems": 512, "items": receipt},
                          "updated_at": TEXT, "retry_after_ms": {"type": ["integer", "null"], "minimum": 0, "maximum": 86_400_000}})
    error = _closed({"schema": {"const": "service.client-error.v1"}, "request_id": {"anyOf": [ID, {"type": "null"}]},
                     "error": _closed({"code": {"enum": ["invalid_request", "forbidden", "not_found", "conflict", "expired", "unavailable", "internal_error"]},
                                       "message": TEXT, "retryable": {"type": "boolean"}})})
    if version not in {1, 2, 3, 4}:
        raise ValueError("unsupported client contract version")
    definitions = {"provider_catalog": catalog_v1 if version == 1 else catalog,
                   "artifact_manifest": _artifact(), "intake": intake,
                   "intake_result": intake_result, "client_projection": projection,
                   "receipt_reference": receipt, "client_error": error}
    if version >= 2:
        definitions = {"provider_catalog": catalog, "provider_catalog_v1": catalog_v1,
                       "provider_catalog_v2": catalog_v2, **{key: value for key, value in definitions.items()
                                                            if key != "provider_catalog"}}
    if version >= 3:
        definitions = {**definitions, "provider_catalog_v3": catalog_v3}
    if version >= 4:
        definitions = {**definitions, "provider_catalog_v4": catalog_v4,
                       "reference_object_result": reference_result,
                       "client_read_authorization": _closed({
            "schema": {"const": "service.client-read-authorization.v1"},
            "operation": {"enum": ["request.status", "artifact.get", "receipt.get"]},
            "resource": TEXT,
        })}
    return {"$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": f"urn:service-management:client:v{version}",
            "title": f"Service Management browser client contracts v{version}",
            "$defs": definitions}


def client_schema_v1() -> dict:
    """Frozen contract suite previously published to Anima."""
    return client_schema(1)


def client_schema_v2() -> dict:
    """Frozen contract suite previously published to Anima."""
    return client_schema(2)


def client_schema_v3() -> dict:
    """Frozen contract suite previously published to Anima."""
    return client_schema(3)
