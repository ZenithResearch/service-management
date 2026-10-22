"""Durable first-service lifecycle from admitted intake to approved Runtime handoff.

The worker is intentionally narrow: it advances only Zenith's reviewed Anima
brand-package contract.  Each Service or Runtime command is retained before
native authority is acquired.  A lost outcome can therefore use only the exact
command and the explicit resume path.
"""

from __future__ import annotations

import base64
import hashlib
import json

from .client_intake import Intake, IntakeStore, ServiceCommandPort, UnknownAdmissionOutcome
from .contracts import canonical
from .errors import ServiceError
from .runtime_port import RuntimeCallError, RuntimeClient, content_digest, expected_run_id, pin


STAGES = (
    "request_admitted", "qualified", "accepted", "converted", "planned",
    "brief_stored", "references_stored", "approved",
)


def _stable(request_id: str, label: str) -> str:
    digest = hashlib.sha256((request_id + "\0" + label).encode("utf-8")).hexdigest()[:32]
    return f"provider-{label}-{digest}"


def _artifact(content: bytes) -> dict:
    return {"content_hash": hashlib.sha256(content).hexdigest(),
            "byte_length": len(content), "media_type": "application/json"}


class BrandPackageLifecycleWorker:
    """Advance one durable command per admitted request per invocation."""

    def __init__(self, store: IntakeStore, service: ServiceCommandPort,
                 runtime: RuntimeClient, process_pin: dict):
        self.store, self.service, self.runtime = store, service, runtime
        self.process_pin = pin(process_pin)
        if (self.process_pin["process_id"] != "zenith.anima.brand-package"
                or self.process_pin["process_version"] != "zenith.anima.brand-package-v1"):
            raise ValueError("exact brand-package process pin required")

    @staticmethod
    def _service_command(operation: str, command_id: str, kind: str,
                         resource_id: str, expected_version: int, payload: dict) -> dict:
        return {"schema": "service.command.v1", "operation": operation,
                "request_id": command_id, "resource": {"kind": kind, "id": resource_id},
                "expected_version": expected_version, "payload": payload}

    def _command(self, stage: str, intake: Intake) -> tuple[str, dict, str]:
        if (intake.provider_id != "zenith" or intake.service_id != "zenith.anima.brand-package"
                or intake.service_version != "1.0.0"):
            raise ServiceError("invalid_command")
        case_id = _stable(intake.request_id, "case")
        command_id = _stable(intake.request_id, stage.replace("_", "-"))
        if stage == "request_admitted":
            return "service", self._service_command(
                "request.qualify", command_id, "ServiceRequest", intake.request_id, 1,
                {"qualification": "Reviewed intake and Zenith membership accepted."}), "qualified"
        if stage == "qualified":
            return "service", self._service_command(
                "request.accept", command_id, "ServiceRequest", intake.request_id, 2,
                {"acceptance": "Accepted for the Zenith Anima brand-package service."}), "accepted"
        if stage == "accepted":
            return "service", self._service_command(
                "request.convert", command_id, "ServiceRequest", intake.request_id, 3,
                {"case_id": case_id, "obligation": "Deliver the reviewed brand-package workflow."}), "converted"
        if stage == "converted":
            return "service", self._service_command(
                "case.plan", command_id, "Case", case_id, 1,
                {"scope": "Execute the immutable Zenith Anima brand-package process from the reviewed brief and reference manifest."}), "planned"

        brief_content = canonical({"schema": "service.reviewed-brief.v1",
                                   "revision": intake.brief_revision,
                                   "content_hash": intake.brief_hash,
                                   "values": intake.values}).encode("utf-8")
        reference_content = canonical({"schema": "service.reference-manifest.v1",
                                       "references": json.loads(intake.references_json)}).encode("utf-8")
        brief_ref, reference_ref = _artifact(brief_content), _artifact(reference_content)
        if stage in {"planned", "brief_stored"}:
            content = brief_content if stage == "planned" else reference_content
            artifact = brief_ref if stage == "planned" else reference_ref
            label = "brief" if stage == "planned" else "references"
            command = self.runtime.new_command(
                "artifact.put", request_id=_stable(intake.request_id, label),
                expected_version=None,
                payload={"artifact": artifact,
                         "content_base64": base64.b64encode(content).decode("ascii")})
            return "runtime", command, "brief_stored" if stage == "planned" else "references_stored"
        if stage == "references_stored":
            organization = intake.values.get("organization_name")
            if not isinstance(organization, str) or not organization.strip():
                raise ServiceError("invalid_command")
            command = self._service_command(
                "case.plan.approve", command_id, "Case", case_id, 2,
                {"revision_id": _stable(intake.request_id, "revision"),
                 "reason": "Approved reviewed intake for the pinned Zenith Anima brand-package process.",
                 "pin": self.process_pin,
                 "inputs": {"organization_name": organization,
                            "reviewed_brief": brief_ref,
                            "reference_manifest": reference_ref},
                 "carry_forward": []})
            return "service", command, "approved"
        raise ServiceError("invalid_transition")

    @staticmethod
    def _validate_service(command: dict, result: dict, next_stage: str) -> None:
        if (not isinstance(result, dict) or result.get("schema") != "service.result.v1"
                or result.get("operation") != command["operation"]
                or result.get("request_id") != command["request_id"]):
            raise ServiceError("internal_error")
        if next_stage in {"qualified", "accepted"}:
            request = result.get("service_request")
            expected = {"qualified": ("qualified", 2), "accepted": ("accepted", 3)}[next_stage]
            if not isinstance(request, dict) or (request.get("state"), request.get("version")) != expected:
                raise ServiceError("internal_error")
        elif next_stage == "converted":
            request, case = result.get("service_request"), result.get("case")
            if (not isinstance(request, dict) or request.get("version") != 4
                    or not isinstance(case, dict) or case.get("state") != "open" or case.get("version") != 1):
                raise ServiceError("internal_error")
        elif next_stage == "planned":
            case = result.get("case")
            if not isinstance(case, dict) or case.get("state") != "planned" or case.get("version") != 2:
                raise ServiceError("internal_error")
        elif next_stage == "approved":
            case, handoff = result.get("case"), result.get("handoff")
            if (not isinstance(case, dict) or case.get("version") != 3
                    or not isinstance(handoff, dict) or handoff.get("state") != "pending"):
                raise ServiceError("internal_error")

    @staticmethod
    def _validate_runtime(command: dict, result: dict) -> None:
        artifact = command["payload"]["artifact"]
        if (not isinstance(result, dict) or result.get("schema") != "runtime.result.v1"
                or result.get("operation") != "artifact.put"
                or result.get("request_id") != command["request_id"]
                or result.get("resource") != command["resource"]
                or result.get("result") != {"artifact": artifact}
                or result.get("version") != 1 or type(result.get("duplicate")) is not bool):
            raise ServiceError("runtime_contract")

    def advance_once(self, *, limit: int = 16) -> list[dict]:
        return self._advance_once(limit=limit, recovery=False)

    def resume_once(self, *, limit: int = 16) -> list[dict]:
        return self._advance_once(limit=limit, recovery=True)

    def _advance_once(self, *, limit: int, recovery: bool) -> list[dict]:
        results = []
        for row in self.store.lifecycle_pending(limit=limit, recovery=recovery):
            intake = Intake.parse(row["intake_json"].encode("utf-8"))
            target, command, next_stage = self._command(row["stage"], intake)
            digest = self.store.retain_lifecycle_command(
                intake.request_id, row["stage"], target, command)
            retained = canonical(command)
            if recovery:
                if row["command_target"] != target or row["command_json"] != retained:
                    raise ServiceError("idempotency_conflict")
            else:
                if not self.store.begin_lifecycle_authority(
                        intake.request_id, row["stage"], digest):
                    continue
            try:
                if target == "service":
                    raw = retained.encode("utf-8")
                    result = self.service.resume(raw) if recovery else self.service.submit(raw)
                    self._validate_service(command, result, next_stage)
                else:
                    action = self.runtime.resume_command if recovery else self.runtime.command
                    result = action(json.loads(retained))
                    self._validate_runtime(command, result)
            except UnknownAdmissionOutcome:
                continue
            except RuntimeCallError as error:
                if error.retryable or error.uncertain:
                    continue
                raise ServiceError("runtime_rejected") from None
            self.store.complete_lifecycle_step(
                intake.request_id, row["stage"], next_stage, digest, result)
            completed = {"request_id": intake.request_id, "stage": next_stage}
            if next_stage == "approved":
                handoff = result["handoff"]
                identity = {"source": "service-management", "event_id": handoff["event_id"]}
                completed["activation"] = {
                    "handoff_id": content_digest(identity),
                    "run_id": expected_run_id(identity),
                }
            results.append(completed)
        return results
