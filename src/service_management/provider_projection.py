"""Authorized client projection over retained intake, Service and Runtime owners."""

from __future__ import annotations

import base64
import hashlib
from datetime import UTC, datetime

from .contracts import canonical, identifier
from .errors import ServiceError
from .runtime_port import RuntimeClient, content_digest, query_data, runtime_id


DELIVERABLES = {
    "brand_package": ("brand-package", "Brand package", "brand-package.md"),
    "deliverable_manifest": ("deliverable-manifest", "Deliverable manifest", "deliverable-manifest.json"),
    "quality_report": ("quality-report", "Quality report", "quality-report.md"),
}


def _time(milliseconds: int) -> str:
    if type(milliseconds) is not int or milliseconds < 0:
        raise ServiceError("runtime_contract")
    return datetime.fromtimestamp(milliseconds / 1000, UTC).isoformat(
        timespec="milliseconds").replace("+00:00", "Z")


class LocalProviderProjection:
    """Build one redacted browser view; underlying stores remain canonical."""

    def __init__(self, intakes, service_storage, runtime: RuntimeClient,
                 *, public_base_url: str | None = None, clock=lambda: datetime.now(UTC)):
        self.intakes, self.service_storage, self.runtime, self.clock = (
            intakes, service_storage, runtime, clock)
        if public_base_url is not None:
            from urllib.parse import urlsplit
            parsed = urlsplit(public_base_url)
            if (parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password
                    or parsed.path not in {"", "/"} or parsed.query or parsed.fragment
                    or public_base_url.endswith("/")):
                raise ValueError("invalid public projection origin")
        self.public_base_url = public_base_url or ""

    def _source(self, request_id: str, subject: str) -> dict:
        if not identifier(request_id) or not identifier(subject):
            raise ServiceError("forbidden")
        source = self.intakes.projection_source(request_id)
        if source is None:
            raise ServiceError("not_found")
        # The local projection opens only after requester verification and
        # Service admission have bound this exact Member Key subject.
        if source["requester_subject"] != subject:
            raise ServiceError("forbidden")
        return source

    def _service(self, request_id: str) -> dict:
        def read(tx):
            request = tx.get_request(request_id)
            if request is None:
                return {"request": None, "case": None, "handoff": None}
            case = tx.get_case(request.case_id) if request.case_id else None
            handoff = (tx.handoff_for_revision(case.current_plan_revision_id)
                       if case and case.current_plan_revision_id else None)
            return {"request": request, "case": case, "handoff": handoff}
        return self.service_storage.transact(read)

    def status(self, request_id: str, subject: str) -> dict:
        source = self._source(request_id, subject)
        intake = source["intake"]
        retained = self._service(request_id)
        request, case, handoff = retained["request"], retained["case"], retained["handoff"]
        execution = None
        deliverables, receipts = [], []
        if handoff and handoff.get("run_id"):
            try:
                run = query_data(self.runtime, "run.get", {"run_id": handoff["run_id"]})
                if (run.get("run_id") != handoff["run_id"]
                        or run.get("state") not in {"pending", "running", "blocked", "succeeded",
                                                    "failed", "cancelled"}
                        or not isinstance(run.get("steps"), list)):
                    raise ServiceError("runtime_contract")
                execution = {"run_id": handoff["run_id"], "state": run["state"],
                             "freshness": "current", "observed_at": self._now()}
                deliverables, receipts = self._delivery(request_id, run)
            except ServiceError as error:
                if error.code not in {"runtime_unavailable", "projection_gap"}:
                    raise
                execution = {"run_id": handoff["run_id"], "state": "unknown",
                             "freshness": "unavailable" if error.code == "runtime_unavailable" else "gap",
                             "observed_at": None}
        request_view = None if request is None else {
            "id": request.id, "state": request.state, "version": request.version,
            "case_id": request.case_id}
        case_view = None if case is None else {
            "id": case.id, "state": case.state, "version": case.version,
            "current_plan_revision_id": case.current_plan_revision_id}
        return {"schema": "service.client-projection.v1", "request_id": request_id,
                "idempotency_key": source["idempotency_key"],
                "provider_id": intake["service"]["provider_id"],
                "service_id": intake["service"]["service_id"],
                "transport": {"state": "consumed", "receipt": source["transport_receipt"]},
                "service_request": request_view, "case": case_view, "execution": execution,
                "deliverables": deliverables, "receipts": receipts,
                "updated_at": self._now(),
                "retry_after_ms": None if execution and execution["state"] in {"succeeded", "failed", "cancelled"} else 3000}

    def _delivery(self, request_id: str, run: dict) -> tuple[list[dict], list[dict]]:
        step = next((item for item in run.get("steps", [])
                     if item.get("step_id") == "package-deliverables"), None)
        if not isinstance(step, dict) or step.get("state") != "succeeded":
            return [], []
        attempt_id = step.get("attempt_id") or step.get("current_attempt")
        if not identifier(attempt_id):
            raise ServiceError("runtime_contract")
        output = query_data(self.runtime, "output.get", {
            "run_id": run["run_id"], "step_id": "package-deliverables",
            "attempt_id": attempt_id})
        if (not runtime_id(output.get("receipt_id"))
                or output.get("run_id") != run["run_id"]
                or output.get("step_id") != "package-deliverables"
                or output.get("attempt_id") != attempt_id):
            raise ServiceError("runtime_contract")
        values = output.get("outputs")
        if (not isinstance(values, dict) or set(values) != set(DELIVERABLES)
                or content_digest(values) != output.get("output_digest")):
            raise ServiceError("runtime_contract")
        receipt = query_data(self.runtime, "receipt.get", {"receipt_id": output["receipt_id"]})
        if (receipt.get("schema") != "runtime.receipt.v1"
                or receipt.get("receipt_id") != output["receipt_id"]
                or receipt.get("outcome") != "succeeded"
                or any(receipt.get(key) != output.get(key)
                       for key in ("run_id", "step_id", "attempt_id", "output_digest"))):
            raise ServiceError("runtime_contract")
        raw_receipt = canonical(receipt).encode("utf-8")
        receipt_reference = {
            "schema": "service.receipt-reference.v1", "owner": "process-runtime",
            "receipt_schema": receipt["schema"], "receipt_id": receipt["receipt_id"],
            "content_hash": hashlib.sha256(raw_receipt).hexdigest(),
            "recorded_at": _time(receipt["recorded_at_ms"]),
            "verification": {"state": "unverified", "verifier": None,
                             "detail": "Runtime receipt has no cryptographic author signature."},
            "href": self.public_base_url + f"/v1/client/requests/{request_id}/receipts/process-runtime/{receipt['receipt_id']}",
        }
        deliverables = []
        for name, (identifier_value, label, filename) in DELIVERABLES.items():
            artifact = values[name]
            if (not isinstance(artifact, dict)
                    or set(artifact) != {"content_hash", "byte_length", "media_type"}
                    or not isinstance(artifact["content_hash"], str)
                    or len(artifact["content_hash"]) != 64
                    or any(char not in "0123456789abcdef" for char in artifact["content_hash"])
                    or type(artifact["byte_length"]) is not int or artifact["byte_length"] < 0
                    or not isinstance(artifact["media_type"], str) or not artifact["media_type"]):
                raise ServiceError("runtime_contract")
            manifest = {"schema": "service.artifact-manifest.v1",
                        "artifact_id": identifier_value, **artifact, "filename": filename}
            deliverables.append({"id": identifier_value, "version": 1, "label": label,
                "artifact": manifest,
                "href": self.public_base_url + f"/v1/client/requests/{request_id}/artifacts/{artifact['content_hash']}",
                "receipt_ids": [receipt["receipt_id"]]})
        return deliverables, [receipt_reference]

    def artifact(self, request_id: str, content_hash: str, subject: str) -> tuple[str, bytes]:
        projection = self.status(request_id, subject)
        matched = next((item for item in projection["deliverables"]
                        if item["artifact"]["content_hash"] == content_hash), None)
        if matched is None:
            raise ServiceError("not_found")
        value = query_data(self.runtime, "artifact.get", {"content_hash": content_hash})
        if value.get("artifact") != {key: matched["artifact"][key]
                                      for key in ("content_hash", "byte_length", "media_type")}:
            raise ServiceError("runtime_contract")
        try:
            body = base64.b64decode(value["content_base64"], validate=True)
        except Exception:
            raise ServiceError("runtime_contract") from None
        if len(body) != matched["artifact"]["byte_length"] or hashlib.sha256(body).hexdigest() != content_hash:
            raise ServiceError("runtime_contract")
        return matched["artifact"]["media_type"], body

    def receipt(self, request_id: str, owner: str, receipt_id: str,
                subject: str) -> bytes:
        if owner != "process-runtime":
            raise ServiceError("not_found")
        projection = self.status(request_id, subject)
        matched = next((item for item in projection["receipts"]
                        if item["owner"] == owner and item["receipt_id"] == receipt_id), None)
        if matched is None:
            raise ServiceError("not_found")
        value = query_data(self.runtime, "receipt.get", {"receipt_id": receipt_id})
        body = canonical(value).encode("utf-8")
        if hashlib.sha256(body).hexdigest() != matched["content_hash"]:
            raise ServiceError("runtime_contract")
        return body

    def _now(self) -> str:
        value = self.clock()
        if not isinstance(value, datetime) or value.tzinfo is None:
            raise ServiceError("internal_error")
        return value.astimezone(UTC).isoformat(timespec="milliseconds").replace("+00:00", "Z")
