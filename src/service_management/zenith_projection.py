"""Read-only normalized Zenith projections of already authorized service records."""

from datetime import datetime
import hashlib
from importlib.resources import files
import json
import re

from jsonschema import Draft202012Validator, FormatChecker
from referencing import Registry, Resource
from referencing.exceptions import NoSuchResource

from .contracts import canonical, identifier
from .domain import Case, ServiceRequest
from .integration_schema import revision_schema

ZN = "https://zenith-research.ca/ontology/terms/"
DIALECT = "https://json-schema.org/draft/2020-12/schema"
SCHEMA_ROOT = "https://zenith-research.ca/ontology/normalized/v0.1.0/schemas/"
FORMAT_CHECKER = FormatChecker()


def _iri(value):
    if not isinstance(value, str) or re.fullmatch(r'[A-Za-z][A-Za-z0-9+.-]*:[^\s<>"{}|\\^\x60]+', value) is None:
        raise ValueError("An absolute IRI is required")
    value.encode("utf-8")
    return value


@FORMAT_CHECKER.checks("iri", raises=(ValueError, UnicodeError))
@FORMAT_CHECKER.checks("uri", raises=(ValueError, UnicodeError))
def _absolute_reference(value):
    return not isinstance(value, str) or bool(_iri(value))


@FORMAT_CHECKER.checks("date-time", raises=ValueError)
def _timestamp(value):
    if not isinstance(value, str):
        return True
    if re.fullmatch(r"\d{4}-\d{2}-\d{2}[Tt]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:[Zz]|[+-]\d{2}:\d{2})", value) is None:
        return False
    parsed = datetime.fromisoformat(value.replace("t", "T").replace("z", "Z"))
    return parsed.utcoffset() is not None


def _offline(uri):
    raise NoSuchResource(ref=uri)


def _resources():
    root = files("service_management").joinpath("ontology")
    lock = json.loads(root.joinpath("zenith.lock.json").read_bytes())
    upstream = root.joinpath("zenith-v0.1.0")
    manifest_bytes = upstream.joinpath("manifest.json").read_bytes()
    if hashlib.sha256(manifest_bytes).hexdigest() != lock["manifestSha256"]:
        raise ValueError("Pinned Zenith manifest integrity mismatch")
    manifest = json.loads(manifest_bytes)
    records = "".join(f"{entry['sha256']}  {entry['path']}\n" for entry in manifest["files"])
    if hashlib.sha256(records.encode()).hexdigest() != lock["bundleDigest"]:
        raise ValueError("Pinned Zenith bundle digest mismatch")
    upstream_hashes = {entry["path"]: entry["sha256"] for entry in manifest["files"]}
    schemas, documents = {}, {}
    for path in lock["vendoredFiles"]:
        contents = upstream.joinpath(path).read_bytes()
        if hashlib.sha256(contents).hexdigest() != upstream_hashes[path]:
            raise ValueError("Pinned Zenith file integrity mismatch")
        document = json.loads(contents)
        if path.startswith("schemas/"):
            schemas[document["$id"]] = document
        else:
            header, = (node for node in document["@graph"] if node["@type"] == "owl:Ontology")
            documents[header["versionIRI"]] = document
    for document in documents.values():
        header, = (node for node in document["@graph"] if node["@type"] == "owl:Ontology")
        if any(dependency not in documents for dependency in header.get("imports", [])):
            raise ValueError("Unresolved pinned Zenith import")
    adoption = json.loads(root.joinpath("adoption.jsonld").read_bytes())
    if (adoption["@type"] != "owl:Ontology"
            or adoption["imports"] != ["https://zenith-research.ca/ontology/normalized/v0.1.0/modules/request-management.jsonld"]
            or any(dependency not in documents for dependency in adoption["imports"])):
        raise ValueError("Unresolved Service Management adoption import")
    return lock, schemas, documents, json.loads(root.joinpath("projections.schema.json").read_bytes())


def ontology_sources():
    """Verify the packaged, pinned Request Management/Core closure offline."""
    lock, _, documents, _ = _resources()
    return {**lock, "closureVerified": True, "imports": sorted(documents)}


class ZenithProjections:
    """Project supplied snapshots without reading storage or changing service state.

    The caller supplies records obtained through an authorized service boundary.
    Keep namespace and identity mappings stable for the owning Service instance.
    Retain complete plan content independently before requesting its projection.
    """

    def __init__(self, namespace: str, *, entity_iris=None, content_schemas=()):
        self.namespace = _iri(namespace)
        if not namespace.endswith(("/", ":")) or "?" in namespace or "#" in namespace:
            raise ValueError("The instance namespace must end in / or : and have no query or fragment")
        self.entity_iris = {subject: _iri(iri) for subject, iri in (entity_iris or {}).items()}
        self.sources, schemas, _, self.schema = _resources()
        self.content_schemas = set()
        for document in content_schemas:
            document = json.loads(canonical(document))
            schema_id = _iri(document["$id"])
            if schema_id in schemas or schema_id == self.schema["$id"] or document.get("$schema") != DIALECT:
                raise ValueError("Plan content needs a distinct Draft 2020-12 schema identity")
            Draft202012Validator.check_schema(document)
            schemas[schema_id] = document
            self.content_schemas.add(schema_id)
        schemas[self.schema["$id"]] = self.schema
        self.registry = Registry(retrieve=_offline).with_resources(
            (uri, Resource.from_contents(document)) for uri, document in schemas.items()
        )

    def _validate(self, value, schema):
        Draft202012Validator(schema, registry=self.registry, format_checker=FORMAT_CHECKER).validate(value)

    def _shared(self, value, filename, definition):
        self._validate(value, {"$ref": f"{SCHEMA_ROOT}{filename}.schema.json#/$defs/{definition}"})
        return value

    def _local(self, value, definition):
        self._validate(value, {"$ref": f"{self.schema['$id']}#/$defs/{definition}"})
        return value

    def iri(self, kind, local_id):
        if kind not in {"requests", "cases", "case-plans", "plan-approvals"} or not identifier(local_id):
            raise ValueError("A known projection kind and service identifier are required")
        return f"{self.namespace}{kind}/{local_id}"

    def request(self, record, *, requester=None, recipient=None):
        """Export RequestCore with optional explicit participant mappings."""
        record = record if isinstance(record, ServiceRequest) else ServiceRequest(**record)
        result = {"id": self.iri("requests", record.id), "type": ZN + "Request",
                  "label": record.summary, "requestedOutcome": record.summary}
        if requester is not None:
            result["requester"] = _iri(requester)
        if recipient is not None:
            result["recipient"] = _iri(recipient)
        return self._shared(result, "request", "RequestCore")

    def case(self, record):
        """Export a Case handling context linked to its originating Request."""
        record = record if isinstance(record, Case) else Case(**record)
        return self._local({"id": self.iri("cases", record.id), "type": ZN + "Case",
                            "requests": [self.iri("requests", record.service_request_id)]}, "Case")

    def _revision(self, approval):
        self._validate(approval, revision_schema())
        creator = self.entity_iris.get(approval["author"])
        if creator is None:
            raise ValueError("The approval author needs an explicit Entity IRI mapping")
        revision = {"revisionNumber": approval["revision_number"], "createdBy": creator,
                    "createdAt": approval["created_at"], "changeReason": approval["reason"]}
        if approval["prior_revision_id"] is not None:
            revision["previousRevision"] = self.iri("case-plans", approval["prior_revision_id"])
        return revision

    def case_plan(self, approval, *, retained_content):
        """Export an immutable CasePlan using complete, explicitly typed content.

        retained_content binds the content's own evidence IRI and exact source
        Case/revision IDs. The configured content schema defines completeness.
        A pin, scope string or approval record alone cannot satisfy this input.
        """
        approval = json.loads(canonical(approval))
        revision = self._revision(approval)
        content = json.loads(canonical(retained_content))
        self._local(content, "RetainedPlanContent")
        if content["caseId"] != approval["case_id"] or content["revisionId"] != approval["id"]:
            raise ValueError("Retained plan content belongs to a different Case or revision")
        if content["schema"] not in self.content_schemas:
            raise ValueError("The complete plan content schema must be registered explicitly")
        self._validate(content["value"], {"$ref": content["schema"]})
        result = {
            "id": self.iri("case-plans", approval["id"]), "type": "zn:CasePlan",
            "case": self.iri("cases", approval["case_id"]), "revision": revision,
            "content": {"schema": content["schema"], "value": content["value"]},
            "sourceEvidence": [self.iri("plan-approvals", approval["id"]), _iri(content["id"])],
        }
        return self._shared(result, "case-plan", "CasePlan")

    def plan_selection(self, record, current_plan=None):
        """Project approval state separately from immutable plan content."""
        record = record if isinstance(record, Case) else Case(**record)
        result = {"case": self.iri("cases", record.id), "currentApprovedPlan": None}
        if record.current_plan_revision_id is not None:
            self._shared(current_plan, "case-plan", "CasePlan")
            if (current_plan["id"] != self.iri("case-plans", record.current_plan_revision_id)
                    or current_plan["case"] != result["case"]):
                raise ValueError("Current plan does not match the Case's approved revision")
            result.update(currentApprovedPlan=current_plan["id"],
                          approvalEvidence=[self.iri("plan-approvals", record.current_plan_revision_id)])
        elif current_plan is not None:
            raise ValueError("The Case has no approved plan")
        return self._shared(result, "case-plan", "CasePlanSelection")

    def supersession(self, previous, replacement, *, approval):
        """Assert only a directly approved replacement, independently of runs."""
        revision = self._revision(approval)
        self._shared(previous, "case-plan", "CasePlan")
        self._shared(replacement, "case-plan", "CasePlan")
        if (previous["case"] != replacement["case"]
                or replacement["case"] != self.iri("cases", approval["case_id"])
                or replacement["id"] != self.iri("case-plans", approval["id"])
                or previous["id"] != self.iri("case-plans", approval["prior_revision_id"])
                or replacement["revision"] != revision
                or replacement["revision"]["revisionNumber"] != previous["revision"]["revisionNumber"] + 1):
            raise ValueError("Supersession requires the same Case and its directly approved replacement")
        return self._shared(
            {"olderVersion": previous["id"], "replacementVersion": replacement["id"],
             "approvalEvidence": [self.iri("plan-approvals", approval["id"])]},
            "case-plan", "Supersession",
        )
