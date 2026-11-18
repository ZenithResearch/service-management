"""Qualification of read-only projections against real service records and retries."""

from copy import deepcopy
from importlib.resources import files
from pathlib import Path
import shutil
import socket
import tempfile
import unittest
from unittest.mock import patch

from jsonschema import ValidationError
from referencing.exceptions import Unresolvable

from service_management.zenith_projection import ZN, ZenithProjections, ontology_sources
from service_management.sqlite_store import SQLiteUnitOfWork
import service_management.zenith_projection as module

import test_integration as integration
from test_integration import query

CONTENT_SCHEMA = {
    "$id": "urn:example:service-plan:v1",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object", "additionalProperties": False,
    "properties": {
        "objective": {"type": "string", "minLength": 1},
        "actions": {"type": "array", "minItems": 1,
                    "items": {"type": "string", "minLength": 1}},
    },
    "required": ["objective", "actions"],
}


class ZenithProjectionTests(unittest.TestCase):
    def setUp(self):
        self.fixture = integration.ServiceIntegrationTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.adapter = ZenithProjections(
            "urn:example:sai-service:",
            entity_iris={"local-dev-untrusted": "urn:example:person:planner"},
            content_schemas=[CONTENT_SCHEMA],
        )

    def content(self, revision_id="revision-1", case_id="case-1"):
        return {"id": f"urn:example:retained-plan:{revision_id}",
                "caseId": case_id, "revisionId": revision_id,
                "schema": CONTENT_SCHEMA["$id"],
                "value": {"objective": "Complete the inspection",
                          "actions": ["Inspect the site", "Record findings", "Report the result"]}}

    def test_pinned_sources_resolve_only_request_management_and_core_offline(self):
        with patch.object(socket, "socket", side_effect=AssertionError("network prohibited")):
            source = ontology_sources()
        self.assertTrue(source["closureVerified"])
        self.assertEqual(source["version"], "0.1.0")
        self.assertEqual(source["gitCommit"], "4a5e54d744c0b1ed0e4dc5750ad98eb52dd11bc2")
        self.assertEqual(len(source["imports"]), 2)

    def test_imported_parent_paths_and_application_schema_ownership(self):
        _, _, documents, _ = module._resources()
        parents = {node["@id"]: node["subClassOf"]
                   for document in documents.values() for node in document["@graph"]
                   if "subClassOf" in node}
        self.assertEqual(parents["zn:Request"], "zn:Artifact")
        self.assertEqual(parents["zn:CasePlan"], "zn:Artifact")
        self.assertEqual(parents["zn:Case"], "owl:Thing")
        self.assertNotIn("ServiceRuntimeHandoff", parents)
        self.assertNotIn("ServiceOutbox", parents)
        from service_management.integration_schema import handoff_schema, revision_schema
        self.assertEqual(handoff_schema()["$id"], "urn:service-management:runtime-handoff:v1")
        self.assertEqual(revision_schema()["properties"]["schema"]["const"],
                         "service.case-plan-revision.v1")

    def test_request_projects_existing_authorized_result_without_inventing_participants(self):
        record = self.fixture.store.transact(lambda tx: tx.get_request("request-1"))
        result = self.adapter.request(record)
        self.assertEqual(result, {
            "id": "urn:example:sai-service:requests/request-1",
            "type": ZN + "Request", "label": record.summary,
            "requestedOutcome": record.summary,
        })
        self.assertEqual(result, self.adapter.request(record.as_dict()))

    def test_explicit_request_participants_and_instance_scoped_identity(self):
        record = self.fixture.store.transact(lambda tx: tx.get_request("request-1"))
        result = self.adapter.request(record, requester="urn:example:person:requester",
                                      recipient="urn:example:org:sai")
        self.assertEqual(result["requester"], "urn:example:person:requester")
        self.assertNotEqual(result["id"], ZenithProjections("urn:example:other:").request(record)["id"])
        with self.assertRaises(ValueError):
            self.adapter.request(record, requester="local-subject")

    def test_case_is_a_handling_context_and_has_no_synthetic_plan(self):
        self.fixture.seed_case()
        record = self.fixture.store.transact(lambda tx: tx.get_case("case-1"))
        result = self.adapter.case(record)
        self.assertEqual(result["type"], ZN + "Case")
        self.assertEqual(result["requests"], ["urn:example:sai-service:requests/request-1"])
        self.assertEqual(result, self.adapter.case(record.as_dict()))
        self.assertIsNone(self.adapter.plan_selection(record)["currentApprovedPlan"])

    def test_case_plan_uses_one_class_and_preserves_complete_typed_snapshot(self):
        approval = self.fixture.approve()["plan_revision"]
        content = self.content()
        original = deepcopy(content)
        result = self.adapter.case_plan(approval, retained_content=content)
        self.assertEqual(result["type"], "zn:CasePlan")
        self.assertEqual(result["revision"]["revisionNumber"], 1)
        self.assertEqual(result["revision"]["createdBy"], "urn:example:person:planner")
        self.assertEqual(result["content"]["value"], original["value"])
        self.assertEqual(result["sourceEvidence"], [
            "urn:example:sai-service:plan-approvals/revision-1", original["id"]])
        result["content"]["value"]["actions"].append("Change only this output")
        self.assertEqual(content, original)
        self.assertNotIn("previousRevision", result["revision"])

    def test_approval_pin_and_scope_cannot_substitute_for_complete_plan_content(self):
        approval = self.fixture.approve()["plan_revision"]
        for content in (None, {}, approval,
                        {"schema": CONTENT_SCHEMA["$id"], "value": {"scope": "Inspect"}}):
            with self.subTest(content=content):
                with self.assertRaises(ValidationError):
                    self.adapter.case_plan(approval, retained_content=content)

    def test_content_is_bound_to_its_exact_case_and_revision(self):
        approval = self.fixture.approve()["plan_revision"]
        for revision_id, case_id in (("revision-2", "case-1"), ("revision-1", "other-case")):
            with self.subTest(revision=revision_id, case=case_id):
                with self.assertRaisesRegex(ValueError, "different Case or revision"):
                    self.adapter.case_plan(approval, retained_content=self.content(revision_id, case_id))

    def test_content_is_validated_against_an_explicit_registered_schema(self):
        approval = self.fixture.approve()["plan_revision"]
        content = self.content()
        content["value"]["actions"] = []
        with self.assertRaises(ValidationError):
            self.adapter.case_plan(approval, retained_content=content)
        content["schema"] = "urn:example:unregistered:v1"
        with self.assertRaisesRegex(ValueError, "registered explicitly"):
            self.adapter.case_plan(approval, retained_content=content)

    def test_author_mapping_is_required_and_does_not_promote_provider_subjects(self):
        approval = self.fixture.approve()["plan_revision"]
        unmapped = ZenithProjections("urn:example:service:", content_schemas=[CONTENT_SCHEMA])
        with self.assertRaisesRegex(ValueError, "explicit Entity IRI mapping"):
            unmapped.case_plan(approval, retained_content=self.content())

    def test_unknown_schema_references_fail_without_network_retrieval(self):
        schema = deepcopy(CONTENT_SCHEMA)
        schema["properties"]["objective"] = {"$ref": "https://unconfigured.example/schema.json"}
        with patch.object(socket, "socket", side_effect=AssertionError("network prohibited")):
            adapter = ZenithProjections("urn:example:offline:", content_schemas=[schema],
                                        entity_iris=self.adapter.entity_iris)
            approval = self.fixture.approve()["plan_revision"]
            with self.assertRaises(Exception) as raised:
                adapter.case_plan(approval, retained_content=self.content())
        self.assertIsInstance(raised.exception.__cause__, Unresolvable)

    def test_invalid_retained_references_and_revision_timestamps_are_rejected(self):
        approval = self.fixture.approve()["plan_revision"]
        content = self.content()
        content["id"] = "urn:example:invalid reference"
        with self.assertRaises(ValidationError):
            self.adapter.case_plan(approval, retained_content=content)
        for timestamp in ("not-a-date", "2026-01-01T00:00:00", "2026-02-30T00:00:00Z"):
            with self.subTest(timestamp=timestamp), self.assertRaises(ValidationError):
                self.adapter.case_plan({**approval, "created_at": timestamp},
                                       retained_content=self.content())

    def test_namespace_and_schema_identity_validation(self):
        for namespace in ("not-an-iri", "https://example.org/service", "urn:example:bad value:",
                          "https://example.org/?tenant=1/"):
            with self.subTest(namespace=namespace), self.assertRaises(ValueError):
                ZenithProjections(namespace)
        schema = deepcopy(CONTENT_SCHEMA)
        for schema_id in (module.SCHEMA_ROOT + "case-plan.schema.json",
                          "urn:service-management:ontology-projections:v1"):
            schema["$id"] = schema_id
            with self.subTest(schema_id=schema_id), self.assertRaisesRegex(ValueError, "distinct"):
                ZenithProjections("urn:example:service:", content_schemas=[schema])

    def test_selection_requires_the_exact_approved_plan_and_not_a_draft(self):
        result = self.fixture.approve()
        plan = self.adapter.case_plan(result["plan_revision"], retained_content=self.content())
        selection = self.adapter.plan_selection(result["case"], plan)
        self.assertEqual(selection["currentApprovedPlan"], plan["id"])
        wrong = deepcopy(plan)
        wrong["id"] = self.adapter.iri("case-plans", "draft")
        with self.assertRaises(ValueError):
            self.adapter.plan_selection(result["case"], wrong)
        with self.assertRaises(ValidationError):
            self.adapter.plan_selection(result["case"])

    def test_revision_supersession_and_original_run_are_independent(self):
        result = self.fixture.approve()
        first = self.adapter.case_plan(result["plan_revision"], retained_content=self.content())
        self.fixture.delivery.reconcile(result["handoff"]["event_id"])
        handoff = self.fixture.store.transact(lambda tx: tx.get_handoff(result["handoff"]["event_id"]))
        run_id = handoff["run_id"]
        replacement = self.fixture.service.execute(self.fixture.revised(run_id, self.fixture.pin))
        second = self.adapter.case_plan(replacement["plan_revision"],
                                        retained_content=self.content("revision-2"))
        supersession = self.adapter.supersession(first, second, approval=replacement["plan_revision"])
        self.assertEqual(supersession["olderVersion"], first["id"])
        self.assertEqual(supersession["replacementVersion"], second["id"])
        self.assertEqual(second["revision"]["previousRevision"], first["id"])
        self.assertEqual(self.fixture.runtime.runs[run_id]["state"], "pending")
        self.assertEqual(first, self.adapter.case_plan(result["plan_revision"],
                                                     retained_content=self.content()))
        self.assertEqual(self.adapter.plan_selection(replacement["case"], second)["currentApprovedPlan"],
                         second["id"])
        with self.assertRaises(ValueError):
            self.adapter.supersession(second, first, approval=result["plan_revision"])
        tampered = deepcopy(second)
        tampered["revision"]["createdBy"] = "urn:example:person:other"
        with self.assertRaises(ValueError):
            self.adapter.supersession(first, tampered, approval=replacement["plan_revision"])

    def test_legacy_reopen_idempotent_replay_and_app_handoff_bytes_are_unchanged(self):
        result = self.fixture.approve()
        before = deepcopy(result)
        store = SQLiteUnitOfWork(self.fixture.path)
        service = self.fixture.make_service(store)
        history_before = service.query(query("case.plan-history", payload={"after_revision": 0, "limit": 100}))
        event_id = result["handoff"]["event_id"]
        handoff_before = store.transact(lambda tx: tx.get_handoff(event_id))
        request = store.transact(lambda tx: tx.get_request("request-1"))
        self.adapter.request(request)
        self.adapter.case(result["case"])
        self.adapter.case_plan(result["plan_revision"], retained_content=self.content())
        self.assertEqual(service.execute(self.fixture.approval()), before)
        self.assertEqual(service.query(query("case.plan-history", payload={"after_revision": 0, "limit": 100})),
                         history_before)
        self.assertEqual(store.transact(lambda tx: tx.get_handoff(event_id)), handoff_before)

    def test_tampered_vendored_schema_is_rejected_before_projection(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            shutil.copytree(files("service_management").joinpath("ontology"), root / "ontology")
            schema = root / "ontology/zenith-v0.1.0/schemas/case-plan.schema.json"
            schema.write_text("{}")
            with patch.object(module, "files", return_value=root):
                with self.assertRaisesRegex(ValueError, "file integrity"):
                    ontology_sources()
