"""Optional independent JSON Schema validator, available with the public SDK."""

import json
import unittest
from pathlib import Path

try:
    from jsonschema import Draft202012Validator, FormatChecker
except ImportError:
    Draft202012Validator = None

from service_management.transport import transport_schema
from service_management.contracts import command_schema, error_schema, result_schema
from service_management.errors import ERRORS, ServiceError
from service_management.integration_schema import handoff_schema, query_schema, query_result_schema, revision_schema
import test_integration as fixtures

ROOT = Path(__file__).resolve().parents[1]
FACTORIES = {"transport": transport_schema, "command": command_schema, "error": error_schema, "result": result_schema, "query": query_schema,
             "query-result": query_result_schema, "case-plan-revision": revision_schema, "runtime-handoff": handoff_schema}


class ExportTests(unittest.TestCase):
    def test_checked_in_public_contracts_match_current_definitions(self):
        for name, factory in FACTORIES.items():
            with self.subTest(contract=name):
                self.assertEqual(json.loads((ROOT/f"contracts/service.{name}.v1.schema.json").read_text()), factory())

    def test_consumer_never_imports_runtime_implementation(self):
        import ast
        for path in (ROOT/"src/service_management").glob("*.py"):
            tree = ast.parse(path.read_text())
            modules = [node.module or "" for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
            modules += [alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names]
            self.assertFalse(any(name == "process_runtime" or name.startswith("process_runtime.") for name in modules), path.name)


@unittest.skipIf(Draft202012Validator is None, "jsonschema is supplied with the optional runtime SDK test environment")
class WireSchemaTests(unittest.TestCase):
    def test_independent_schemas_accept_real_service_results_revisions_queries_and_errors(self):
        validators = {}
        for name, factory in FACTORIES.items():
            schema = factory(); Draft202012Validator.check_schema(schema)
            validators[name] = Draft202012Validator(schema, format_checker=FormatChecker())
        fixture = fixtures.ServiceIntegrationTests(); fixture.setUp(); self.addCleanup(fixture.doCleanups)
        approved = fixture.approve()
        validators["command"].validate(json.loads(fixture.approval()))
        validators["result"].validate(approved)
        validators["case-plan-revision"].validate(approved["plan_revision"])
        stored = fixture.store.transact(lambda tx: tx.get_handoff(approved["handoff"]["event_id"]))
        validators["runtime-handoff"].validate(stored["command"]["payload"])
        for raw in [fixtures.query("request.execution", "request-1"), fixtures.query("case.summary"), fixtures.query("case.plan-history", payload={"after_revision": 0, "limit": 100})]:
            validators["query"].validate(json.loads(raw))
            validators["query-result"].validate(fixture.service.query(raw))
        started = fixture.delivery.reconcile(approved["handoff"]["event_id"])
        selection = fixture.runtime.commit_output(started["run_id"])
        pin2 = fixture.runtime.publish("inspection-v2", {"evidence": {"kind": "string"}})
        raw = fixture.revised(started["run_id"], pin2, selection)
        validators["command"].validate(json.loads(raw))
        result = fixture.service.execute(raw)
        validators["result"].validate(result)
        validators["case-plan-revision"].validate(result["plan_revision"])
        for code in ERRORS:
            validators["error"].validate(ServiceError(code).envelope())
