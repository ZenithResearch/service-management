"""Check a wheel-installed projection adapter outside its checkout and offline."""

import argparse
import json
from pathlib import Path
import subprocess
import tempfile


def qualify(python):
    program = """
import json, socket, sys
from pathlib import Path
def denied(*args, **kwargs):
    raise AssertionError("ontology projection attempted network access")
socket.socket = denied
socket.create_connection = denied
import service_management
from service_management import Case, ServiceRequest, ZenithProjections, ontology_sources
assert Path(service_management.__file__).is_relative_to(Path(sys.prefix))
sources = ontology_sources()
assert sources["closureVerified"] is True
assert sources["gitCommit"] == "4a5e54d744c0b1ed0e4dc5750ad98eb52dd11bc2"
content_schema = {
    "$id": "urn:example:plan-content:v1",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "properties": {"actions": {"type": "array", "minItems": 1,
                               "items": {"type": "string", "minLength": 1}}},
    "required": ["actions"], "additionalProperties": False,
}
adapter = ZenithProjections("urn:example:installed-service:",
    entity_iris={"planner": "urn:example:person:planner"},
    content_schemas=[content_schema])
record = ServiceRequest("request-1", "Inspect the site", "", "intake", 1,
                        "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z")
projected = adapter.request(record)
assert projected["type"] == "https://zenith-research.ca/ontology/terms/Request"
assert projected["id"] == "urn:example:installed-service:requests/request-1"
case_record = Case("case-1", "request-1", "Inspect the site", "planned", 2,
                   "2026-01-01T00:00:00Z", "2026-01-01T00:00:00Z", plan_scope="Inspect")
case = adapter.case(case_record)
assert case["type"] == "https://zenith-research.ca/ontology/terms/Case"
pin = {"process_id": "inspection", "process_version": "version-1", "compilation_hash": "0" * 64}
approval = {
    "schema": "service.case-plan-revision.v1", "id": "revision-1", "case_id": "case-1",
    "revision_number": 1, "reason": "Approved", "author": "planner",
    "authority_mode": "verified_call", "created_at": "2026-01-01T00:00:00Z",
    "command_id": "approval-1", "case_version_before": 2,
    "prior_revision_id": None, "prior_pin": None, "new_pin": pin,
    "superseded_run_id": None, "inputs": {}, "carry_forward": [],
}
content = {"id": "urn:example:retained:revision-1", "caseId": "case-1",
           "revisionId": "revision-1", "schema": content_schema["$id"],
           "value": {"actions": ["Inspect", "Record", "Report"]}}
plan = adapter.case_plan(approval, retained_content=content)
assert plan["type"] == "zn:CasePlan" and plan["case"] == case["id"]
print(json.dumps({"version": sources["version"], "offlineClosureVerified": True,
                  "installedProjections": ["Request", "Case", "CasePlan"]}))
"""
    with tempfile.TemporaryDirectory(prefix="service-installed-ontology-") as directory:
        result = subprocess.check_output([str(python), "-B", "-I", "-c", program],
                                         cwd=directory, text=True, timeout=30)
    return json.loads(result)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--python", type=Path, required=True)
    args = parser.parse_args()
    print(json.dumps(qualify(args.python.absolute()), sort_keys=True))
