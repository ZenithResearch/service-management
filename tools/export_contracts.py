"""Regenerate checked-in v1 contracts from the package's contract definitions."""

import json
from pathlib import Path

from service_management.transport import transport_schema
from service_management.contracts import command_schema, error_schema, result_schema
from service_management.integration_schema import handoff_schema, query_schema, query_result_schema, revision_schema

root = Path(__file__).resolve().parents[1] / "contracts"
root.mkdir(parents=True, exist_ok=True)
for name, factory in [("transport", transport_schema), ("command", command_schema), ("result", result_schema), ("error", error_schema)]:
    (root / f"service.{name}.v1.schema.json").write_text(json.dumps(factory(), ensure_ascii=False, indent=2) + "\n")
for name, factory in [("runtime-handoff", handoff_schema), ("query", query_schema), ("query-result", query_result_schema), ("case-plan-revision", revision_schema)]:
    (root / f"service.{name}.v1.schema.json").write_text(json.dumps(factory(), ensure_ascii=False, indent=2) + "\n")
