"""Regenerate checked-in service and browser contracts from their definitions."""

import json
from pathlib import Path

from service_management.transport import transport_schema
from service_management.contracts import command_schema, error_schema, result_schema
from service_management.integration_schema import handoff_schema, query_schema, query_result_schema, revision_schema
from service_management.client_contract import client_schema, client_schema_v1, client_schema_v2, client_schema_v3
from service_management.castalia_gateway import gateway_reference_schema

root = Path(__file__).resolve().parents[1] / "contracts"
root.mkdir(parents=True, exist_ok=True)
for name, factory in [("transport", transport_schema), ("command", command_schema), ("result", result_schema), ("error", error_schema)]:
    (root / f"service.{name}.v1.schema.json").write_text(json.dumps(factory(), ensure_ascii=False, indent=2) + "\n")
for name, factory in [("runtime-handoff", handoff_schema), ("query", query_schema), ("query-result", query_result_schema), ("case-plan-revision", revision_schema)]:
    (root / f"service.{name}.v1.schema.json").write_text(json.dumps(factory(), ensure_ascii=False, indent=2) + "\n")
(root / "service.client.v1.schema.json").write_text(json.dumps(client_schema_v1(), ensure_ascii=False, indent=2) + "\n")
(root / "service.client.v2.schema.json").write_text(json.dumps(client_schema_v2(), ensure_ascii=False, indent=2) + "\n")
(root / "service.client.v3.schema.json").write_text(json.dumps(client_schema_v3(), ensure_ascii=False, indent=2) + "\n")
(root / "service.client.v4.schema.json").write_text(json.dumps(client_schema(), ensure_ascii=False, indent=2) + "\n")
(root / "gateway.reference-object.v1.schema.json").write_text(
    json.dumps(gateway_reference_schema(), ensure_ascii=False, indent=2) + "\n")
