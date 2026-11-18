# Normalized Zenith projections

Service Management adopts Zenith normalized 0.1.0 at commit
`4a5e54d744c0b1ed0e4dc5750ad98eb52dd11bc2`.
`service_management.ZenithProjections` is the public read-only Python adapter.
Call it with snapshots already obtained through an authorized Service boundary.

## Ownership and inheritance

| Service record | Shared projection | Full parent path |
| --- | --- | --- |
| ServiceRequest | zn:Request | owl:Thing → zn:Artifact → zn:Request |
| Case | zn:Case | owl:Thing → zn:Case |
| Complete retained version of the Case's plan | zn:CasePlan | owl:Thing → zn:Artifact → zn:CasePlan |

The packaged adoption document imports the exact Request Management module,
which imports the same release's Core module. The lock records the upstream
commit, release-archive digest, canonical bundle digest and selected file hashes.
`ontology_sources()` verifies these packaged files and their import closure.
The schema registry resolves the packaged schemas and explicitly registered
content schemas offline.

ServiceRuntimeHandoff, ServiceOutbox entries, delivery attempts,
RuntimeProgressProjection and the approval/pin record
`service.case-plan-revision.v1` remain application-owned contracts.
The projections read existing records. The owning service retains their original
fields, current lifecycle, command results, authority evidence and retry intent.

## Stable identities and participants

Configure a persistent namespace for each independent Service instance.
Keep that namespace unchanged when moving a deployment.

```python
from service_management import ZenithProjections, ontology_sources

sources = ontology_sources()
projector = ZenithProjections("urn:example:sai-service:")
request = projector.request(
    authorized_result["request"],
    requester="urn:example:person:requester",
    recipient="urn:example:organization:sai",
)
case = projector.case(authorized_result["case"])
```

An existing request's ID becomes
`urn:example:sai-service:requests/<source-id>`. Cases, immutable plan versions and
approval evidence use distinct paths beneath the same namespace.
The Request projection uses the source summary as its label and requested
outcome. Details and service lifecycle evidence remain in the source record.

Request projections validate against upstream RequestCore. Requester and
recipient references are optional in this adapter. Supply actual mapped
participant IRIs when available. A submission workflow that requires
RequestSubmission must additionally validate those required participant fields.
An approval author's provider-local subject requires an explicit Entity IRI
mapping before it can become revision.createdBy.

## Complete CasePlan versions

The existing approval record retains approval identity, author, reason, timestamp,
process pins, typed inputs and carry-forward evidence. Complete retained plan
content is an additional input to the projection. The caller selects a
version-specific content schema, defines completeness for its planning workflow,
validates and retains the complete snapshot, and binds it to the exact Case and
approved revision.

```python
plan_schema = {
    "$id": "urn:example:sai-plan-content:v1",
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "type": "object",
    "properties": {
        "objective": {"type": "string", "minLength": 1},
        "actions": {
            "type": "array", "minItems": 1,
            "items": {"type": "string", "minLength": 1},
        },
    },
    "required": ["objective", "actions"],
    "additionalProperties": False,
}
projector = ZenithProjections(
    "urn:example:sai-service:",
    entity_iris={"planner-subject": "urn:example:person:planner"},
    content_schemas=[plan_schema],
)
retained_content = {
    "id": "urn:example:retained-plan:revision-1",
    "caseId": "case-1",
    "revisionId": "revision-1",
    "schema": plan_schema["$id"],
    "value": {
        "objective": "Inspect the site and report findings",
        "actions": ["Inspect the site", "Record findings", "Report the result"],
    },
}
plan = projector.case_plan(
    authorized_approval["plan_revision"],
    retained_content=retained_content,
)
selection = projector.plan_selection(authorized_approval["case"], plan)
```

These examples use synthetic identities and a deliberately small content schema.
A real planning workflow must define and retain all of its applicable planning
information under an immutable schema identity. Evidence references preserve the
source approval and retained content identities. The application remains
responsible for resolving these logical references to retained records.

Every emitted version has type zn:CasePlan. Its revision profile carries the
revision number, mapped creator, timestamp, reason and known immediate predecessor.
The upstream CasePlan schema requires the compact type value `zn:CasePlan`.
Request and Case use full term IRIs in their projection schemas.

## Approval selection and supersession

`plan_selection(case, current_plan)` requires the projected version that matches
the Case's current approved revision. A Case awaiting approval has a null selection.

`supersession(previous, replacement, approval=approved_revision)` requires two
projected versions of the same Case, consecutive revision numbers, and the
replacement approval's exact predecessor. It returns the upstream Supersession
relationship schema. Its semantic edge is
`older-version zn:supersededBy approved-replacement`.

Selection and supersession sit outside immutable plan content. The earlier plan,
its source approval, prior pin and runtime run remain individually identifiable.
The service's existing explicit Runtime cancellation operation controls any run
cancellation.

## Existing records and verification

Existing requests, Cases, approval histories and saved command results load
through the current application contracts. Historical approvals become eligible
for CasePlan projection after complete retained content and the author mapping
are supplied. The adapter rejects unavailable content, unknown schemas,
cross-Case content, mismatched revisions and unresolved schema references.

Run the full suite with the CI-pinned public Runtime SDK installed.

```sh
PYTHONPATH=src python -m unittest discover -s tests -v
cd clients/typescript
npm ci
npm test
npm run typecheck
```

`tools/qualify_ontology_install.py --python /absolute/path/to/wheel-venv/bin/python`
checks an installed wheel from a temporary directory with socket access denied.
