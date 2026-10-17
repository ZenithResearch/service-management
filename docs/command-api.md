# Service command API v1

`POST /v1/commands` accepts UTF-8 JSON with `Content-Type: application/json` and
one `Content-Length`. A direct command body is bounded to 65536 bytes. The optional
[service.transport.v1](../contracts/service.transport.v1.schema.json) body carries
the same command plus strict canonical `authority_base64`; it is bounded to
786786 bytes, with decoded evidence at most 295127 bytes and the inner command
at most 65536 bytes. Header and body evidence cannot be combined. See [transport budgets](transport-budgets.md) for exact Packet, escaping, helper and bounded HTTP admission limits.
Chunked encoding, compressed bodies,
duplicate JSON keys, non-finite numbers, invalid Unicode, NUL-containing
payload strings, unknown fields, and unknown operations are rejected. No Unicode
normalization is applied. The command schema is
[service.command.v1.schema.json](../contracts/service.command.v1.schema.json).

| Field | Meaning |
| --- | --- |
| `schema` | Exactly `service.command.v1` |
| `operation` | One of the nine operations below |
| `request_id` | Stable identity of this command attempt and its exact retries |
| `resource` | Closed `{kind, id}` target; kind is `ServiceRequest` or `Case` |
| `expected_version` | `null` for creation; positive safe integer for an existing aggregate |
| `payload` | Operation-specific closed fields |

All resource IDs, Case IDs, command IDs, and internal verified subjects use 1–128
ASCII lowercase characters: first character alphanumeric, remaining characters
alphanumeric, dot, underscore, or hyphen. Versions start at 1. Required text must
contain a non-whitespace character; limits below count Unicode code points.

| Operation | Resource kind | Required payload | Optional payload |
| --- | --- | --- | --- |
| `request.create` | ServiceRequest | `summary` ≤2048 | `details` ≤16384 |
| `request.qualify` | ServiceRequest | `qualification` ≤4096 | none |
| `request.accept` | ServiceRequest | `acceptance` ≤4096 | none |
| `request.reject` | ServiceRequest | `reason` ≤4096 | none |
| `request.convert` | ServiceRequest | `case_id` ≤128, `obligation` ≤4096 | none |
| `case.plan` | Case | `scope` ≤8192 | none |
| `case.close` | Case | `resolution` ≤8192 | none |
| `case.plan.approve` | Case | `revision_id`, `reason`, `pin`, `inputs`, empty `carry_forward` | none |
| `case.plan.revise` | Case | `revision_id`, `reason`, `pin`, `inputs`, `carry_forward`, `superseded_run_id` | none |

The two runtime plan operations require a planned Case. `pin` names the exact
published process, version, and compilation hash. `inputs` is bounded to 128
typed named values and can include finite JSON numbers. `carry_forward` is a
bounded list of explicit committed-output selections. A revision reason is
required and bounded to 4096 characters. Version fields still require integer
tokens; `1.0` cannot be used as an expected version. See the published schema and
[ADR 0002](adr/0002-runtime-handoff-and-plan-revisions.md) for the nested shapes,
immutable source evidence, and reconciliation rules.

The [example sequence](../contracts/examples/service-lifecycle.json) is exercised
by tests as a real producer-to-application contract. `request.create` fails if
the resource already exists; a new request ID never means an upsert. Conversion
targets the accepted request's version and requires a previously unused Case ID.

## Results and errors

A committed command returns HTTP 200 and the closed result shape:

```json
{
  "schema": "service.result.v1",
  "request_id": "command-identity",
  "operation": "request.create",
  "authority": {"subject": "local-dev-untrusted", "mode": "local_dev_untrusted"},
  "service_request": {"id": "request-identity"},
  "case": null,
  "audit_event_ids": ["event-uuid"]
}
```

The illustrative aggregate above is abbreviated. The published
[result schema](../contracts/service.result.v1.schema.json) gives its complete
closed snapshot. Requests return the changed ServiceRequest; Case commands
return the changed Case. Conversion returns both and two audit event IDs.
Nullable evidence fields appear explicitly, never by omission. New plan commands
also return `plan_revision` and a redacted `handoff` summary. Other current commands
return null for these fields. They remain optional in the published result schema
because successful pre-extension v1 responses must remain exact on retry.

Errors use [service.error.v1](../contracts/service.error.v1.schema.json):

```json
{
  "schema": "service.error.v1",
  "request_id": "command-identity",
  "error": {
    "code": "version_conflict",
    "message": "The expected resource version is stale.",
    "details": {"expected_version": 2, "actual_version": 3}
  }
}
```

`request_id` is null before a command passes parsing, or for a generic internal
failure. Consumers should branch on the stable code, not message text. No raw
database or authority failure detail is returned.

| Status | Codes |
| --- | --- |
| 400 | `invalid_json`, `invalid_command`, `invalid_plan_inputs` |
| 403 | `forbidden` |
| 404 | `not_found` |
| 409 | `version_conflict`, `resource_conflict`, `idempotency_conflict`, `invalid_transition`, `already_converted`, `handoff_unresolved`, `invalid_carry_forward`, `runtime_rejected`, `projection_gap` |
| 502 | `runtime_contract` |
| 503 | `storage_unavailable`, `runtime_unavailable` |
| 500 | `internal_error` |

## Exact retries and concurrency

The idempotency key is `(verified subject, request_id)`. Digest input is the UTF-8
encoding of `service.command.v1`, one zero byte, and the command JSON serialized
with sorted keys, no extra whitespace, literal Unicode, and no non-finite numbers.
JSON key order and wire whitespace are immaterial. Every field, including the
resource, expected version, and optional field presence, contributes to the
digest. Omitted `details` differs from explicitly empty `details` for retry intent.

The service stores only successfully committed commands. An exact retry returns
its original result before checking today's aggregate version. Changed content
under the same key fails. If a response is lost, retry the same command and key;
do not substitute a new key or update the expected version to guess the outcome.
After an explicit failure, a caller may read authorized canonical context and
submit new intent with a new key. There is no unauthenticated resource or audit
query route.

Concurrent commands are serialized by SQLite `BEGIN IMMEDIATE`. Different
decisions with the same expected version produce one success and a stale-version
failure. Concurrent exact retries produce one mutation and the same result.
SQLite lock contention returns `storage_unavailable` after the configured
timeout; use bounded retries with the same command. An unexpected internal or
transport failure has an uncertain outcome from the caller's perspective, so
the same exact retry rule applies.

## Authority and ingress

`X-Service-Authority`, if present, is opaque adapter evidence passed to the
receiver-owned verifier. This header defines no secS credential format and grants
no authority itself. The installed default verifier denies all commands. Explicit
development mode accepts only the absence of that header and labels results
`local_dev_untrusted`; production rejects that mode at startup.

Future Matrix, Hermes, and other ingress adapters may translate user intent into
this same envelope and convey approved authority evidence. They may not change
lifecycle state, infer authority from transport identity, write SQLite, or
bypass the application. The public API has no caller-set actor or status field.
The concrete native receiver adapter verifies the existing secS schema-4 public
helper contract; [receiver authority v1](receiver-authority-v1.md) documents exact
service scope, pins, replay and CLI options. `verified_call` is internal metadata
produced after verification, never caller proof. Live pins/policy, production
qualification and readiness admission remain pending.

## Authorized bounded queries

`POST /v1/queries` uses the same framing and verifier boundary with
`service.query.v1`: schema, request_id, operation, resource, and payload. No
expected-version field is accepted on a query. Query IDs correlate responses;
reads return current data and are not stored as idempotent command results.

| Operation | Target | Payload | Result |
| --- | --- | --- | --- |
| `request.execution` | ServiceRequest | `{}` | accepted/awaiting-plan and handoff disposition |
| `case.summary` | Case | `{}` | canonical service state plus explicitly derived, redacted runtime progress |
| `case.plan-history` | Case | `after_revision` ≥0, `limit` 1–100 | immutable revision history and next revision cursor |

The [query schema](../contracts/service.query.v1.schema.json) and
[query-result schema](../contracts/service.query-result.v1.schema.json) are closed.
Summary progress can be unavailable, catching up, current, stale, or gapped.
Its source resource/version and global cursor identify the evidence observed;
observed step counts are not a guessed total process size. Every summary says
`canonical_runtime: false` and identifies omitted sensitive fields. Rebuild
diagnostics compare view fingerprints at the same source cursor to expose drift.

## Storage compatibility

SQLite schema v3 stores complete aggregate snapshots, event snapshots, and exact
successful result JSON. Foreign keys and unique originating-request links
protect conversion; aggregate updates use SQL compare-and-swap. Migration from an
empty database and migration from v1/v2 run in explicit transactions. Schema v3
adds atomic native replay admission without rewriting saved results or history;
an unknown newer version is
rejected. WAL and `synchronous=FULL` provide SQLite's durable commit behavior on
a supported local filesystem. The database is service-owned and set to mode 0600.

The foundation has no deployed older client release; retained v1/v2 databases
and successful v1 results remain supported by the explicit migrations.
Future changes must keep saved v1 retries interpretable, preserve audit evidence
and request-to-Case links, and use explicit migrations. The executable examples,
parser, schemas, and stored representations must be updated together.
