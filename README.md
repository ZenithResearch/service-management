# service-management

Python 3.12 service lifecycle foundations. `ServiceRequest` owns intake, qualification,
acceptance, and rejection. An explicit conversion of an accepted request creates a
distinct `Case`, which owns the managed service obligation, initial scope, and closure.

This is reviewable implementation preparation for the foundation tasks:
`service-domain-scope-adr`, `service-intake-api-and-ingress`, and
`service-lifecycle-persistence-tests`. It does not assert canonical Devgraph task
readiness or completion. Source-owned handoff, explicit plan revisions, and runtime
summary projection preparation are also included; their exact task IDs and
integration boundaries are in [ADR 0002](docs/adr/0002-runtime-handoff-and-plan-revisions.md).

## Run locally

There are no runtime dependencies outside Python 3.12's standard library. From this
repository:

```sh
PYTHONPATH=src python3.12 -m unittest discover -s tests -v
PYTHONPATH=src python3.12 -m service_management \
  --database /tmp/service-management-dev/service.db \
  --environment development --local-dev-untrusted
```

The CLI binds `127.0.0.1:8091`. `GET /live` reports process liveness; it does not
certify authority or storage readiness. `GET /ready` checks bounded SQLite writer
admission and schema metadata without reading business records. It returns 503
for unavailable storage, default-deny authority, or an unqualified custom verifier.
An explicitly enabled local adapter with healthy storage returns 200 and reports
`local_dev_untrusted`; this does not certify production authority or runtime
connectivity. `POST /v1/commands` accepts the
[closed command contract](contracts/service.command.v1.schema.json).
`POST /v1/queries` accepts the [bounded query contract](contracts/service.query.v1.schema.json).
The executable [example sequence](contracts/examples/service-lifecycle.json)
creates, qualifies, accepts, converts, plans, and closes one sample obligation.
Use a new command `request_id` for new intent; retain the exact command when a
response is lost.

`--local-dev-untrusted` visibly marks results and audit events as untrusted local
development. The option is rejected with the default `production` environment.
Without it, the authority port denies every command. No bearer string, Matrix
identity, Hermes account, room membership, caller key, or JSON claim grants
authority. A concrete native secS receiver adapter and CLI injection options are described in
[receiver authority v1](docs/receiver-authority-v1.md). Live pins, policy and native
production qualification remain separate; configured native readiness is unqualified.

## Boundaries

- `domain.py` contains storage-neutral aggregates and transitions.
- `application.py` authorizes every command, checks idempotency and versions, and
  commits state, audit events, and the successful result through application-owned
  ports in `ports.py`. Authorization runs after writer admission and runs again
  after external plan preparation. The verifier must reload current receiver
  permissions on each call; expiry uses a fresh clock after verification.
- `sqlite_store.py` implements the ports using explicit `BEGIN IMMEDIATE`
  transactions, WAL, foreign keys, version checks, and durable command results.
  Each command uses one connection; SQLite admits one writer across processes.
- `http_api.py` and `ingress.py` submit the same closed commands to the application.
  Adapters do not own lifecycle decisions or write the database directly.

Read [ADR 0001](docs/adr/0001-service-domain-and-command-boundary.md) for ownership
and transition rules, and [the API contract](docs/command-api.md) for errors,
retry semantics, authority boundaries, persistence, and compatibility.

`case.plan` records service scope only; it creates no runtime entity. An explicit
`case.plan.approve` selects an exact published pin and atomically records a
CasePlanRevision and durable outbox event. `case.plan.revise` explicitly replaces
that plan after reconciling its handoff and validating selected prior outputs.
`case.close` records an authorized service owner's closure decision; it does not
claim that runtime execution happened or cancel any run.

`OutboxDelivery` retries the exact stored command through the `RuntimeClient`
port. `SDKRuntimeAdapter` imports only the public `process_runtime_client` package.
The package is supplied by the separately built runtime distribution; no runtime
domain or storage implementation is imported by service code. The CLI leaves this
port unavailable by default. Explicit endpoint/projection/polling options and the
trusted startup factory now compose this port with bounded durable delivery and
projection workers; see [runtime workers](docs/runtime-workers.md). Production
outbound native authority remains unavailable unless a qualified port is injected
by trusted startup code. Development CLI polling is visibly untrusted.

The projection consumes the global runtime cursor stream into bounded, redacted
progress summaries. It can be discarded and rebuilt without altering canonical
Case state, ProcessRuns, outbox identity, or plan history.

Public command/query requests retain the 65,536-byte limit. The separate native Packet, proof, context, authority and escaped HTTP bounds are documented in [transport budgets](docs/transport-budgets.md). Each HTTP server admits two request bodies with an absolute five-second read deadline. These bounds preserve the canonical and compact ASCII-escaped producer profiles; operation, output and authority qualification limits remain independent.

The standard-library HTTP server is a local foundation adapter. Production
deployment, approved secS verification, and Matrix/Hermes transport integration
require their separate qualification work.

## Persistence and verification

The service owns only its SQLite file. Schema v3 installs atomically on first use
and upgrades v1/v2 with immutable plan history, outbox, delivery evidence, and
transactional native replay admission. Existing snapshots and saved results are retained.
Startup refuses newer schema versions. Saved v1 results remain exact on retry;
new response fields are optional in the v1 result schema for those retained
receipts. No deployed service consumer existed in this greenfield repository.

Tests exercise real loopback HTTP, parser rejection, lifecycle rules, default deny,
authority binding, independent concurrent SQLite writers, compare-and-swap,
duplicate conversion, lost-response retries across restart, lock contention,
rollback on audit failure, and abrupt process death during a transaction. Tests
use temporary databases and require permission to bind a loopback test port.

Real provider qualification uses the installed public SDK and launches the
runtime's public CLI against a temporary database. With the runtime distribution
available in the test environment, set `SERVICE_RUNTIME_COMMAND` to a JSON argv
list such as `["python3.12", "-m", "process_runtime"]` and run the same test suite.
Without that variable the provider test reports a skip; fake-provider tests remain
available with only the standard library. Integration tests use explicitly
untrusted local development authority and do not qualify production secS.

Successful command results and audit events are retained without automatic
expiry. Retention policy, backup/recovery operations, and production scaling are
future operational decisions; they must not silently erase idempotency history.

## Public deployment

Use the [Zenith Hub lightweight deployer](https://github.com/ZenithResearch/zenith-hub-lightweight)
for the shared Apple-silicon Mac installer and operator UI. Component source lives
under [ZenithResearch](https://github.com/ZenithResearch). Installation does not
provision native identities, grant command authority, or enable external effects.
See `NOTICE.public-baseline.md` for the scope of this clean publication.
