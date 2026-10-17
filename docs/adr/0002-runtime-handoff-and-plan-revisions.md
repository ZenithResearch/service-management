# ADR 0002: Source-owned handoff, explicit plan revision, disposable progress

Date: 2026-10-12

Status: local implementation preparation and provider qualification; no canonical
Devgraph workflow readiness or completion is asserted.

## Scope and task references

This decision covers the exact planned tasks:

- `service-runtime-handoff-contract`
- `service-outbox-runtime-inbox`
- `service-handoff-reconciliation-tests`
- `case-plan-revision-contract`
- `case-plan-carry-forward-validation`
- `case-plan-revision-integration-tests`
- `case-runtime-summary-projection`
- `case-runtime-summary-api`
- `case-runtime-summary-rebuild-tests`

The runtime provider owns its inbox, ProcessRuns, output commits, and receipts.
This service owns the originating request, Case, immutable plan decision, and
delivery obligation. No Hub binding record or runtime database access is needed.

## Acceptance and explicit approval

An accepted request without a selected published process reports `awaiting_plan`.
Acceptance does not manufacture a pin, Case, or runtime creation. Conversion and
`case.plan` establish the distinct Case and plain-text service scope.

`case.plan.approve` then explicitly selects a revision identity, reason, exact pin
(`process_id`, `process_version`, `compilation_hash`), and inputs. Before committing,
the service reads that exact published version through the authenticated runtime
query port, verifies the compiled snapshot hash, and validates its declared input
types. Within one service transaction it checks the current Case version, stores
the immutable revision, updates the Case's current revision reference, appends the
audit evidence, and persists the exact handoff command and retry result.

The handoff uses the runtime's published `service.runtime-handoff.v1` payload with
source identity, service request, Case, plan revision, exact pin, inputs, event ID,
and idempotency key. The source never uses an active-version pointer at delivery
time. Publishing another ProcessVersion cannot change an already-approved event.

## Delivery and uncertain outcomes

The runtime adapter uses only the public `process_runtime_client` SDK. Authority
evidence remains an adapter boundary; the service does not decode a caller's
claimed runtime identity or access runtime storage. Production authority is not
qualified by local tests; the local SDK authority mode is explicit and prohibited
in production composition.

An outbox delivery attempt is recorded as uncertain before a network call. The
exact stored command is copied to the adapter; a mutable adapter cannot alter the
retained intent. A validated acknowledgement must match command identity,
operation, resource, source event, exact pin, and deterministic runtime run ID.
Every retry uses the original command, key, resource, and expected version.

Timeouts, lost acknowledgements, malformed success responses, and process exit
leave the event pending and uncertain. Later version skew cannot convert a prior
unknown commit into proof of failure. A late failed concurrent attempt cannot
overwrite a newer uncertain attempt or confirmed run. A definitive first rejection
can become `failed`, with a bounded error code; explicit retry reuses the same
intent after the underlying problem is fixed. Successful delivery is `started`:
that means runtime creation is acknowledged, not that execution succeeded.

An external event bus may wake a poller but cannot acknowledge delivery or change
state. The durable outbox remains authoritative when every wake-up is lost.
Application composition owns bounded polling and explicit failed-delivery retry;
the library does not start an unrequested background scheduler.

## Revisions and carry-forward

`case.plan.revise` requires a reason, caller-selected new revision identity, exact
new pin and inputs, explicit superseded run ID, and explicit carry-forward list.
The previous handoff must first be reconciled to a known run. Each revision retains
its author and authority mode, command identity, timestamp, prior revision, prior
and new pins, superseded run, and selected output provenance.

Each carried value names the old run, step, Attempt, output name, target input,
and expected immutable output digest. The service reads the trusted runtime run,
output commit, and receipt. It verifies the prior pin, current successful source
Attempt and fence, output/receipt correlation, actor and input digest, canonical
output digest, selected output type and value, and exact target type. Unknown,
stale, mismatched, duplicate-target, or incompatible selections fail closed.
Values never come from the caller's assertion that an earlier step succeeded.

A partially completed or cancelled prior run can supply a specifically selected
committed successful output if these checks pass. A failed or retried Attempt's
stale output cannot. The replacement event creates a new run through the same
outbox. The old run's pin and history remain intact. This service does not silently
cancel the old run; an explicit runtime cancellation is a separate authorized
command. There is no implicit carry-forward or active-run repinning.

## Progress projection and bounded queries

`RuntimeProjection` uses its own disposable SQLite database and refuses a file
containing canonical service tables. It consumes the unfiltered global runtime
event stream, using `sequence`, exact duplicate identity/content checks,
`next_cursor`, and `high_watermark`. Batches commit atomically; gaps, out-of-order
events, conflicting duplicates, or incompatible events mark the projection
unusable until valid replay or rebuild. A clean rebuild starts at retained cursor
zero; unavailable old history is a visible gap, never silent data loss.

Only run/step states, observed completion/blocker counts, and source identifiers,
versions, resources, and cursors are retained. Raw event data, inputs, outputs,
credentials, and arbitrary blocker prose are not stored in the projection.
Counts describe observed steps, not a guessed total from an unavailable plan.

`case.summary` separates canonical service state from derived runtime progress,
with freshness, age, cursor, source version, and explicit redaction metadata.
Rebuild fingerprints detect drift when the same source cursor produces a different
view. `case.plan-history` uses revision cursors and a limit of 1–100. All queries go
through the same default-deny verifier; there is no anonymous Case/progress route.
Projection deletion, gap, or runtime completion cannot close or mutate a Case.

## Compatibility and qualification limits

SQLite migration v2 adds plan history, source outbox, and delivery attempts without
reinterpreting saved v1 results. Older Case snapshots load with no current runtime
revision; older successful responses remain exact on retry. Optional v1 result
fields allow those retained receipts to continue validating. New plan commands
are explicit additions to the pre-release closed v1 API; older readers reject
unknown operations rather than guess their semantics.

Fake-provider tests establish service-owned invariants. Real-provider tests use
only the public SDK and CLI with temporary databases, and separately qualify the
published schemas, resource derivation, handoff, committed-output reads, explicit
replacement, and projection replay. Neither test mode grants production secS
authority or changes the canonical Devgraph task workflow.
