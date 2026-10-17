# ADR 0001: Service ownership and explicit lifecycle commands

Date: 2026-10-12

Status: implemented foundation for review; dependent integration contracts pending.

## Context

Intake intent and an accepted managed service obligation have different identities
and lifecycles. Transport adapters must not decide whether work is qualified,
accepted, executable, or closed. A retry or concurrent decision must not create a
second obligation or lose the audit evidence of the first decision.

The repository is greenfield. The neighboring process-runtime and Frank owners
are being developed separately. This decision introduces a service-owned
contract without guessing their shared execution or secS contracts.

Non-service SOPs may create ProcessRuns directly through process-runtime without
any Case. Service-management owns the only Case aggregate; process-runtime owns
the only ProcessRun aggregate. A plan pin, delivery acknowledgement, or disposable
summary in this service is a reference to runtime state, not a second run owner.

## Decision

`ServiceRequest` is the canonical intake aggregate. Its lifecycle is:

| Current state | Command | Next state | Required evidence |
| --- | --- | --- | --- |
| absent | `request.create` | intake | summary; optional details |
| intake | `request.qualify` | qualified | qualification |
| intake or qualified | `request.reject` | rejected | reason |
| qualified | `request.accept` | accepted | acceptance |
| accepted, no Case | `request.convert` | accepted, with Case reference | new Case identity and obligation |

Acceptance alone does not create a Case. Conversion atomically increments the
request version, records its Case reference, creates one Case, and records both
aggregate audit events. The original accepted request remains inspectable in
service storage. A unique foreign key permits at most one Case per request.
Rejected requests cannot be qualified, accepted, or converted. There is no
implicit reopening, rejection of accepted work, or acceptance reversal.

`Case` owns a distinct managed obligation and the following foundation lifecycle:

| Current state | Command | Next state | Required evidence |
| --- | --- | --- | --- |
| absent | `request.convert` on accepted request | open | originating request and obligation |
| open | `case.plan` | planned | initial service scope |
| planned | `case.close` | closed | service closure resolution |

The initial scope is a service decision. It does not stand in for a runtime plan,
binding version, execution result, or plan revision. Replanning and runtime
handoff need the later contracts and must not be smuggled through `case.plan`.
There is no direct Case creation or patch-any-field API. Subsequent explicit
runtime plan approval and revision commands are described in ADR 0002.

## Application and authority

All ingress submits `service.command.v1` to the application. Its fields are
closed: schema, operation, request_id, resource, expected_version, and payload.
Lifecycle state and actor cannot be set by callers. The application owns the
transaction and verifier ports; the domain imports neither SQLite nor transport
types. The HTTP adapter only reads bytes and opaque authority evidence and formats
the result. No Matrix or Hermes adapter is invented in this foundation.

The verifier port defaults to denial. The concrete native adapter described in [receiver authority v1](../receiver-authority-v1.md) verifies
receiver-local authorization, identity, audience, permissions, revocation, expiry,
and replay against the exact command before returning an internal `VerifiedCall`.
The application rechecks subject, audience, command digest, finite expiry, and mode.
`VerifiedCall` is an internal port value, not a user-supplied credential format.
Verification runs on every attempt, including an idempotent retry, so saved
results do not bypass current authority. No role or permission semantics are
claimed for arbitrary custom port adapters. The shipped native wrapper binds the
service descriptor and permissions to native schema-4 proof and transactionally
admits replay; live native qualification remains pending.

`local_dev_untrusted` is an explicit opt-in verifier for development and tests.
It accepts no authority evidence and is forbidden in production. Its label is
retained in every result and event so local fixtures cannot appear authenticated.

## Persistence and consequences

One SQLite transaction holds the write reservation before reading current
versions or idempotency records. SQL updates require the exact expected version;
each successful aggregate update increments it once. State, audit events, and
the successful retry result commit together, including both sides of conversion.
Exceptions and failed commits roll the transaction back.

Idempotency is scoped by the verified subject and command `request_id`. A saved
digest must match all canonical command content; otherwise the service returns
`idempotency_conflict`. Identical retries return the original result, event IDs,
versions, and timestamps even after a restart or later lifecycle changes.
Rejected commands are not retained as successful results and can be reevaluated
after authorization or transient storage conditions change.

The serialized snapshots are storage adapter details. Audit events are append-only
through the application port and include before/after snapshots, actor, authority
mode, command identity, versions, and time. They are not claimed to be
cryptographically tamper-evident. UI projections may later be rebuilt from
canonical service data; no current UI or transport copy is an authority source.

No existing client or persisted database needs migration for this initial version.
Incompatible command semantics require a new schema identifier. New storage
versions require an explicit migration and retention tests for command results,
aggregate links, and audit history. Runtime aggregates and runtime persistence
remain exclusively process-runtime's responsibility.
