# ADR 0003: Deliver encrypted reference objects and materialize verified execution inputs

Status: accepted for the source candidate on 2026-10-22. Release, deployment,
operator provisioning, and live execution remain separate qualification steps.

## Context

`service.intake-envelope.v1` carries the reviewed brief and immutable reference
manifests. It deliberately does not carry the referenced bytes. A provider that
admits that request without separately receiving the originals can create a Case
whose Runtime inputs name content the executor cannot inspect. Queue acceptance,
ServiceRequest creation, and a Runtime `ArtifactRef` therefore do not prove that
the provider received or used a selected reference.

The first useful provider workflow needs one closed path from the browser's
reviewed input to the exact bytes presented to the selected executor. It must
retain the existing owners: secS protects machine-to-machine payloads, Service
Management owns admission and lifecycle, Process Runtime owns immutable execution
artifacts, and Frank owns execution through the configured Hermes adapter.

## Decision

Provider catalog v4 publishes a distinct encrypted reference-object route using
`service.reference-object-envelope.v1`. The request envelope and each reference
object have separate ciphertext, authorization, queue topic, idempotency domain,
and transport receipt. Both carry the same stable `request_id`,
`idempotency_key`, and exact requester-evidence bytes.
The browser obtains that evidence once and seals both envelopes before returning
either prepared value; separate Wallet calls are not equivalent even when both
proofs are individually valid.

The initial profile accepts zero or one reference object, with an original-byte
limit of 524,288 bytes. The browser hashes the selected bytes before sealing. It
persists and retries the exact prepared envelope until expiry; an uncertain send
never creates a replacement identity or reseals changed evidence under the same
identity. Files above the limit remain local and make the request ineligible for
this service profile. Chunking, CDN upload, shared-provider workspace sync, and
filesystem mapping are outside this decision.

The operator worker opens the object only through the content-pinned secS native
binary, then commits the verified original and requester evidence to the intake
database before acknowledging its queue delivery. Canonical request admission
waits until every declared reference is present and matches its artifact ID,
digest, byte length, stable request identities, and the request envelope's exact
evidence bytes. Object-first and request-first arrival are both valid.

During lifecycle advancement, Service Management writes two immutable Runtime
artifacts:

1. `service.reviewed-brief.v1`, containing the reviewed brief values and digest;
2. `service.reference-manifest.v2`, containing the exact manifest and base64 of
   the verified original, or an empty list when no reference was selected.

The approved plan continues to contain only Runtime artifact references. Frank
must resolve those references through Runtime, recheck their hashes, lengths,
closed schemas, brief value digest, embedded reference digest, and size limit,
and bind the resulting canonical provider input into the captured Hermes prompt
before execution. A missing, changed, malformed, or inaccessible input fails the
dispatch. It is never replaced with a path, placeholder, transport URL, model
guess, or browser state.

## Consequences

- The smallest released profile supports a complete zero-or-one-reference path.
- A queue receipt still means transport retention only. Service admission waits
  for the separately delivered originals and requester verification.
- Service Management remains the only owner of lifecycle decisions; the public
  gateway still has no Service or Runtime authority.
- Runtime artifacts are the immutable executor boundary. The intake database is
  a durable transport staging store, not a shared workspace or global work graph.
- Matrix may carry notifications or future transport events, but Matrix delivery
  does not create a ServiceRequest, Case, Runtime artifact, or execution receipt.
- Larger files and multi-object packages need a later versioned protocol rather
  than an implicit expansion of this profile.

## Retry and recovery

The request and reference queues are independently at least once. A client
retries only the exact retained ciphertext for the stable identity. Each local
worker commits before acknowledgement and exact duplicates return the retained
result. Conflicting bytes or evidence fail closed. Native Service and Runtime
authority keep their existing explicit `issue` versus `resume` recovery paths;
reference delivery does not grant either authority.

