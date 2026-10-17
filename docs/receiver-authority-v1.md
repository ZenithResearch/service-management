# Service receiver authority v1

`SecSServiceAuthorityVerifier` implements the service-owned verifier port. It
imports no runtime aggregate, authority implementation or storage. The default
service and CLI deny all commands and queries. The CLI can explicitly inject an
absolute native verifier path, its expected SHA-256 and an absolute receiver-owned
policy file. All three options are required together; they cannot be combined
with `local_dev_untrusted`. No pins, service identity or live policy are shipped.

This is receiver implementation and synthetic compatibility evidence, not native
production qualification. Configuring this port does not make `/ready` return
200: authority remains `unqualified` until the separate artifact/identity/policy
qualification gate has a supported admission mechanism. Liveness may return 200.
The component still denies missing or invalid evidence with no canonical write.

## Native public boundary

The service consumes the existing verification-only executable protocol
`process-runtime.secs-check-input.v1` / `process-runtime.secs-check-output.v1`.
The protocol name identifies the helper artifact; it grants no runtime authority.
The helper comes from process-runtime's `native/secs-verifier`, with pinned secS
revision `11e7128e49c6df57f53e4c8b05e72d4bc78d798c`. The helper has no signing,
credential, private-key, grant, network, replay-store or installation interface.

Evidence is a closed JSON object with exactly `schema: service.secs-envelope.v1`,
`packet_hex` and `signed_context_hex`. Values are lowercase encodings of the
actual fixed-integer bincode ZenithPacket and SignedVerifiedCallContext. The
service retains the native representation; it does not invent a JSON-signature
scheme or accept a caller-selected trust key, verifier path, audience or policy.

The helper checks closed bounded input, trailing/noncanonical native bytes,
schema 4, Ed25519 node-and-verifier authentication, active pinned verifier keys,
exact audience, exclusive expiry and a lifetime of at most 60 seconds. It binds
the hash of the entire serialized packet, session, nonce, opcode and claim TTL.
`packet.encrypted_payload` must equal the service's canonical UTF-8 request JSON
bytes. This profile uses that field as a payload container; it does not claim
transport encryption. The service command/query digest remains the existing
schema-prefixed digest; it is not confused with native `packet_hash`.

The wrapper independently requires audience `service-management`, the full name
`service.<raw-operation>.v1`, the configured opcode/descriptor fingerprint/handler,
and native replay scope `session:opcode:nonce`. Resources are exactly
`requests/<ServiceRequest.id>` or `cases/<Case.id>`, according to the closed request
resource. Conversion binds its destination Case identity and obligation through
the exact signed command payload. The wrapper accepts no `runtime.*` operation or
run/Attempt/lease grant. An Actor or transport identifier is not an identity.

The helper path and its ancestors, and the policy path and its ancestors, must be
operator-controlled. Symlink leaf files are rejected; deployment must separately
qualify custody and filesystem control. The helper digest is checked before each
invocation, its environment is empty and its timeout is five seconds. Errors are
fixed service errors and never include proof, policy or payload bytes.

## Receiver-owned policy

`FileReceiverPolicy` reloads a bounded closed `service.receiver-policy.v1` object
before each native check and again after it. A changed or unreadable policy denies
the call, including saved-result retries. The root fields are exactly:

- `schema`, `audience`, `keys`, `descriptors`, `rules`, `revoked_subject_keys`.
- `keys`: up to 32 unique public verifier pins with `key_id`, `public_key_hex`,
  `status`, `production_authority`, and optional Unix-second `not_before`,
  `not_after`, `revoked_at`. These have the helper's existing public format.
- `descriptors`: unique full service `operation` and `opcode` (integer 0..255),
  `fingerprint` (64 lowercase hex) and `handler_id`. The opcode is supplied by the
  reviewed native manifest, not allocated or registered by this component.
- `rules`: `subject_id`, full service `operation`, `resource`, `effect` (`allow` or
  `deny`), `not_before_ms`, `not_after_ms`, optional `key_id`, `active`, and
  `resource_match` (`exact` or explicit slash-terminated `prefix`). No wildcard
  rule exists. The validity window is exclusive at its end.
- `revoked_subject_keys`: arrays of `[subject_id, key_id]` pairs.

Absent allows deny; matching denies win. Subject key revocation is independent
of verifier-key revocation. Permission boundaries and verifier-key expiry bound
the returned internal call expiry, so the application's fresh post-verifier clock
also rejects permissions that expired while native verification blocked. Policy
and native descriptor installation remain external security-owner responsibilities.
There is no grant creation or service identity provisioning command here.

## Transactional admission and retained data

Schema v3 adds `authority_replays` without rewriting v1/v2 aggregate snapshots,
audit history, revisions, outbox or exact retained command results. Each native
mutation uniquely admits `(subject, session, opcode, nonce)` after current
verification inside the final writer transaction. State, replay, audit and result
commit together. Process death or failed lifecycle validation rolls all back.
Plan preparation can verify the same evidence twice; only the final transaction
consumes replay. Queries admit replay with the read transaction and need fresh
native evidence on every new query.

Exact successful command retries first revalidate current native authority and
then return the original retained result before nonce admission. Changed intent
cannot reuse that command ID or nonce. Stable-subject key rotation preserves
idempotency and replay history; actual rotation remains a native qualification
gate. No automatic replay/result retention deletion is introduced.

## HTTP and CLI

Existing direct command/query bodies and the bounded `X-Service-Authority` header
remain supported. Larger evidence uses the additive closed `service.transport.v1`
body: `schema`, `request` (the original command/query object), `authority_base64`.
The base64 encoding is strict and canonical; header evidence cannot accompany the
wrapper. Raw command/query size remains 65,536 bytes, decoded evidence is bounded
at 295,127 bytes and the outer body at 786,786 bytes. Both paths reach the same
application parser, lifecycle checks and native verifier. TLS, deployment and
external ingress qualification are separate. Exact current byte, per-server admission and absolute body-read limits are documented in [transport budgets](transport-budgets.md).

Operator wiring, after qualified pins/policy exist:

```sh
service-management --database /operator/service/service.db \
  --native-verifier /operator/artifacts/process-runtime-secs-verifier \
  --native-verifier-sha256 "$REVIEWED_NATIVE_VERIFIER_SHA256" \
  --receiver-policy /operator/policy/service-receiver.json
```

This is configuration syntax, not approval to provision, activate or trust an
identity. No sample production policy or synthetic trust root is supplied.

## Synthetic-only verification

`tests/fixtures/native-secs-v4.json` contains public signed test fixtures. They
reuse the upstream helper's fixed `#[cfg(test)]` signer in an isolated `/private/tmp`
copy, changing only the test fixture audience and handler strings to this service
profile. The installed helper binary and all runtime/native source files remain
unchanged. Fixtures use a historical clock and have no live authority. Never pin
the synthetic public key as a production trust root.

Set `SERVICE_NATIVE_VERIFIER` to the separately reviewed helper build and run
`python -m unittest discover -s tests -v`. Without it, four native tests explicitly
skip; policy/binding/replay tests remain available. Passing them demonstrates
helper compatibility, native signature rejection and service admission behavior.
It does not qualify the live Wallet/secS stack, unattended issuer, service identity,
active descriptors/permissions, installed custody, rotation/revocation ceremonies,
HTTPS deployment, runtime handoff poller or canonical Devgraph completion.

## Native descriptor fingerprint compatibility

After the pinned helper authenticates the exact signed context, the receiver
accepts either the existing lowercase 64-hex descriptor digest or Native’s exact
`descriptor:sha256:<digest>` representation, provided that digest equals the
current receiver-owned descriptor pin. Other prefixes, spelling, case, lengths
and digests deny. Runtime normalizes this authenticated binding to its existing
internal digest field; the original context and signature bytes remain intact.
Service uses the same exact comparison without changing its internal call wire.
This is additive compatibility with the existing schema-4 verifier, not a new
signature format, trust source, policy grant or installed qualification.
