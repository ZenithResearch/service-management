# Service runtime workers and startup composition

`build_application(CompositionConfig(...), inbound_verifier=..., runtime_authority=...)`
is the component-owned trusted startup factory. It composes the canonical service
store, the public runtime SDK adapter and a separate disposable projection store.
It imports no runtime application, aggregate, authority or database implementation.
Existing direct `Service`, `OutboxDelivery`, `RuntimeProjection`, and SDK adapter
usage remains supported; no library constructor starts a background worker.

The factory's outbound `RuntimeAuthority` port accepts the exact closed public SDK
request and returns approved native evidence bytes. The concrete
`CastaliaWalletRuntimeAuthority` selects only a digest-pinned
`castalia-wallet-service` executable and owner-private `application=runtime`
configuration. It contains no seed reader, key provisioner, trust installer or
generic signing command. Runtime independently verifies and authorizes every
query and handoff. Source composition and an injected label are not proof that an
installed binary, identity, permission window or receiver policy is qualified.

With no injected outbound port, production startup can serve liveness and
fail-closed intake/readiness but does not start delivery or projection workers.
Existing pending events remain untouched, including their attempt counts. It
does not convert them to failed solely because native issuance is unavailable.
The CLI's explicit `local_dev_untrusted` option is limited to test/development
and must also be enabled by the separately running runtime. It is never production
identity or authority. Native inbound receiver options remain independent.

## Explicit CLI composition

A development example, with the independently started public runtime at port 8092:

```sh
service-management --database /tmp/service-owned/service.db \
  --environment development --local-dev-untrusted \
  --runtime-endpoint http://127.0.0.1:8092 \
  --projection-database /tmp/service-owned/projection.db \
  --poll-runtime --poll-interval 1 --max-backoff 30 \
  --batch-size 100 --projection-pages 4 --runtime-timeout 5
```

A production-shaped source composition adds all four Wallet pins:

```sh
service-management --database /private/provider/service.db \
  --native-verifier /private/provider/bin/process-runtime-secs-check \
  --native-verifier-sha256 "$SERVICE_VERIFIER_SHA256" \
  --receiver-policy /private/provider/service-receiver.json \
  --runtime-endpoint http://127.0.0.1:8092 \
  --projection-database /private/provider/projection.db --poll-runtime \
  --runtime-wallet-command /private/provider/bin/castalia-wallet-service \
  --runtime-wallet-command-sha256 "$WALLET_COMMAND_SHA256" \
  --runtime-wallet-configuration /private/provider/runtime-wallet-command.json \
  --runtime-wallet-configuration-sha256 "$RUNTIME_WALLET_CONFIG_SHA256"
```

These options accept no raw key, arbitrary operation, policy, caller-selected
mode or unpinned compatibility fallback. An uncertain retained Runtime command
uses the adapter's explicit `resume` operation on the next reconciliation;
queries always acquire fresh `query` evidence.

`--poll-runtime` explicitly requests both workers and requires the runtime origin
and separate projection file. Shared canonical/projection storage is rejected.
Without polling, an explicitly configured SDK can still perform foreground plan
validation; no unrequested scheduler runs. Rebuild is also explicit:
`--rebuild-projection` with `--poll-runtime` resets only derived view data and
replays retained global history from cursor zero through bounded pages. A missing
projection file starts at cursor zero; it cannot change canonical Cases, runtime
runs, source outbox events, revisions, outputs or receipts.

The origin must satisfy the public SDK's credential-free, no-redirect URL profile;
remote plaintext HTTP is rejected. Signed evidence is obtained per SDK call;
request snapshots and output values are not treated as credentials.

## Workers and recovery

Two independent non-daemon worker threads perform bounded work:

- Outbox delivery visits at most `batch_size` pending records in one cycle. It
  rotates its durable-outbox cursor so a retryable low event ID does not starve
  later events. Each attempt uses the source-owned exact command/key/version/pin,
  records uncertainty before send and commits a validated acknowledgement after.
- Projection sync consumes at most `projection_pages` pages of at most
  `batch_size` global events each cycle. Persisted cursor/freshness remain in the
  disposable projection file. Empty pages below the high watermark and
  nonadvancing/out-of-order pages are visible gaps. A gap requires inspected valid
  replay or an explicit restart with rebuild; it is not silently cleared.

Failed cycles use exponential backoff capped by `max_backoff`; healthy/catching-up
cycles return to `poll_interval`. Timing and page/batch settings have finite
explicit bounds. Delivery and projection failures do not stall each other.
Persisted queue counts keep definitive failed events visible after restart.
Definitive failures require explicit service-owned reconciliation using the
existing `OutboxDelivery.reconcile(event_id, retry_failed=True)` port; workers do
not silently retry or replace failed intent.

A runtime admission closure returns `not_ready` with `retryable=true`. Accepted
handoff intent remains pending; reopened admission retries identical saved bytes.
Timeout, lost acknowledgement or process exit retains an unknown outcome until
exact retry/reconciliation. A provider success acknowledges run creation, not
completion. Runtime execution progress never closes the Case.

SIGINT/SIGTERM stop new polls and further foreground SDK calls, interrupt backoff,
join bounded in-flight workers and drain admitted HTTP requests. Existing atomic
SQLite transactions and uncertain delivery records remain recoverable. Each
accepted HTTP connection has a five-second idle/header/body timeout. Native
verification-only subprocesses retain their separate five-second bound. Supported
remote DNS/transport/custody behavior still requires deployment qualification.

## Readiness and redaction

The ordinary no-runtime readiness shape remains unchanged. Explicit runtime
composition adds `runtime_authority`, `outbox_delivery`, and `runtime_projection`
checks. Each worker reports a fixed state/error, owner, recovery action, cycle
count, bounded next delay, and safe queue counts or projection cursor/freshness.
No endpoint, filename, native evidence, intake content, inputs, outputs or raw
exception text appears in readiness or worker logs.

Examples of recovery ownership:

- Missing outgoing native issuer: `native-service-authority`; install and select
  the qualified Wallet command/configuration tuple.
- `not_ready` from closed admission: `process-runtime`; review and reopen
  receiver-owned new-run admission.
- Uncertain/unavailable runtime: restore the runtime then reconcile exact intent.
- Native permission denial: qualify or restore the exact outbound permission.
- Projection gap: inspect retained history then explicitly rebuild the view.
- Pinned contract mismatch: review the producer/consumer artifact tuple.

Polling readiness requires healthy delivery and a current projection, along with
existing storage and ingress authority requirements. A configured native receiver
remains unqualified until native production admission has its separate evidence.
Liveness remains distinct from readiness. Development readiness proves only the
explicitly untrusted composition, not production authority.

## Retained local evidence

`tests/test_entrypoints.py` launches actual separate service and runtime CLI
processes and uses only the public SDK/wire API. Its disposable receiver-owned
admission policy is changed through the public operator CLI. An HTTP proxy drops
one successful handoff acknowledgement after runtime commit; the service recovers
by exact retry. Tests verify one runtime handoff, unchanged source command digest,
service restart, executor output, bounded projection rebuild, Case independence,
redaction, clean shutdown and disabled production outgoing authority. Smaller
worker tests verify bounded/fair batches, capped backoff, gap handling, separate
storage, trusted injection and shutdown cancellation.

Exact installed artifacts, commands, results and source hashes are retained in
`/example/tmp/process-completion-execution-20261013/service-entrypoint-pollers.json`.
They are implementation/review artifacts, not committed production releases or
canonical Devgraph completion. The native unattended outbound issuer, real
permissions and installed custody/rotation/revocation remain unqualified.

## Cancellation while acquiring authority

The SDK adapter validates each outgoing command or query before requesting
proof. Authority acquisition receives a separate value copy, so a callback
cannot change the retained or dispatched intent. After that potentially blocking
call returns bytes, the adapter checks shutdown again before invoking the public
SDK with explicit evidence. Each dispatch acquires authority once; it never
changes a shared SDK client's authority callback.

Cancellation at this boundary returns retryable `runtime_unavailable` with
`uncertain=false`, and no SDK dispatch occurs. Existing outbox handling still
preserves any earlier uncertain attempt. Cancellation after SDK admission cannot
recall an in-flight request; transport timeouts and invalid acknowledgements keep
the existing uncertainty rules. This local admission check does not add native
issuance, current-policy qualification or a socket-level cancellation guarantee.
