# Provider client intake boundary

Status: **source candidate complete; installed native artifacts, real
operator pins, deployed gateway and live Queue are not production-qualified**.

The local authorized status/artifact/receipt projection is implemented in
`provider_projection.py`, its framework-neutral routes are in `provider_http.py`,
and `provider_projection_server.py` composes a numeric-loopback GET/OPTIONS-only
listener. The selected initial response transport is an operator-approved HTTPS
Tailscale Funnel to that listener. This is a transport route, not a synchronized
workspace or second canonical store. Public Anima users use normal HTTPS and do
not join the provider tailnet. The source candidate does not alter Funnel state.

This adapter connects a reachable provider inbox to the existing canonical
Service Management command boundary. It does not make the queue, dispatcher or
browser authoritative over a `ServiceRequest`.

## Ownership and flow

| Stage | Owner | Durable meaning |
| --- | --- | --- |
| Reviewed brief and selected manifests | Client | User-reviewed intent bound by `brief.content_hash` |
| HTTPS authentication and publish | Public provider gateway | Requester proof verified for the exact submission; no ServiceRequest yet |
| Bounded encrypted queue payload | Vercel Queues | `pending`; retained for at most its configured TTL |
| Separately encrypted reference object | Browser / reference Queue | Exact selected original is sealed and retried independently; no ServiceRequest yet |
| Decrypt/authenticate transport envelope | Provider worker | Dispatcher identity and ciphertext integrity only |
| `client_intake` SQLite commit | Provider worker | Exact intake, reference original and requester evidence are durable before each Queue acknowledgement |
| Requester verification | Provider policy adapter | Existing membership and exact-request authority are valid under receiver policy |
| `service.command.v1/request.create` | Service Management | Canonical ServiceRequest admission under separately configured Service authority |
| Qualification, acceptance and conversion | Service Management | Explicit lifecycle decisions; Case creation is never implied by queue delivery |
| Immutable process pin and run | Service Management / Process Runtime | Existing plan revision, outbox, runtime and receipt contracts remain canonical |

`src/service_management/client_intake.py` implements the transport-independent
store and workers. `src/service_management/client_gateway.py` implements the
bounded encrypted public submission core, the earlier plaintext integration
core, and official SDK byte-topic publisher.
`src/service_management/vercel_intake.py` implements the official Vercel Python
SDK poll boundary. `src/service_management/castalia_requester.py` independently
verifies the closed
[`service.castalia-requester-evidence.v1`](../contracts/requester.evidence.v1.schema.json)
composition. `src/service_management/secs_intake.py` implements the
provider-side adapter for the fixed-purpose `secs-provider-intake-v1` native
executable. Browser contracts and fixtures are in `clients/typescript`.
`src/service_management/castalia_credential.py` supplies the bounded public
receiver-credential core used before Wallet approval.
`src/service_management/castalia_gateway.py` verifies the outer Wallet Auth v2
presentation over exact ciphertext routing metadata. `provider_http.py` exposes
the two public commands through a framework-neutral, exact-origin HTTP adapter;
`provider_vercel.py` and `api/provider.py` provide the fail-closed Vercel
composition and Python entry point.

Provider catalog v4 publishes `/v1/client/reference-objects` as a separate
encrypted route. The initial profile accepts zero or one original up to 524,288
bytes. The browser must retain and retry the exact prepared ciphertext. The
reference and request may arrive in either order, but canonical admission waits
until every declared reference matches its stable identities, manifest digest,
byte length, original bytes, and the request envelope's exact requester evidence.
Files above the limit and requests with more than one reference fail closed; this
version defines no chunking, CDN, Matrix-attachment or shared-workspace fallback.
See [ADR 0003](adr/0003-encrypted-reference-delivery-and-execution-materialization.md).

## Receiver credential issuance

The browser first creates the exact canonical intake and disclosure digests. It
posts those digests, a fresh nonce, the exact caller and its active public Zenith
membership credential using
[`service.castalia-credential-issuance.v1`](../contracts/requester.credential.v1.schema.json).
The issuer verifies the membership signature against pinned Zenith roots and
returns the existing `castalia.request-credential.v1`, valid for at most 120
seconds. Castalia Wallet verifies the configured receiver key and asks for
per-request consent before producing its Member Key presentation.

The issuer signer is an injected fixed-transcript port. Its configured public
key is checked against every returned signature, so a missing, substituted or
misconfigured signer fails before a credential is returned. The endpoint never
receives the intake plaintext, Wallet private key, secS recipient secret,
Vercel OIDC token or Service Management authority. Possessing an issued request
credential alone is insufficient: the provider Mac still requires the active
membership credential, matching Member Key signature, exact decrypted intake,
configured policy and authenticated Queue acceptance time.

After secS seals the intake and inner requester evidence, the browser constructs
`service.encrypted-intake-authorization.v1` from the provider/request/idempotency
identities, exact intake and envelope digests, recipient key and envelope expiry.
It obtains a second short-lived request credential and Member Key presentation
over those exact canonical bytes. The closed
[`service.castalia-gateway-presentation.v1`](../contracts/gateway.requester.v1.schema.json)
travels as an unpadded base64url `Authorization: Castalia …` header. The public
gateway checks the configured caller origin, receiver key/audience/policy pins,
credential and presentation signatures and current freshness before Queue publish.
This outer proof authorizes the online ciphertext hop; the independent inner
proof is reverified locally after decryption and authorizes the exact service
request. Neither proof is Service Management command authority.

## Recovery invariants

1. `request_id` identifies the future ServiceRequest. `idempotency_key` identifies
   the one stable `request.create` command.
2. An intake retry succeeds only when both identities, the canonical intake
   digest and the durable requester-evidence bytes match. Reusing either identity
   with changed content or a refreshed/different proof fails closed. The gateway
   must normalize an exact request into deterministic, queue-lifetime evidence.
3. The pull worker commits the exact intake, public requester evidence and
   transport receipt before queue acknowledgement. A lost acknowledgement causes
   an exact local deduplication retry.
   The independent reference worker applies the same invariant to each selected
   original and its separate transport receipt.
4. The admission worker durably retains the generated command and changes its
   local authority state to `resume_required` before starting Wallet issuance.
   Fresh polling never calls `issue` again for that row. An uncertain or lost
   result is recovered only by the explicit `resume-admission-once` operator
   command with the same bytes; Service Management's result store then returns
   the original result without a second audit event or aggregate.
5. A dispatcher or Vercel OIDC token can move ciphertext. It does not grant Zenith
   membership, organizational authority or Service Management command authority.
6. `pending` means only that the reachable transport retained the payload.
   `admitted` is returned only after canonical Service Management commit.

The queue adapter uses deploymentless poll mode because the operator Mac must
consume compatible envelopes produced across frontend deployments. The envelope
therefore needs an explicit version and a closed reader. Consumer group names
must be scoped to one provider installation; two machines sharing a group compete
for work.

Vercel documents at-least-once poll delivery, acknowledgement on successful
handler completion and a per-message retention range of 60 seconds through seven
days. The current v4 transport profile uses seven days and exposes that expiry
in the `service.intake-result.v1` transport receipt. Expiry before local commit is
terminal for that queued copy; the client reconciles status and may republish the
same exact request identity.

- [Vercel Queues poll mode](https://vercel.com/docs/queues/poll-mode)
- [Vercel Queues API](https://vercel.com/docs/queues/api)
- [Vercel Queues Python SDK](https://vercel.com/docs/queues/python-sdk)

## Required production composition

The following ports intentionally have no permissive default:

- `EnvelopeOpener`: validate a closed, versioned encrypted envelope; pin the
  provider recipient key; authenticate dispatcher origin; return only bounded
  `service.intake.v1` bytes and requester evidence. Reuse the current secS X25519,
  HKDF and ChaCha20-Poly1305 tunnel primitives rather than introducing a second
  unreviewed cryptosystem.
- `CastaliaRequesterVerifier`: verify the existing Zenith membership v3
  credential, Wallet Auth v2 receiver credential and Member Key presentation
  over the exact canonical intake bytes. It returns the deterministic public
  membership ID only. Queue or dispatcher credentials are never accepted as
  membership or request consent.
- `NativeAuthorizedServicePort`: pass the exact retained canonical command to
  `CastaliaWalletServiceAuthority`, require bounded native evidence, and submit
  the same bytes and evidence through `CommandIngress`. The adapter pins the
  released `castalia-wallet-service` executable and one owner-private
  `application=service` configuration. It exposes distinct `issue` and `resume`
  operations and never falls back between them.

The production public gateway receives an already-sealed secS envelope plus
bounded routing metadata. The requester's presentation binds the provider,
request, idempotency identity, exact intake digest, recipient key and expiry;
the provider repeats membership verification from the exact evidence inside the
envelope after opening. A mismatch fails locally and never creates a
ServiceRequest. The earlier `PublicIntakeGateway` plaintext/seal composition is
retained for source compatibility and local integration, not production public
ingress.

The public gateway must never place wallet private keys, recovery material,
provider tunnel secrets, Service authority, Vercel OIDC tokens or local paths in
the queue. Requester evidence must be sufficient to reverify the exact request
after restart and must contain no private key.

The Wallet Auth request credential and holder presentation are deliberately
short lived. Local admission can occur after they expire because the verifier
evaluates their interval at the authenticated Queue `created_at` stored in the
durable `TransportReceipt`. The transport timestamp contributes only the
arrival-time observation: membership still requires the pinned Zenith issuer
signature, exact-request authority still requires the pinned request issuer
signature, and possession still requires the Member Key signature. A receipt
from an unconfigured transport is rejected. The gateway cannot create any of
those proofs and local current time cannot retroactively make a late proof valid.

The encrypted gateway requires stable public request and idempotency identities
plus the canonical intake digest. It validates the closed public envelope frame,
recipient key and a 60-second-to-seven-day expiry without opening ciphertext,
then hashes the stable logical identities into the Queue idempotency key. Its
membership verifier must authorize that exact metadata. Requester evidence inside
the envelope remains deterministic through Queue expiry; refreshing or replacing
it under the same logical request is rejected by the local inbox. Queue publish
failure is an unknown outcome, so the caller retries the exact envelope.

## Vercel source deployment configuration

The checked-in `vercel.json` rewrites only `/v1/provider`,
`/v1/request-credential`, `/v1/client/requests` and
`/v1/client/reference-objects` to the bounded Python handler. `GET /v1/provider`
returns the deployment-pinned canonical provider-catalog v4 used by Anima's
trust check. `requirements.txt` installs
the package with its pinned Queue and Castalia verifier extras. Deployment fails
closed unless all of these values are explicit:

| Variable | Meaning |
| --- | --- |
| `ZENITH_ANIMA_ORIGIN` | One exact browser origin; HTTPS except numeric loopback HTTP for the local Anima pilot; also the Wallet caller pin |
| `ZENITH_PUBLIC_BASE_URL` | Exact public HTTPS gateway origin; catalog endpoints must be beneath this origin |
| `ZENITH_PROVIDER_ID` | Provider identifier in the catalog and routing headers |
| `ZENITH_RECIPIENT_KEY_ID` | Released secS recipient key identifier published in the catalog |
| `ZENITH_RECIPIENT_PUBLIC_KEY_HEX` | Released secS recipient public key published in the catalog |
| `ZENITH_RECEIVER_ISSUER`, `ZENITH_RECEIVER_KEY_ID`, `ZENITH_RECEIVER_PUBLIC_KEY_HEX` | Receiver credential signing identity and public pin |
| `ZENITH_RECEIVER_SIGNING_SEED_B64` | Owner-provisioned unpadded base64url Ed25519 seed stored only as a protected server secret; startup proves it matches the public pin |
| `ZENITH_RECEIVER_AUDIENCE` | Wallet Auth audience |
| `ZENITH_REQUESTER_POLICY_DIGEST_SHA256` | Exact receiver policy digest |
| `ZENITH_MEMBERSHIP_ROOTS_JSON` | Closed JSON array of accepted Zenith membership issuer roots |
| `ZENITH_MEMBERSHIP_ISSUER_ORIGIN` | Exact membership issuer origin published in the catalog |
| `ZENITH_PROVIDER_CATALOG_JSON` | Canonical provider-catalog v4; startup validates its endpoints and every authority, membership and recipient pin against the independent variables above |
| `ZENITH_QUEUE_REGION`, `ZENITH_QUEUE_TOPIC` | Vercel region and reviewed-intake Queue route |
| `ZENITH_REFERENCE_QUEUE_TOPIC` | Separate encrypted reference-object Queue route |
| `x-vercel-oidc-token` request header | Vercel-provided runtime transport credential; the entry point requires exactly one and binds Queue publication to that request context |
| `ZENITH_STATUS_BASE_URL` | Exact HTTPS base, with optional normalized mount path, of the separately deployed authorized projection listener |

The deployed provider gateway remains HTTPS when the configured Anima caller is
numeric loopback HTTP. That exception applies only to the exact browser origin
bound into CORS and Wallet authorization; it does not downgrade the gateway,
permit `localhost`, accept a path, or create a local submission endpoint.

The composition never captures a build-time `VERCEL_OIDC_TOKEN`; Vercel runtime
OIDC tokens arrive on the request header and are resolved by the Queue SDK while
that exact request context is active. The composition creates no identity, key,
membership, project, Queue or paid
resource. Real values must match provider-catalog v4. Secret rotation, rate
limits, live origin configuration and deployment qualification remain release
operations, not browser behavior.

## GET-only operator response listener

`service-management-provider-projection` binds only to explicit numeric
`127.0.0.1`. It accepts browser `GET` and `OPTIONS` for request status, committed
artifact bytes and canonical receipt bytes. `POST`, `PUT` and `DELETE` are
disabled in the read-only composition, so the Funnel does not create a second
submission path. Every business read still needs a fresh exact Castalia Wallet
presentation and must match the requester membership retained at admission.

The operator pins the existing intake and Service databases, requester policy,
Runtime endpoint and Runtime Wallet query authority. `--public-base-url` is the
exact HTTPS Funnel base, including an optional normalized mount path, placed on
returned artifact and receipt links. The gateway uses the same base as
`ZENITH_STATUS_BASE_URL` when returning the initial `status_url`. Anima
configures its origin in `trustedReadOrigins`, and configures the full base as
`responseBaseUrl` so an unknown intake outcome can reconcile the stable request
ID even when no acknowledgement supplied `status_url`. Neither response data nor
catalog metadata can add an origin to the client's trust set.

```text
service-management-provider-projection \
  --intake-database /private/provider/intake.db \
  --service-database /private/provider/service.db \
  --requester-policy /private/provider/requester-policy.json \
  --browser-origin https://anima.example \
  --public-base-url https://matrix-home.example.ts.net/zenith/provider \
  --runtime-endpoint http://127.0.0.1:8292 \
  --runtime-wallet-command /private/provider/bin/castalia-wallet-service \
  --runtime-wallet-command-sha256 <released-sha256> \
  --runtime-wallet-configuration /private/provider/runtime-wallet-command.json \
  --runtime-wallet-configuration-sha256 <reviewed-sha256> \
  --host 127.0.0.1 --port 8293
```

The local `/live` and `/ready` diagnostics report listener liveness and the
independent intake-store, Service-store, requester-policy and Runtime-authority
composition checks. A live listener does not imply a live Runtime, successful
execution or available deliverables; canonical status reports unavailable
Runtime state as `unknown`.

## Native secS composition

`NativeSecSIntakeOpener` is the concrete provider-side `EnvelopeOpener`. The
operator supplies an absolute path and the SHA-256 digest of a reviewed
`secs-provider-intake-v1` release artifact. The adapter rejects symlinks or a
changed executable, invokes only its fixed `open` command, passes the opaque
envelope over standard input with an empty environment, and parses one bounded
binary response frame. It never receives a key path and never exports the
recipient private key.

The executable and `service.intake-envelope.v1` contract are under review in
[secS PR #302](https://github.com/ZenithResearch/secS-magik/pull/302), currently
at commit `4ec825c`. Source qualification does not make that commit an installed
production component. Production configuration must pin the digest of a merged,
released artifact and provision its canonical macOS recipient key explicitly.
Service Management still verifies requester membership and request authority
after decryption, persists before queue acknowledgement, and acquires separate
native Service authority before canonical command admission.

## Current qualification evidence

The focused tests cover:

- invalid/changed reviewed-brief hashes and closed intake parsing;
- duplicate and split idempotency identities;
- local commit before acknowledgement and lost acknowledgement redelivery;
- post-commit lost Service response and exact retry without duplicate audit;
- restart recovery using the retained command;
- rejection when transport is authenticated but requester membership is absent;
- Vercel SDK delivery acknowledgement only after successful local persistence;
- pinned Zenith membership v3, Wallet Auth v2 credential and Member Key
  verification over exact intake bytes at authenticated Queue acceptance time;
- rejection of altered membership, altered intake, expired-at-arrival proofs,
  unknown evidence fields and untrusted receipt sources;
- fixed-shape receiver credential issuance, caller/policy/key pins, membership
  denial and signer substitution/length failure;
- native secS executable pinning, closed response framing, bounded envelope
  admission, and fail-closed handling of key/configuration failures.

These are integration-ready source tests. The secS envelope and native opener
are implemented and source-qualified in PR #302 but are not yet a released
artifact. The requester verifier is source-qualified but still needs released
composition with the real public issuer pins. Production remains blocked on the
secS release, a deployed gateway/queue with confirmed owner cost, operator OIDC
provisioning, released receiver credential signer/endpoint composition, merged
Wallet workspace authority, installed/configured native pins, and one released
end-to-end namespaced workflow execution with real artifacts.

## One-shot local worker commands

The `service-management-provider` entry point keeps transport consumption and
canonical admission explicit:

```text
service-management-provider pull-once \
  --intake-database /private/provider/intake.db \
  --region <released-region> --topic <released-topic> \
  --consumer-group <one-provider-installation> \
  --intake-opener /private/provider/bin/secs-provider-intake-v1 \
  --intake-opener-sha256 <released-sha256> \
  --oidc-token-file /private/provider/vercel-oidc-token

service-management-provider pull-references-once \
  --intake-database /private/provider/intake.db \
  --region <released-region> --topic <released-reference-topic> \
  --consumer-group <one-provider-installation-reference-group> \
  --intake-opener /private/provider/bin/secs-provider-intake-v1 \
  --intake-opener-sha256 <released-sha256> \
  --oidc-token-file /private/provider/vercel-oidc-token

service-management-provider admit-once \
  --intake-database /private/provider/intake.db \
  --service-database /private/provider/service.db \
  --requester-policy /private/provider/requester-policy.json \
  --native-verifier /private/provider/bin/process-runtime-secs-check \
  --native-verifier-sha256 <released-sha256> \
  --receiver-policy /private/provider/service-receiver.json \
  --wallet-command /private/provider/bin/castalia-wallet-service \
  --wallet-command-sha256 <released-sha256> \
  --wallet-configuration /private/provider/wallet-command.json \
  --wallet-configuration-sha256 <reviewed-sha256>
```

Run `resume-admission-once` with the same admission arguments after an uncertain
Wallet/output outcome. It selects only held rows and invokes only Wallet
`resume`; `admit-once` selects only fresh rows. The worker reads Vercel OIDC
from one absolute, owner-private regular file (mode `0600`) and passes it to the
official SDK in memory. The credential is never placed in argv, inherited
environment, worker output or browser state. It accepts no browser token,
Wallet key, Service key, or arbitrary operation on its command line.

After admission, `advance-brand-package-once` advances at most one command for
each retained `zenith.anima.brand-package` request. It accepts the same pinned
Service verifier and Wallet arguments plus the Runtime endpoint, the four
Runtime Wallet command/configuration pins, and the reviewed
`process_id`/`process_version`/`compilation_hash` tuple. The fixed progression is:

1. qualify and accept the canonical ServiceRequest;
2. convert it to a deterministic Case and record its plan scope;
3. commit the exact reviewed brief and `service.reference-manifest.v2` as two
   content-addressed Runtime artifacts; the latter embeds the verified original
   bytes for the initial zero-or-one-reference profile;
4. approve the Case plan with those artifact references, the organization name,
   and the exact immutable `zenith.anima.brand-package` process pin.

Every command is stored before authority acquisition. An uncertain Service or
Runtime result remains held and is excluded from fresh work. Run
`resume-brand-package-once` with the identical arguments to recover only the
stored command through the corresponding native resume operation. Approval
creates the ordinary durable Service outbox handoff; the separately configured
outbox worker delivers that exact command to Runtime. Neither lifecycle command
infers execution completion from the handoff acknowledgement.

`activation-brand-package-once` reads one admitted, unfinished intake without
issuing authority or changing either database. It returns the exact future
64-hex Runtime handoff ID and deterministic `handoff-<first-48-hex>` Run ID.
The handoff event identity is derived from the stable Case and immutable plan
revision IDs, so the later `approved` result must return the same activation.
The installer binds Runtime authority to both previewed values before lifecycle
artifact writes; inventing either identity or granting only the Run is not
sufficient for `artifact.put` and `handoff.consume`.

After the installer has bound that authority and explicitly opened Runtime
new-run admission, `deliver-handoff-once --handoff-id <exact-64-hex>` scans at
most 10,000 pending outbox records and reconciles only the matching handoff. It
uses the exact Runtime Wallet command/configuration pins. A prior unknown result
is recovered through the SDK's explicit resume path; a different pending
handoff is never consumed by that invocation.
