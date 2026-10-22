# Service Management TypeScript client 0.8.0

Status: **integration-ready contract package**. The fixtures are explicitly
illustrative and do not claim that the Zenith brand-package provider is deployed.

This package gives Anima and other provider-neutral clients a stable browser
boundary over the existing Service Management and Process Runtime owners. It does
not implement either service, issue authority, create membership, or treat a
transport acknowledgement as service admission.

## Operations

| Client method | HTTP operation | Canonical owner |
| --- | --- | --- |
| `catalog()` | `GET /v1/provider` | Provider publishes its service descriptions |
| `putArtifact()` | `PUT /v1/client/artifacts/{sha256}` | Intake store until consumed; Runtime owns committed execution artifacts |
| `submit()` | `POST /v1/client/requests` | Intake transport accepts pending work; Service Management owns admitted ServiceRequests |
| `prepareEncrypted()` + `sendPreparedEncrypted()` | Provider-catalog v2/v3 `intake.endpoint` | Browser seals once, persists resumable ciphertext, then sends or retries those exact bytes |
| `submitEncrypted()` | Provider-catalog v2/v3 `intake.endpoint` | Convenience prepare-and-send wrapper for callers that do not need resumable recovery |
| `requestCredential()` | Catalog v3 credential endpoint on an explicitly trusted origin | Requests the existing short-lived Wallet Auth v2 credential after presenting an active public Zenith membership credential |
| `encryptedIntakeAuthorizationBytes()` | Local helper | Produces the exact canonical public gateway request for the outer Wallet credential and presentation |
| `clientReadAuthorizationBytes()` | Local helper | Produces the exact canonical request bound by status, artifact and receipt Wallet presentations |
| `status()` | `GET /v1/client/requests/{request_id}` | Adapter projects Service Management plus redacted Runtime state |
| `artifact()` | descriptor `href` | Publishing component owns bytes; adapter enforces access and digest |
| `receipt()` | receipt-reference `href` | Named receipt owner remains authoritative |

The authorization callback receives the exact method, URL, logical operation,
resource and body digest. A provider may use a receiver-issued Web session or a
Wallet/secS presentation. The callback's headers are opaque to this client. The
package never treats Matrix identity, Nostr transport signing, Tailscale
membership, email verification, or a provider descriptor as service authority.

For status, artifact and receipt reads, `clientReadAuthorizationBytes()`
canonicalizes the fixed `service.client-read-authorization.v1` value bound by
the current short-lived Wallet credential and presentation. The provider checks
that presentation, then independently checks the requesting Member Key against
the retained ServiceRequest before reading local Runtime artifacts or receipts.

Discovery is public. Submission, status, artifact and receipt access require the
provider's receiver-issued authority. The provider verifies its own audience,
operation, resource, expiry, revocation, request digest and replay policy.

`service.provider-catalog.v1` remains readable for existing fixtures and local
integration. Production encrypted intake uses `service.provider-catalog.v3`,
which includes the v2 gateway endpoint, retention and bounded envelope key plus
the accepted Zenith membership roots and receiver credential endpoint/pins.
These are public trust configuration, not authority. Catalog v2 remains readable
for earlier encrypted-intake integration. A client must obtain the catalog from
its configured provider and explicitly trust any separate gateway, credential or
read origin; catalog metadata and returned links cannot silently expand those
origin sets. `trustedReadOrigins` permits a provider to keep intake online while
serving canonical status and delivery bytes from an operator-controlled HTTPS
origin. The application, rather than the response payload, selects that trust.

`prepareEncrypted()` canonicalizes and validates the reviewed request, gives an
owned copy of those exact bytes to the requester-evidence adapter, obtains
deterministic requester evidence, and
supplies the exact intake and evidence bytes to a released secS-compatible
sealer. Persist the returned `PreparedEncryptedSubmission` in local IndexedDB
before the first send. `sendPreparedEncrypted()` rechecks the ciphertext digest,
obtains fresh gateway authorization bound to that same envelope digest, and sends
the retained bytes. Evidence and sealing run once across retries. A network
failure remains an unknown outcome; retry the same prepared object until its
published expiry, then reconcile through the stable request/status identity.
The `submitEncrypted()` wrapper performs both steps but cannot return the prepared
object after an exception, so durable clients use the split API. Only the sealed
envelope and bounded public routing headers reach the intake endpoint. The
legacy `submit()` plaintext method remains available for v1/local integration;
it is not the production public-gateway path.

The production adapter uses two independently verified Wallet presentations. The
first is inside the secS envelope and binds the active membership to the exact
canonical intake. After sealing, call `encryptedIntakeAuthorizationBytes()` on
the prepared object, obtain a second short-lived receiver credential and Wallet
presentation over those bytes, and return that closed
`service.castalia-gateway-presentation.v1` value from `authority.authorize()` as
an unpadded base64url `Authorization: Castalia …` header. The public gateway can
then authorize the ciphertext and routing metadata without learning the brief.

`requestCredential()` sends only the active public membership credential, exact
request/disclosure digests, caller and nonce to an explicitly trusted endpoint.
The returned `castalia.request-credential.v1` is structurally parsed but is not
trusted by parsing: Castalia Wallet verifies its configured issuer pin before
approval, and the provider Mac independently verifies the issuer, membership,
Member Key presentation, exact intake and Queue acceptance time. The endpoint
never receives wallet private material or Service Management command authority.

## Retry and status rules

- `request_id` is the stable logical request and future ServiceRequest identity.
- `idempotency_key` is the stable command identity. Retry the exact same body and
  key after network loss or an HTTP 5xx outcome.
- `pending` means an online transport retained the bounded request. It does not
  mean the operator Mac persisted it or Service Management admitted it.
- `admitted` must include the canonical ServiceRequest identity and version.
- A closed 4xx error is known rejection. Network failure and malformed success
  acknowledgements remain uncertain.
- Poll the returned `status_url`; never invent a replacement request to learn an
  uncertain outcome.
- UI display state is derived from the retained transport, ServiceRequest, Case,
  Runtime and deliverable fields. Unknown or stale projection state stays visible.
- `brief.content_hash` is SHA-256 over the UTF-8 bytes of the package's canonical
  JSON encoding of `brief.values`: object keys sorted lexicographically, arrays in
  source order, no insignificant whitespace, and ordinary JSON primitive encoding.
  A complete selected Anima `anima.brand-brief.v1` value belongs under
  `values.anima_brief`; its own source digest remains a separate field inside that
  value. Submission rejects a digest that does not bind the exact reviewed values.

## Artifacts and receipts

The browser hashes artifact bytes before upload and after download. The provider
must persist and verify the same immutable manifest. Local filesystem paths are
never contract data.

Receipt references name the existing owner and schema. The current
`runtime.receipt.v1` signature is `null`; such a receipt may be internally
consistent but is not cryptographically authored, so the projection must not mark
it `verified` merely because it exists. secS and Service Management evidence remain
separate canonical records.

Provider-returned status, artifact and receipt links are restricted to the
configured provider origin plus any application-configured `trustedReadOrigins`.
Fetches omit ambient browser credentials and reject redirects; receiver-issued
authorization is supplied only by the explicit `authorize` callback. The current
Zenith candidate uses this option for a GET-only Tailscale Funnel origin. Public
Anima users access its ordinary HTTPS URL and do not join the provider tailnet.

## Compatibility

Version 0.8.0 reads the exact closed `*.v1` envelopes in this package and closed
provider-catalog v1, v2 and v3. It adds the v4 contract bundle for the read-
authorization value while preserving the frozen v1-v3 bundles. Unknown fields
or versions fail closed.
Its evidence callback receives the exact canonical intake bytes needed to build
`service.castalia-requester-evidence.v1`; the view is an owned copy and cannot
mutate the request passed to the envelope sealer.
Each catalog revision is a new closed envelope, so existing v1/v2 consumers and
fixtures remain valid. Existing
`service.command.v1`, `service.result.v1`, `service.query.v1`,
`service.query-result.v1`, `service.runtime-handoff.v1` and
`runtime.receipt.v1` meanings are unchanged.

Run the dependency-free contract tests with Node 26 or later:

```sh
npm test
```

The package is checked with strict TypeScript 5.9 DOM types:

```sh
npm run typecheck
```

Anima may implement provider discovery, reviewed-intake composition, exact retry,
pending/admitted/rejected states, canonical status rendering and deliverable /
receipt surfaces against these fixtures now. Live submission remains dependent on
the provider adapter, reachable inbox and qualified authority described in the
repository integration guide.
