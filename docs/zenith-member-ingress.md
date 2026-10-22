# Zenith member ingress for service requests

Status: integration design; no new authority adapter is qualified by this document

Anima is one producer of Service Management commands. It does not create a parallel service lifecycle or authorize commands from a Web session.

## Producer flow

1. Anima verifies Wallet possession and active Zenith membership.
2. Anima resolves the member's Rolodex registration and checks the ontology requirements for the chosen service.
3. The member supplies the closed service inputs.
4. A trusted producer obtains receiver-verifiable authority for the exact Service Management operation and resource.
5. Anima submits the unchanged `service.command.v1` command and preserves its exact `request_id` for retry.

The initial operation is `request.create`. Qualification, acceptance, conversion, planning, and closure remain separate authorized commands owned by Service Management.

## Authority mapping

Zenith membership is admission to Anima, not authority to mutate every service object. A future adapter may map a valid member credential and Wallet-approved request to narrowly scoped secS evidence, subject to receiver policy. The receiver must still verify operation, resource, audience, expiry, revocation, request digest, replay state, and policy.

An Anima referral, Rolodex Actor reference, Nostr key, Matrix identity, display name, browser session, or caller-supplied Member Key grants no command authority. The internal verified subject should remain stable for idempotency, while optional registry references remain non-authoritative metadata outside the closed v1 command until a versioned contract admits them.

## End-to-end receipt

Anima should retain and display:

- the `request.create` request ID and ServiceRequest version;
- later Case identity and plan revision;
- runtime handoff disposition;
- redacted progress summaries;
- deliverable/artifact references; and
- final service and runtime receipts.

The browser must retry an uncertain result with the exact original command and request ID. It must never guess a new version or create a second request after a lost response.

## Compatibility

The first integration should use existing command fields and keep identity/registry linkage in the producer's local state or a separately versioned reference contract. Changing `service.command.v1` requires synchronized schema, parser, storage, fixtures, producer, migration, and retained-retry tests.

Related documents:

- `README.md`
- `docs/command-api.md`
- `docs/receiver-authority-v1.md`
- `docs/adr/0001-service-domain-and-command-boundary.md`
