import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import {readFile} from "node:fs/promises";
import test from "node:test";
import {fileURLToPath} from "node:url";
import {dirname, resolve} from "node:path";
import {clientReadAuthorizationBytes, deriveDisplayState, encryptedIntakeAuthorizationBytes, encryptedReferenceAuthorizationBytes, parseClientProjection, parseIntakeResult, parseProviderCatalog, ServiceClient, ServiceClientError, validateIntake, type IntakeRequest, type ProviderCatalogV2, type ProviderCatalogV3, type ProviderCatalogV4} from "../src/index.ts";

const here = dirname(fileURLToPath(import.meta.url));
async function fixture(name: string): Promise<any> { return JSON.parse(await readFile(resolve(here, "../fixtures", name), "utf8")); }

test("published fixtures parse and retain canonical distinctions", async () => {
  const catalog = parseProviderCatalog(await fixture("provider-catalog.fixture.json"));
  const request = await fixture("intake-request.fixture.json") as IntakeRequest;
  validateIntake(request, catalog);
  const pending = parseIntakeResult(await fixture("intake-pending.fixture.json"));
  assert.equal(pending.state, "pending");
  assert.equal(pending.service_request_id, null);
  const delivered = parseClientProjection(await fixture("request-delivered.fixture.json"));
  assert.equal(deriveDisplayState(delivered), "delivered");
  assert.equal(delivered.receipts[0].verification.state, "unverified");
});

test("closed readers reject unknown fields and versions", async () => {
  const catalog = await fixture("provider-catalog.fixture.json");
  catalog.unreviewed = true;
  assert.throws(() => parseProviderCatalog(catalog), ServiceClientError);
  delete catalog.unreviewed;
  catalog.schema = "service.provider-catalog.v5";
  assert.throws(() => parseProviderCatalog(catalog), /Unsupported provider catalog/);
});

test("catalog v4 prepares and retries one exact encrypted original reference", async () => {
  const catalog = parseProviderCatalog(await fixture("provider-catalog-v4.fixture.json")) as ProviderCatalogV4;
  const request = await fixture("intake-request.fixture.json") as IntakeRequest;
  const bytes = new TextEncoder().encode("reference");
  request.references = [{schema: "service.artifact-manifest.v1", artifact_id: "reference-1",
    content_hash: "52367a6622b19f08825e915fad80c542ad4f4c34dbcebad9f5007994b3e39208",
    byte_length: bytes.byteLength, media_type: "image/png", filename: "reference.png"}];
  const evidence = new TextEncoder().encode("same-intake-requester-evidence");
  let sent: RequestInit | undefined;
  const client = new ServiceClient({baseUrl: "https://provider.invalid",
    trustedIntakeOrigins: ["https://intake.zenith.invalid"], authorize: async () => ({}),
    fetch: async (_input, init) => { sent = init; return new Response(JSON.stringify({schema: "service.reference-object-result.v1", request_id: request.request_id, idempotency_key: request.idempotency_key, artifact_id: "reference-1", content_hash: request.references[0].content_hash, state: "pending", transport_receipt: {transport: "vercel-queue", receipt_id: "receipt-1", recorded_at: "2026-10-22T08:00:00.000Z", expires_at: "2026-10-23T08:00:00.000Z"}}), {status: 202}); }});
  const prepared = await client.prepareEncryptedReference(request, catalog, request.references[0], bytes, evidence, {sealReferenceObject: async (input) => { assert.deepEqual(input.object, bytes); assert.deepEqual(input.requester_evidence, evidence); return new Uint8Array([5, 4, 3, 2, 1]); }}, Date.parse("2026-10-22T08:00:00.000Z"));
  const authorization = JSON.parse(new TextDecoder().decode(encryptedReferenceAuthorizationBytes(prepared)));
  assert.equal(authorization.schema, "service.encrypted-reference-authorization.v1");
  assert.equal(authorization.artifact_id, "reference-1");
  const result = await client.sendPreparedEncryptedReference(prepared, {authorize: async () => ({Authorization: "fixture-reference-presentation"})}, Date.parse("2026-10-22T08:00:00.001Z"));
  assert.equal(result.state, "pending");
  assert.equal((sent?.headers as Record<string, string>)["Content-Type"], "application/vnd.zenith.service-reference-object-envelope-v1");
  assert.deepEqual(new Uint8Array(sent?.body as ArrayBuffer), new Uint8Array([5, 4, 3, 2, 1]));
});

test("catalog v4 bundle seals request and reference with one exact requester proof", async () => {
  const catalog = parseProviderCatalog(await fixture("provider-catalog-v4.fixture.json")) as ProviderCatalogV4;
  const request = await fixture("intake-request.fixture.json") as IntakeRequest;
  const bytes = new TextEncoder().encode("reference");
  const manifest = {schema: "service.artifact-manifest.v1", artifact_id: "reference-1",
    content_hash: "52367a6622b19f08825e915fad80c542ad4f4c34dbcebad9f5007994b3e39208",
    byte_length: bytes.byteLength, media_type: "image/png", filename: "reference.png"} as const;
  request.references = [manifest];
  const evidence = new TextEncoder().encode("one-exact-requester-proof");
  let evidenceCalls = 0, requestProof: Uint8Array | undefined, referenceProof: Uint8Array | undefined;
  const client = new ServiceClient({baseUrl: "https://provider.invalid",
    trustedIntakeOrigins: ["https://intake.zenith.invalid"], authorize: async () => ({})});
  const prepared = await client.prepareEncryptedBundle(request, catalog,
    {manifest, bytes}, {now: Date.parse("2026-10-22T08:00:00.000Z"),
      authority: {evidence: async () => { evidenceCalls += 1; return evidence; }},
      sealer: {seal: async (input) => { requestProof = new Uint8Array(input.requester_evidence); return new Uint8Array([1]); }},
      referenceSealer: {sealReferenceObject: async (input) => { referenceProof = new Uint8Array(input.requester_evidence); return new Uint8Array([2]); }}});
  assert.equal(evidenceCalls, 1);
  assert.deepEqual(requestProof, referenceProof);
  assert.notEqual(requestProof, evidence);
  assert.deepEqual(prepared.request.envelope, new Uint8Array([1]));
  assert.deepEqual(prepared.reference?.envelope, new Uint8Array([2]));
});

test("catalog v3 publishes closed Castalia requester policy without changing v2", async () => {
  const catalog = parseProviderCatalog(await fixture("provider-catalog-v3.fixture.json")) as ProviderCatalogV3;
  assert.equal(catalog.schema, "service.provider-catalog.v3");
  assert.equal(catalog.requester.evidence_schema, "service.castalia-requester-evidence.v1");
  assert.equal(catalog.requester.membership.roots[0].issuer_id, "zenith-research");
  assert.equal(catalog.requester.credential.endpoint, "https://credentials.zenith.invalid/v1/request-credential");
  assert.equal(catalog.requester.credential.callers[0].id, "https://anima.example");
  const altered = await fixture("provider-catalog-v3.fixture.json");
  altered.requester.credential.callers[0].id = "https://anima.example/path";
  assert.throws(() => parseProviderCatalog(altered), /canonical secure browser origin/);
});

test("catalog recipient key ids match the canonical secS public-key fingerprint", async () => {
  for (const name of ["provider-catalog-v2.fixture.json", "provider-catalog-v3.fixture.json", "provider-catalog-v4.fixture.json"]) {
    const catalog = parseProviderCatalog(await fixture(name)) as ProviderCatalogV2 | ProviderCatalogV3 | ProviderCatalogV4;
    const publicKey = Buffer.from(catalog.intake.envelope.recipient_public_key_hex, "hex");
    const expected = `tunnel:x25519:${createHash("sha256").update(publicKey).digest("hex").slice(0, 32)}`;
    assert.equal(catalog.intake.envelope.recipient_key_id, expected);
    if (catalog.schema === "service.provider-catalog.v4") assert.equal(catalog.reference_objects.envelope.recipient_key_id, expected);
  }
});

test("catalog v2 publishes a bounded secS intake key without breaking v1", async () => {
  const legacy = parseProviderCatalog(await fixture("provider-catalog.fixture.json"));
  assert.equal(legacy.schema, "service.provider-catalog.v1");
  const catalog = parseProviderCatalog(await fixture("provider-catalog-v2.fixture.json"));
  assert.equal(catalog.schema, "service.provider-catalog.v2");
  assert.equal(catalog.intake.envelope.schema, "service.intake-envelope.v1");
  assert.match(catalog.intake.envelope.recipient_key_id, /^tunnel:x25519:/);
  const altered = await fixture("provider-catalog-v2.fixture.json");
  altered.intake.envelope.not_after = altered.intake.envelope.not_before;
  assert.throws(() => parseProviderCatalog(altered), /validity is empty/);
});

test("encrypted submission sends only the sealed envelope to an explicitly trusted gateway", async () => {
  const request = await fixture("intake-request.fixture.json") as IntakeRequest;
  const catalog = parseProviderCatalog(await fixture("provider-catalog-v2.fixture.json")) as ProviderCatalogV2;
  const pending = await fixture("intake-pending.fixture.json");
  let sealedInput: Uint8Array | undefined, sent: {url: string; init?: RequestInit} | undefined;
  const client = new ServiceClient({
    baseUrl: "https://provider.invalid",
    trustedIntakeOrigins: ["https://intake.zenith.invalid"],
    authorize: async () => ({}),
    fetch: async (input, init) => { sent = {url: String(input), init}; return new Response(JSON.stringify(pending), {status: 200, headers: {"Content-Type": "application/json"}}); },
  });
  const result = await client.submitEncrypted(request, catalog, {
    now: Date.parse("2026-10-22T08:00:00.000Z"),
    authority: {
      evidence: async (authorization) => {
        assert.match(authorization.body_digest ?? "", /^[a-f0-9]{64}$/);
        assert.equal(JSON.parse(new TextDecoder().decode(authorization.intake)).request_id, request.request_id);
        authorization.intake.fill(0);
        return new TextEncoder().encode("durable-membership-evidence");
      },
      authorize: async (authorization) => {
        assert.equal(authorization.envelope_digest, "9f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a");
        return {Authorization: "fixture-presentation"};
      },
    },
    sealer: {seal: async ({intake}) => { sealedInput = intake; return new Uint8Array([1, 2, 3, 4]); }},
  });
  assert.equal(result.state, "pending");
  // The evidence adapter receives an owned copy and cannot alter sealed intent.
  assert.equal(JSON.parse(new TextDecoder().decode(sealedInput)).request_id, request.request_id);
  assert.equal(sent?.url, catalog.intake.endpoint);
  assert.deepEqual(new Uint8Array(sent?.init?.body as ArrayBuffer), new Uint8Array([1, 2, 3, 4]));
  const headers = sent?.init?.headers as Record<string, string>;
  assert.equal(headers["Content-Type"], "application/vnd.zenith.service-intake-envelope-v1");
  assert.equal(headers["X-Zenith-Request-Id"], request.request_id);
  assert.equal(headers.Authorization, "fixture-presentation");
});

test("prepared encrypted submission retries the exact envelope without repeating evidence or sealing", async () => {
  const request = await fixture("intake-request.fixture.json") as IntakeRequest;
  const catalog = parseProviderCatalog(await fixture("provider-catalog-v3.fixture.json")) as ProviderCatalogV3;
  const pending = await fixture("intake-pending.fixture.json");
  let evidenceCalls = 0, sealCalls = 0, authorizeCalls = 0, sendCalls = 0;
  const bodies: Uint8Array[] = [];
  const authority = {
    evidence: async () => { evidenceCalls += 1; return new TextEncoder().encode("durable-membership-evidence"); },
    authorize: async () => { authorizeCalls += 1; return {Authorization: `fixture-presentation-${authorizeCalls}`}; },
  };
  const now = Date.parse("2026-10-22T08:00:00.000Z");
  const client = new ServiceClient({
    baseUrl: "https://provider.invalid", trustedIntakeOrigins: ["https://intake.zenith.invalid"], authorize: async () => ({}),
    fetch: async (_input, init) => {
      sendCalls += 1; bodies.push(new Uint8Array(init?.body as ArrayBuffer));
      if (sendCalls === 1) throw new TypeError("ack lost");
      return new Response(JSON.stringify(pending), {status: 200, headers: {"Content-Type": "application/json"}});
    },
  });
  const prepared = await client.prepareEncrypted(request, catalog, {now, authority, sealer: {seal: async () => { sealCalls += 1; return new Uint8Array([9, 8, 7, 6]); }}});
  const gatewayAuthorization = JSON.parse(new TextDecoder().decode(encryptedIntakeAuthorizationBytes(prepared)));
  assert.deepEqual(Object.keys(gatewayAuthorization).sort(), ["envelope_digest_sha256", "envelope_expires_at_ms", "idempotency_key", "intake_digest_sha256", "provider_id", "recipient_key_id", "request_id", "schema"]);
  assert.equal(gatewayAuthorization.envelope_digest_sha256, prepared.envelope_digest);
  await assert.rejects(client.sendPreparedEncrypted(prepared, authority, now), (error: unknown) => error instanceof ServiceClientError && error.uncertain);
  const result = await client.sendPreparedEncrypted(prepared, authority, now + 1);
  assert.equal(result.state, "pending");
  assert.equal(evidenceCalls, 1); assert.equal(sealCalls, 1); assert.equal(authorizeCalls, 2);
  assert.deepEqual(bodies[0], bodies[1]);
  prepared.envelope[0] ^= 0xff;
  await assert.rejects(client.sendPreparedEncrypted(prepared, authority, now + 2), /was changed/);
});

test("catalog metadata cannot redirect encrypted authorization to an untrusted origin", async () => {
  const request = await fixture("intake-request.fixture.json") as IntakeRequest;
  const catalog = parseProviderCatalog(await fixture("provider-catalog-v2.fixture.json")) as ProviderCatalogV2;
  const client = new ServiceClient({baseUrl: "https://provider.invalid", authorize: async () => ({})});
  await assert.rejects(client.submitEncrypted(request, catalog, {
    now: Date.parse("2026-10-22T08:00:00.000Z"),
    authority: {evidence: async () => { throw new Error("must not run"); }, authorize: async () => ({})},
    sealer: {seal: async () => new Uint8Array([1])},
  }), /not explicitly trusted/);
});

test("credential issuance sends only public membership and exact digests to an explicitly trusted endpoint", async () => {
  let sent: {url: string; init?: RequestInit} | undefined;
  const claims = {schema: "castalia.request-credential.v1" as const, issuer: "zenith-service-authority", key_id: "request-1", holder_public_key: "22".repeat(32), audience: "zenith-service-management", caller: {kind: "browser" as const, id: "https://anima.example"}, request_digest_sha256: "33".repeat(32), disclosure_digest_sha256: "44".repeat(32), policy_digest_sha256: "55".repeat(32), nonce: "66".repeat(16), issued_at: 100, expires_at: 220};
  const client = new ServiceClient({baseUrl: "https://provider.invalid", trustedCredentialOrigins: ["https://credentials.zenith.invalid"], authorize: async () => ({}), fetch: async (input, init) => { sent = {url: String(input), init}; return new Response(JSON.stringify({claims, signature: "77".repeat(64)}), {status: 200, headers: {"Content-Type": "application/json"}}); }});
  const membership = {schema: "castalia.zenith-membership-credential.v3" as const, version: 3 as const, membershipId: "11".repeat(32), ownerPublicKey: "22".repeat(32), status: "active" as const, issuerId: "zenith-research", issuerKeyId: "membership-1", signatureSuite: "Ed25519" as const, issuerSignature: "A".repeat(86)};
  const credential = await client.requestCredential("https://credentials.zenith.invalid/v1/request-credential", {schema: "service.castalia-credential-issuance.v1", membership, request_digest_sha256: "33".repeat(32), disclosure_digest_sha256: "44".repeat(32), caller: {kind: "browser", id: "https://anima.example"}, nonce: "66".repeat(16)});
  assert.equal(credential.claims.holder_public_key, membership.ownerPublicKey);
  assert.equal(sent?.url, "https://credentials.zenith.invalid/v1/request-credential");
  const posted = JSON.parse(new TextDecoder().decode(sent?.init?.body as ArrayBuffer));
  assert.deepEqual(Object.keys(posted).sort(), ["caller", "disclosure_digest_sha256", "membership", "nonce", "request_digest_sha256", "schema"]);

  await assert.rejects(client.requestCredential("https://attacker.invalid/v1/request-credential", {schema: "service.castalia-credential-issuance.v1", membership, request_digest_sha256: "33".repeat(32), disclosure_digest_sha256: "44".repeat(32), caller: {kind: "browser", id: "https://anima.example"}, nonce: "66".repeat(16)}), /not explicitly trusted/);
});

test("network loss preserves an uncertain exact retry", async () => {
  const request = await fixture("intake-request.fixture.json") as IntakeRequest;
  const client = new ServiceClient({
    baseUrl: "https://provider.invalid",
    authorize: async () => ({Authorization: "test-only"}),
    fetch: async () => { throw new TypeError("network lost"); },
  });
  await assert.rejects(client.submit(request), (error: unknown) => {
    assert.ok(error instanceof ServiceClientError);
    assert.equal(error.uncertain, true);
    assert.equal(error.retryable, true);
    return true;
  });
});

test("closed provider errors do not become uncertain after explicit denial", async () => {
  const request = await fixture("intake-request.fixture.json") as IntakeRequest;
  const body = await fixture("forbidden.fixture.json");
  const client = new ServiceClient({
    baseUrl: "https://provider.invalid",
    authorize: async () => ({Authorization: "test-only"}),
    fetch: async () => new Response(JSON.stringify(body), {status: 403, headers: {"Content-Type": "application/json"}}),
  });
  await assert.rejects(client.submit(request), (error: unknown) => {
    assert.ok(error instanceof ServiceClientError);
    assert.equal(error.code, "forbidden");
    assert.equal(error.uncertain, false);
    return true;
  });
});

test("provider-returned links cannot move authority to another origin", async () => {
  const client = new ServiceClient({baseUrl: "https://provider.example", authorize: async () => ({Authorization: "test-only"})});
  await assert.rejects(client.status("https://attacker.example/status", "anima-brand-request-01"), /not explicitly trusted/);
});

test("an explicitly trusted response origin receives only exact read authority", async () => {
  let sent: {url: string; authorization?: string} | undefined;
  const projection = await fixture("request-delivered.fixture.json");
  const client = new ServiceClient({
    baseUrl: "https://provider.example",
    trustedReadOrigins: ["https://operator-response.example"],
    authorize: async (request) => {
      assert.equal(request.operation, "request.status");
      assert.equal(request.resource, "requests/anima-brand-request-01");
      assert.equal(request.method, "GET");
      assert.equal(request.body_digest, null);
      return {Authorization: "Castalia exact-read-presentation"};
    },
    fetch: async (input, init) => {
      sent = {url: String(input), authorization: (init?.headers as Record<string, string>).Authorization};
      return new Response(JSON.stringify(projection), {status: 200, headers: {"Content-Type": "application/json"}});
    },
  });
  assert.equal((await client.status("https://operator-response.example/v1/client/requests/anima-brand-request-01", "anima-brand-request-01")).request_id, "anima-brand-request-01");
  assert.deepEqual(sent, {url: "https://operator-response.example/v1/client/requests/anima-brand-request-01", authorization: "Castalia exact-read-presentation"});
});

test("an unknown submission can reconcile from the configured path-mounted response base", async () => {
  let sent = "";
  const projection = await fixture("request-delivered.fixture.json");
  const client = new ServiceClient({
    baseUrl: "https://provider.example",
    trustedReadOrigins: ["https://operator-response.example"],
    responseBaseUrl: "https://operator-response.example/zenith/provider",
    authorize: async (request) => {
      assert.equal(request.operation, "request.status");
      assert.equal(request.resource, "requests/anima-brand-request-01");
      return {Authorization: "Castalia exact-read-presentation"};
    },
    fetch: async (input) => {
      sent = String(input);
      return new Response(JSON.stringify(projection), {status: 200, headers: {"Content-Type": "application/json"}});
    },
  });
  assert.equal((await client.statusForRequest("anima-brand-request-01")).request_id, "anima-brand-request-01");
  assert.equal(sent, "https://operator-response.example/zenith/provider/v1/client/requests/anima-brand-request-01");
  assert.throws(() => new ServiceClient({baseUrl: "https://provider.example", trustedReadOrigins: ["https://operator-response.example"], responseBaseUrl: "https://attacker.example/zenith/provider", authorize: async () => ({})}), /not explicitly trusted/);
});

test("client reads bind the exact operation and resource without URL or secrets", () => {
  const bytes = clientReadAuthorizationBytes({operation: "request.status", resource: "requests/request-1", method: "GET", body_digest: null});
  assert.deepEqual(JSON.parse(new TextDecoder().decode(bytes)), {
    schema: "service.client-read-authorization.v1",
    operation: "request.status",
    resource: "requests/request-1",
  });
  assert.throws(() => clientReadAuthorizationBytes({operation: "artifact.get", resource: "requests/request-1", method: "GET", body_digest: null}), /Invalid client read resource/);
});

test("unknown or stale runtime projections remain unknown", async () => {
  const delivered = parseClientProjection(await fixture("request-delivered.fixture.json"));
  delivered.execution!.freshness = "stale";
  assert.equal(deriveDisplayState(delivered), "unknown");
  delivered.execution!.freshness = "current";
  delivered.execution!.state = "unknown";
  assert.equal(deriveDisplayState(delivered), "unknown");
});
