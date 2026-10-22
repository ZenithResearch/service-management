export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };
export type Identifier = string;
export type Sha256 = string;

export interface ProviderIdentity { id: Identifier; name: string; version: string; }
export interface InputField { id: Identifier; label: string; type: "string" | "integer" | "number" | "boolean"; required: boolean; description: string; max_length: number | null; }
export interface ReferenceRequirement { id: Identifier; label: string; required: boolean; media_types: string[]; max_bytes: number; }
export interface DeliverableExpectation { id: Identifier; label: string; media_types: string[]; multiple: boolean; }
export interface ProcessPin { process_id: string; process_version: string; compilation_hash: Sha256; }
export interface ProviderService {
  id: Identifier; version: string; name: string; summary: string;
  availability: "available" | "paused" | "preview";
  inputs: InputField[]; accepted_references: ReferenceRequirement[];
  expected_deliverables: DeliverableExpectation[]; process: ProcessPin | null;
  communication: Array<"provider-status" | "matrix">;
}
export interface ProviderAuthority {
  submission: "receiver-issued"; status: "receiver-issued"; artifacts: "receiver-issued";
}
export interface IntakeEnvelopeProfile {
  schema: "service.intake-envelope.v1";
  algorithm: "x25519-hkdf-sha256-chacha20poly1305";
  recipient_key_id: string; recipient_public_key_hex: string;
  not_before: string; not_after: string;
}
export interface ProviderCatalogV1 {
  schema: "service.provider-catalog.v1"; provider: ProviderIdentity; services: ProviderService[];
  authority: { submission: "receiver-issued"; status: "receiver-issued"; artifacts: "receiver-issued"; };
}
export interface ProviderCatalogV2 {
  schema: "service.provider-catalog.v2"; provider: ProviderIdentity; services: ProviderService[];
  authority: ProviderAuthority;
  intake: { endpoint: string; max_retention_seconds: number; envelope: IntakeEnvelopeProfile; };
}
export interface ZenithMembershipRoot {
  issuer_id: Identifier; key_id: Identifier; public_key_hex: Sha256;
}
export interface PublishedRequesterProfile {
  evidence_schema: "service.castalia-requester-evidence.v1";
  membership: {
    credential_schema: "castalia.zenith-membership-credential.v3";
    issuer_origin: string; roots: ZenithMembershipRoot[];
  };
  credential: {
    endpoint: string;
    issuance_schema: "service.castalia-credential-issuance.v1";
    credential_schema: "castalia.request-credential.v1";
    presentation_protocol: "castalia.wallet-auth.v2";
    issuer: string; key_id: Identifier; public_key_hex: Sha256;
    audience: string; policy_digest_sha256: Sha256; callers: PresentationCaller[];
  };
}
export interface ProviderCatalogV3 {
  schema: "service.provider-catalog.v3"; provider: ProviderIdentity; services: ProviderService[];
  authority: ProviderAuthority;
  intake: { endpoint: string; max_retention_seconds: number; envelope: IntakeEnvelopeProfile; };
  requester: PublishedRequesterProfile;
}
export type ProviderCatalog = ProviderCatalogV1 | ProviderCatalogV2 | ProviderCatalogV3;
export type EncryptedProviderCatalog = ProviderCatalogV2 | ProviderCatalogV3;
export interface ArtifactManifest {
  schema: "service.artifact-manifest.v1"; artifact_id: Identifier; content_hash: Sha256;
  byte_length: number; media_type: string; filename: string;
}
export interface ReviewedBrief { schema: "service.reviewed-brief.v1"; revision: number; content_hash: Sha256; values: Record<string, JsonValue>; }
export interface IntakeRequest {
  schema: "service.intake.v1"; request_id: Identifier; idempotency_key: Identifier;
  service: { provider_id: Identifier; service_id: Identifier; service_version: string; };
  brief: ReviewedBrief; references: ArtifactManifest[]; submitted_at: string;
}
export interface PresentationCaller { kind: "browser" | "terminal"; id: string; }
export interface ZenithMembershipCredentialV3 {
  schema: "castalia.zenith-membership-credential.v3"; version: 3;
  membershipId: Sha256; ownerPublicKey: Sha256; status: "active";
  issuerId: string; issuerKeyId: string; signatureSuite: "Ed25519"; issuerSignature: string;
}
export interface CastaliaCredentialIssuanceRequestV1 {
  schema: "service.castalia-credential-issuance.v1";
  membership: ZenithMembershipCredentialV3; request_digest_sha256: Sha256;
  disclosure_digest_sha256: Sha256; caller: PresentationCaller; nonce: string;
}
export interface RequestCredentialClaimsV1 {
  schema: "castalia.request-credential.v1"; issuer: string; key_id: string;
  holder_public_key: Sha256; audience: string; caller: PresentationCaller;
  request_digest_sha256: Sha256; disclosure_digest_sha256: Sha256;
  policy_digest_sha256: Sha256; nonce: string; issued_at: number; expires_at: number;
}
export interface RequestCredentialV1 { claims: RequestCredentialClaimsV1; signature: string; }
export interface TransportReceipt { transport: string; receipt_id: Identifier; recorded_at: string; expires_at: string | null; }
export interface IntakeResult {
  schema: "service.intake-result.v1"; request_id: Identifier; idempotency_key: Identifier;
  state: "pending" | "admitted" | "rejected"; transport_receipt: TransportReceipt | null;
  service_request_id: Identifier | null; service_request_version: number | null; status_url: string;
}
export interface ReceiptReference {
  schema: "service.receipt-reference.v1"; owner: "service-management" | "process-runtime" | "secs";
  receipt_schema: string; receipt_id: Identifier; content_hash: Sha256; recorded_at: string;
  verification: { state: "verified" | "unverified" | "failed"; verifier: string | null; detail: string | null; };
  href: string;
}
export interface DeliverableDescriptor { id: Identifier; version: number; label: string; artifact: ArtifactManifest; href: string; receipt_ids: Identifier[]; }
export interface ServiceRequestProjection { id: Identifier; state: "intake" | "qualified" | "accepted" | "rejected"; version: number; case_id: Identifier | null; }
export interface CaseProjection { id: Identifier; state: "open" | "planned" | "closed"; version: number; current_plan_revision_id: Identifier | null; }
export interface ExecutionProjection {
  run_id: string | null; state: "awaiting_plan" | "pending" | "running" | "blocked" | "succeeded" | "failed" | "cancelled" | "unknown";
  freshness: "current" | "catching_up" | "stale" | "gap" | "unavailable"; observed_at: string | null;
}
export interface ClientProjection {
  schema: "service.client-projection.v1"; request_id: Identifier; idempotency_key: Identifier;
  provider_id: Identifier; service_id: Identifier;
  transport: { state: "pending" | "consumed" | "expired" | "failed"; receipt: TransportReceipt | null; };
  service_request: ServiceRequestProjection | null; case: CaseProjection | null; execution: ExecutionProjection | null;
  deliverables: DeliverableDescriptor[]; receipts: ReceiptReference[]; updated_at: string; retry_after_ms: number | null;
}
export interface ClientErrorBody {
  schema: "service.client-error.v1"; request_id: Identifier | null;
  error: { code: "invalid_request" | "forbidden" | "not_found" | "conflict" | "expired" | "unavailable" | "internal_error"; message: string; retryable: boolean; };
}
export type DisplayState = "submitting" | "pending-provider" | "accepted" | "qualification-needed" | "planned" | "running" | "review-needed" | "delivered" | "rejected" | "failed" | "unknown";
export interface AuthorizationRequest {
  operation: "artifact.put" | "request.submit" | "request.status" | "artifact.get" | "receipt.get";
  resource: string; method: "GET" | "PUT" | "POST"; url: string; body_digest: Sha256 | null;
}
export interface ClientReadAuthorizationV1 {
  schema: "service.client-read-authorization.v1";
  operation: "request.status" | "artifact.get" | "receipt.get";
  resource: string;
}
export type Authorize = (request: AuthorizationRequest) => Promise<Record<string, string>>;
export interface EncryptedAuthorizationRequest extends AuthorizationRequest {
  provider_id: Identifier; request_id: Identifier; idempotency_key: Identifier;
  recipient_key_id: string; expires_at_ms: number;
}
export interface EncryptedGatewayAuthorizationRequest extends EncryptedAuthorizationRequest {
  envelope_digest: Sha256;
}
export interface RequesterEvidenceRequest extends EncryptedAuthorizationRequest {
  /** Owned exact canonical intake bytes. Mutating this view cannot alter the sealed request. */
  intake: Uint8Array;
}
export interface EncryptedSubmissionAuthority {
  evidence(request: RequesterEvidenceRequest): Promise<Uint8Array>;
  authorize(request: EncryptedGatewayAuthorizationRequest): Promise<Record<string, string>>;
}
export interface IntakeEnvelopeSealer {
  seal(input: { intake: Uint8Array; requester_evidence: Uint8Array;
    profile: IntakeEnvelopeProfile; expires_at_ms: number; }): Promise<Uint8Array>;
}
export interface PreparedEncryptedSubmission {
  /** SDK-local resumable state. Persist this exact object before the first send. */
  endpoint: string; envelope: Uint8Array; envelope_digest: Sha256; intake_digest: Sha256;
  provider_id: Identifier; request_id: Identifier; idempotency_key: Identifier;
  recipient_key_id: string; expires_at_ms: number;
}
export interface EncryptedIntakeAuthorizationV1 {
  schema: "service.encrypted-intake-authorization.v1";
  provider_id: Identifier; request_id: Identifier; idempotency_key: Identifier;
  intake_digest_sha256: Sha256; envelope_digest_sha256: Sha256;
  recipient_key_id: string; envelope_expires_at_ms: number;
}

const identifierPattern = /^[a-z0-9][a-z0-9._-]{0,127}$/;
const hashPattern = /^[a-f0-9]{64}$/;
const noncePattern = /^[a-f0-9]{32}$/;
const signatureHexPattern = /^[a-f0-9]{128}$/;
const visibleAsciiPattern = /^[!-~]{1,255}$/;
const maxEncryptedEnvelope = 328032;
const maxRequesterEvidence = 262144;

export class ServiceClientError extends Error {
  readonly code: string; readonly retryable: boolean; readonly uncertain: boolean; readonly status: number | null;
  constructor(code: string, message: string, options: { retryable?: boolean; uncertain?: boolean; status?: number | null } = {}) {
    super(message); this.name = "ServiceClientError"; this.code = code;
    this.retryable = options.retryable ?? false; this.uncertain = options.uncertain ?? false; this.status = options.status ?? null;
  }
}

function record(value: unknown, label: string): Record<string, unknown> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) throw new ServiceClientError("incompatible_response", `${label} must be an object`);
  return value as Record<string, unknown>;
}
function exact(value: Record<string, unknown>, fields: string[], label: string): void {
  const actual = Object.keys(value).sort(), expected = [...fields].sort();
  if (actual.length !== expected.length || actual.some((field, index) => field !== expected[index])) throw new ServiceClientError("incompatible_response", `${label} has unsupported fields`);
}
function string(value: unknown, label: string, minimum = 1): string { if (typeof value !== "string" || value.length < minimum) throw new ServiceClientError("incompatible_response", `${label} must be a string`); return value; }
function identifier(value: unknown, label: string): Identifier { const result = string(value, label); if (!identifierPattern.test(result)) throw new ServiceClientError("incompatible_response", `${label} must be an identifier`); return result; }
function hash(value: unknown, label: string): Sha256 { const result = string(value, label); if (!hashPattern.test(result)) throw new ServiceClientError("incompatible_response", `${label} must be a SHA-256 digest`); return result; }
function natural(value: unknown, label: string, positive = false): number { if (!Number.isSafeInteger(value) || (value as number) < (positive ? 1 : 0)) throw new ServiceClientError("incompatible_response", `${label} must be an integer`); return value as number; }
function array(value: unknown, label: string): unknown[] { if (!Array.isArray(value)) throw new ServiceClientError("incompatible_response", `${label} must be an array`); return value; }
function oneOf<T extends string>(value: unknown, values: readonly T[], label: string): T { if (typeof value !== "string" || !values.includes(value as T)) throw new ServiceClientError("incompatible_response", `${label} is unsupported`); return value as T; }
function nullableString(value: unknown, label: string): string | null { return value === null ? null : string(value, label); }
function timestamp(value: unknown, label: string): string { const result = string(value, label); if (!result.endsWith("Z") || Number.isNaN(Date.parse(result))) throw new ServiceClientError("incompatible_response", `${label} must be a UTC timestamp`); return result; }
function absoluteHttpUrl(value: unknown, label: string): string { const result = string(value, label); let url: URL; try { url = new URL(result); } catch { throw new ServiceClientError("incompatible_response", `${label} must be an absolute URL`); } if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || url.hash) throw new ServiceClientError("incompatible_response", `${label} is unsupported`); return url.toString(); }

function parseArtifact(value: unknown): ArtifactManifest {
  const item = record(value, "artifact"); exact(item, ["schema", "artifact_id", "content_hash", "byte_length", "media_type", "filename"], "artifact");
  if (item.schema !== "service.artifact-manifest.v1") throw new ServiceClientError("incompatible_version", "Unsupported artifact contract");
  return {schema: item.schema, artifact_id: identifier(item.artifact_id, "artifact_id"), content_hash: hash(item.content_hash, "content_hash"), byte_length: natural(item.byte_length, "byte_length"), media_type: string(item.media_type, "media_type"), filename: string(item.filename, "filename")};
}
function parseTransportReceipt(value: unknown): TransportReceipt {
  const item = record(value, "transport receipt"); exact(item, ["transport", "receipt_id", "recorded_at", "expires_at"], "transport receipt");
  return {transport: string(item.transport, "transport"), receipt_id: identifier(item.receipt_id, "receipt_id"), recorded_at: string(item.recorded_at, "recorded_at"), expires_at: nullableString(item.expires_at, "expires_at")};
}
function parseCaller(value: unknown, label: string): PresentationCaller {
  const item = record(value, label); exact(item, ["kind", "id"], label);
  return {kind: oneOf(item.kind, ["browser", "terminal"] as const, `${label}.kind`), id: string(item.id, `${label}.id`)};
}
function parsePublishedCaller(value: unknown, label: string): PresentationCaller {
  const caller = parseCaller(value, label);
  if (caller.kind === "browser") {
    let url: URL;
    try { url = new URL(caller.id); } catch { throw new ServiceClientError("incompatible_response", `${label}.id must be a browser origin`); }
    if (!["http:", "https:"].includes(url.protocol) || url.username || url.password || url.origin !== caller.id || (url.protocol === "http:" && !["localhost", "127.0.0.1", "[::1]", "::1"].includes(url.hostname))) throw new ServiceClientError("incompatible_response", `${label}.id must be a canonical secure browser origin`);
  }
  return caller;
}
function parseMembership(value: unknown): ZenithMembershipCredentialV3 {
  const item = record(value, "membership"); exact(item, ["schema", "version", "membershipId", "ownerPublicKey", "status", "issuerId", "issuerKeyId", "signatureSuite", "issuerSignature"], "membership");
  if (item.schema !== "castalia.zenith-membership-credential.v3" || item.version !== 3 || item.status !== "active" || item.signatureSuite !== "Ed25519" || typeof item.issuerSignature !== "string" || !/^[A-Za-z0-9_-]{86}$/.test(item.issuerSignature)) throw new ServiceClientError("incompatible_response", "Unsupported membership credential");
  return {schema: item.schema, version: 3, membershipId: hash(item.membershipId, "membershipId"), ownerPublicKey: hash(item.ownerPublicKey, "ownerPublicKey"), status: "active", issuerId: string(item.issuerId, "issuerId"), issuerKeyId: string(item.issuerKeyId, "issuerKeyId"), signatureSuite: "Ed25519", issuerSignature: item.issuerSignature};
}
export function parseRequestCredential(value: unknown): RequestCredentialV1 {
  const root = record(value, "request credential"); exact(root, ["claims", "signature"], "request credential");
  const claims = record(root.claims, "request credential claims"); exact(claims, ["schema", "issuer", "key_id", "holder_public_key", "audience", "caller", "request_digest_sha256", "disclosure_digest_sha256", "policy_digest_sha256", "nonce", "issued_at", "expires_at"], "request credential claims");
  if (claims.schema !== "castalia.request-credential.v1" || typeof root.signature !== "string" || !signatureHexPattern.test(root.signature)) throw new ServiceClientError("incompatible_response", "Unsupported request credential");
  const issuedAt = natural(claims.issued_at, "issued_at"), expiresAt = natural(claims.expires_at, "expires_at", true);
  if (expiresAt <= issuedAt || expiresAt - issuedAt > 120 || typeof claims.nonce !== "string" || !noncePattern.test(claims.nonce)) throw new ServiceClientError("incompatible_response", "Invalid request credential validity");
  return {claims: {schema: claims.schema, issuer: string(claims.issuer, "issuer"), key_id: string(claims.key_id, "key_id"), holder_public_key: hash(claims.holder_public_key, "holder_public_key"), audience: string(claims.audience, "audience"), caller: parseCaller(claims.caller, "caller"), request_digest_sha256: hash(claims.request_digest_sha256, "request_digest_sha256"), disclosure_digest_sha256: hash(claims.disclosure_digest_sha256, "disclosure_digest_sha256"), policy_digest_sha256: hash(claims.policy_digest_sha256, "policy_digest_sha256"), nonce: claims.nonce, issued_at: issuedAt, expires_at: expiresAt}, signature: root.signature};
}

export function parseProviderCatalog(value: unknown): ProviderCatalog {
  const root = record(value, "provider catalog");
  if (root.schema !== "service.provider-catalog.v1" && root.schema !== "service.provider-catalog.v2" && root.schema !== "service.provider-catalog.v3") throw new ServiceClientError("incompatible_version", "Unsupported provider catalog");
  exact(root, root.schema === "service.provider-catalog.v3" ? ["schema", "provider", "services", "authority", "intake", "requester"] : root.schema === "service.provider-catalog.v2" ? ["schema", "provider", "services", "authority", "intake"] : ["schema", "provider", "services", "authority"], "provider catalog");
  const provider = record(root.provider, "provider"); exact(provider, ["id", "name", "version"], "provider");
  const authority = record(root.authority, "authority"); exact(authority, ["submission", "status", "artifacts"], "authority");
  for (const key of ["submission", "status", "artifacts"]) if (authority[key] !== "receiver-issued") throw new ServiceClientError("incompatible_response", `Unsupported ${key} authority`);
  const services = array(root.services, "services").map((raw): ProviderService => {
    const service = record(raw, "service"); exact(service, ["id", "version", "name", "summary", "availability", "inputs", "accepted_references", "expected_deliverables", "process", "communication"], "service");
    const inputs = array(service.inputs, "inputs").map((rawInput): InputField => { const input = record(rawInput, "input"); exact(input, ["id", "label", "type", "required", "description", "max_length"], "input"); if (typeof input.required !== "boolean" || (input.max_length !== null && !Number.isSafeInteger(input.max_length))) throw new ServiceClientError("incompatible_response", "Invalid input bounds"); return {id: identifier(input.id, "input.id"), label: string(input.label, "input.label"), type: oneOf(input.type, ["string", "integer", "number", "boolean"] as const, "input.type"), required: input.required, description: string(input.description, "input.description", 0), max_length: input.max_length as number | null}; });
    const accepted = array(service.accepted_references, "accepted_references").map((rawReference): ReferenceRequirement => { const reference = record(rawReference, "reference requirement"); exact(reference, ["id", "label", "required", "media_types", "max_bytes"], "reference requirement"); if (typeof reference.required !== "boolean") throw new ServiceClientError("incompatible_response", "Invalid reference requirement"); return {id: identifier(reference.id, "reference.id"), label: string(reference.label, "reference.label"), required: reference.required, media_types: array(reference.media_types, "media_types").map((item) => string(item, "media_type")), max_bytes: natural(reference.max_bytes, "max_bytes", true)}; });
    const deliverables = array(service.expected_deliverables, "expected_deliverables").map((rawDeliverable): DeliverableExpectation => { const deliverable = record(rawDeliverable, "deliverable expectation"); exact(deliverable, ["id", "label", "media_types", "multiple"], "deliverable expectation"); if (typeof deliverable.multiple !== "boolean") throw new ServiceClientError("incompatible_response", "Invalid deliverable expectation"); return {id: identifier(deliverable.id, "deliverable.id"), label: string(deliverable.label, "deliverable.label"), media_types: array(deliverable.media_types, "media_types").map((item) => string(item, "media_type")), multiple: deliverable.multiple}; });
    let process: ProcessPin | null = null;
    if (service.process !== null) { const pin = record(service.process, "process pin"); exact(pin, ["process_id", "process_version", "compilation_hash"], "process pin"); process = {process_id: string(pin.process_id, "process_id"), process_version: string(pin.process_version, "process_version"), compilation_hash: hash(pin.compilation_hash, "compilation_hash")}; }
    return {id: identifier(service.id, "service.id"), version: string(service.version, "service.version"), name: string(service.name, "service.name"), summary: string(service.summary, "service.summary"), availability: oneOf(service.availability, ["available", "paused", "preview"] as const, "availability"), inputs, accepted_references: accepted, expected_deliverables: deliverables, process, communication: array(service.communication, "communication").map((item) => oneOf(item, ["provider-status", "matrix"] as const, "communication"))};
  });
  const common = {provider: {id: identifier(provider.id, "provider.id"), name: string(provider.name, "provider.name"), version: string(provider.version, "provider.version")}, services, authority: {submission: "receiver-issued", status: "receiver-issued", artifacts: "receiver-issued"} as const};
  if (root.schema === "service.provider-catalog.v1") return {schema: root.schema, ...common};
  const intake = record(root.intake, "intake delivery"); exact(intake, ["endpoint", "max_retention_seconds", "envelope"], "intake delivery");
  const envelope = record(intake.envelope, "intake envelope"); exact(envelope, ["schema", "algorithm", "recipient_key_id", "recipient_public_key_hex", "not_before", "not_after"], "intake envelope");
  if (envelope.schema !== "service.intake-envelope.v1" || envelope.algorithm !== "x25519-hkdf-sha256-chacha20poly1305" || typeof envelope.recipient_key_id !== "string" || !visibleAsciiPattern.test(envelope.recipient_key_id)) throw new ServiceClientError("incompatible_response", "Unsupported intake envelope profile");
  const notBefore = timestamp(envelope.not_before, "envelope.not_before"), notAfter = timestamp(envelope.not_after, "envelope.not_after");
  if (Date.parse(notAfter) <= Date.parse(notBefore)) throw new ServiceClientError("incompatible_response", "Intake key validity is empty");
  const retention = natural(intake.max_retention_seconds, "max_retention_seconds", true);
  if (retention < 60 || retention > 604800) throw new ServiceClientError("incompatible_response", "Unsupported intake retention");
  const parsedIntake = {endpoint: absoluteHttpUrl(intake.endpoint, "intake.endpoint"), max_retention_seconds: retention, envelope: {schema: envelope.schema, algorithm: envelope.algorithm, recipient_key_id: envelope.recipient_key_id, recipient_public_key_hex: hash(envelope.recipient_public_key_hex, "recipient_public_key_hex"), not_before: notBefore, not_after: notAfter}} as const;
  if (root.schema === "service.provider-catalog.v2") return {schema: root.schema, ...common, intake: parsedIntake};
  const requester = record(root.requester, "requester"); exact(requester, ["evidence_schema", "membership", "credential"], "requester");
  if (requester.evidence_schema !== "service.castalia-requester-evidence.v1") throw new ServiceClientError("incompatible_response", "Unsupported requester evidence");
  const membership = record(requester.membership, "requester.membership"); exact(membership, ["credential_schema", "issuer_origin", "roots"], "requester.membership");
  if (membership.credential_schema !== "castalia.zenith-membership-credential.v3") throw new ServiceClientError("incompatible_response", "Unsupported membership credential");
  const roots = array(membership.roots, "requester.membership.roots").map((value): ZenithMembershipRoot => { const item = record(value, "membership root"); exact(item, ["issuer_id", "key_id", "public_key_hex"], "membership root"); return {issuer_id: identifier(item.issuer_id, "membership root issuer_id"), key_id: identifier(item.key_id, "membership root key_id"), public_key_hex: hash(item.public_key_hex, "membership root public_key_hex")}; });
  if (roots.length < 1 || roots.length > 16) throw new ServiceClientError("incompatible_response", "Membership roots are empty or too large");
  const credential = record(requester.credential, "requester.credential"); exact(credential, ["endpoint", "issuance_schema", "credential_schema", "presentation_protocol", "issuer", "key_id", "public_key_hex", "audience", "policy_digest_sha256", "callers"], "requester.credential");
  if (credential.issuance_schema !== "service.castalia-credential-issuance.v1" || credential.credential_schema !== "castalia.request-credential.v1" || credential.presentation_protocol !== "castalia.wallet-auth.v2") throw new ServiceClientError("incompatible_response", "Unsupported requester credential protocol");
  const callers = array(credential.callers, "requester.credential.callers").map((value, index) => parsePublishedCaller(value, `requester.credential.callers[${index}]`));
  if (callers.length < 1 || callers.length > 16) throw new ServiceClientError("incompatible_response", "Credential callers are empty or too large");
  return {schema: root.schema, ...common, intake: parsedIntake, requester: {
    evidence_schema: requester.evidence_schema,
    membership: {credential_schema: membership.credential_schema, issuer_origin: absoluteHttpUrl(membership.issuer_origin, "membership.issuer_origin"), roots},
    credential: {endpoint: absoluteHttpUrl(credential.endpoint, "credential.endpoint"), issuance_schema: credential.issuance_schema, credential_schema: credential.credential_schema, presentation_protocol: credential.presentation_protocol, issuer: string(credential.issuer, "credential.issuer"), key_id: identifier(credential.key_id, "credential.key_id"), public_key_hex: hash(credential.public_key_hex, "credential.public_key_hex"), audience: string(credential.audience, "credential.audience"), policy_digest_sha256: hash(credential.policy_digest_sha256, "credential.policy_digest_sha256"), callers},
  }};
}

export function parseIntakeResult(value: unknown): IntakeResult {
  const root = record(value, "intake result"); exact(root, ["schema", "request_id", "idempotency_key", "state", "transport_receipt", "service_request_id", "service_request_version", "status_url"], "intake result");
  if (root.schema !== "service.intake-result.v1") throw new ServiceClientError("incompatible_version", "Unsupported intake result");
  return {schema: root.schema, request_id: identifier(root.request_id, "request_id"), idempotency_key: identifier(root.idempotency_key, "idempotency_key"), state: oneOf(root.state, ["pending", "admitted", "rejected"] as const, "state"), transport_receipt: root.transport_receipt === null ? null : parseTransportReceipt(root.transport_receipt), service_request_id: root.service_request_id === null ? null : identifier(root.service_request_id, "service_request_id"), service_request_version: root.service_request_version === null ? null : natural(root.service_request_version, "service_request_version", true), status_url: string(root.status_url, "status_url")};
}

export function parseClientProjection(value: unknown): ClientProjection {
  const root = record(value, "client projection"); exact(root, ["schema", "request_id", "idempotency_key", "provider_id", "service_id", "transport", "service_request", "case", "execution", "deliverables", "receipts", "updated_at", "retry_after_ms"], "client projection");
  if (root.schema !== "service.client-projection.v1") throw new ServiceClientError("incompatible_version", "Unsupported client projection");
  const transport = record(root.transport, "transport"); exact(transport, ["state", "receipt"], "transport");
  let request: ServiceRequestProjection | null = null;
  if (root.service_request !== null) { const item = record(root.service_request, "service request"); exact(item, ["id", "state", "version", "case_id"], "service request"); request = {id: identifier(item.id, "service_request.id"), state: oneOf(item.state, ["intake", "qualified", "accepted", "rejected"] as const, "service_request.state"), version: natural(item.version, "service_request.version", true), case_id: item.case_id === null ? null : identifier(item.case_id, "case_id")}; }
  let caseValue: CaseProjection | null = null;
  if (root.case !== null) { const item = record(root.case, "case"); exact(item, ["id", "state", "version", "current_plan_revision_id"], "case"); caseValue = {id: identifier(item.id, "case.id"), state: oneOf(item.state, ["open", "planned", "closed"] as const, "case.state"), version: natural(item.version, "case.version", true), current_plan_revision_id: item.current_plan_revision_id === null ? null : identifier(item.current_plan_revision_id, "current_plan_revision_id")}; }
  let execution: ExecutionProjection | null = null;
  if (root.execution !== null) { const item = record(root.execution, "execution"); exact(item, ["run_id", "state", "freshness", "observed_at"], "execution"); execution = {run_id: item.run_id === null ? null : string(item.run_id, "run_id"), state: oneOf(item.state, ["awaiting_plan", "pending", "running", "blocked", "succeeded", "failed", "cancelled", "unknown"] as const, "execution.state"), freshness: oneOf(item.freshness, ["current", "catching_up", "stale", "gap", "unavailable"] as const, "freshness"), observed_at: nullableString(item.observed_at, "observed_at")}; }
  const deliverables = array(root.deliverables, "deliverables").map((raw): DeliverableDescriptor => { const item = record(raw, "deliverable"); exact(item, ["id", "version", "label", "artifact", "href", "receipt_ids"], "deliverable"); return {id: identifier(item.id, "deliverable.id"), version: natural(item.version, "deliverable.version", true), label: string(item.label, "deliverable.label"), artifact: parseArtifact(item.artifact), href: string(item.href, "deliverable.href"), receipt_ids: array(item.receipt_ids, "receipt_ids").map((id) => identifier(id, "receipt_id"))}; });
  const receipts = array(root.receipts, "receipts").map((raw): ReceiptReference => { const item = record(raw, "receipt reference"); exact(item, ["schema", "owner", "receipt_schema", "receipt_id", "content_hash", "recorded_at", "verification", "href"], "receipt reference"); if (item.schema !== "service.receipt-reference.v1") throw new ServiceClientError("incompatible_version", "Unsupported receipt reference"); const verification = record(item.verification, "verification"); exact(verification, ["state", "verifier", "detail"], "verification"); return {schema: item.schema, owner: oneOf(item.owner, ["service-management", "process-runtime", "secs"] as const, "receipt owner"), receipt_schema: string(item.receipt_schema, "receipt_schema"), receipt_id: identifier(item.receipt_id, "receipt_id"), content_hash: hash(item.content_hash, "receipt hash"), recorded_at: string(item.recorded_at, "recorded_at"), verification: {state: oneOf(verification.state, ["verified", "unverified", "failed"] as const, "verification.state"), verifier: nullableString(verification.verifier, "verifier"), detail: nullableString(verification.detail, "detail")}, href: string(item.href, "receipt.href")}; });
  return {schema: root.schema, request_id: identifier(root.request_id, "request_id"), idempotency_key: identifier(root.idempotency_key, "idempotency_key"), provider_id: identifier(root.provider_id, "provider_id"), service_id: identifier(root.service_id, "service_id"), transport: {state: oneOf(transport.state, ["pending", "consumed", "expired", "failed"] as const, "transport.state"), receipt: transport.receipt === null ? null : parseTransportReceipt(transport.receipt)}, service_request: request, case: caseValue, execution, deliverables, receipts, updated_at: string(root.updated_at, "updated_at"), retry_after_ms: root.retry_after_ms === null ? null : natural(root.retry_after_ms, "retry_after_ms")};
}

export function deriveDisplayState(value: ClientProjection): DisplayState {
  if (value.transport.state === "failed" || value.transport.state === "expired") return "failed";
  if (value.service_request === null) return value.transport.state === "pending" ? "pending-provider" : "unknown";
  if (value.service_request.state === "rejected") return "rejected";
  if (value.service_request.state === "intake") return "qualification-needed";
  if (value.service_request.state === "qualified") return "accepted";
  if (value.case === null) return "accepted";
  if (value.execution !== null && (value.execution.state === "unknown" || value.execution.freshness !== "current")) return "unknown";
  if (value.execution?.state === "failed" || value.execution?.state === "cancelled") return "failed";
  if (value.execution?.state === "succeeded") return value.deliverables.length > 0 ? "delivered" : "review-needed";
  if (["running", "blocked", "pending"].includes(value.execution?.state ?? "")) return "running";
  if (value.case.state === "planned") return "planned";
  return "accepted";
}

export function validateIntake(request: IntakeRequest, catalog: ProviderCatalog): void {
  if (!identifierPattern.test(request.request_id) || !identifierPattern.test(request.idempotency_key)) throw new ServiceClientError("invalid_request", "Request identities are invalid");
  const service = catalog.services.find((item) => item.id === request.service.service_id && item.version === request.service.service_version && catalog.provider.id === request.service.provider_id);
  if (!service || service.availability !== "available") throw new ServiceClientError("invalid_request", "The selected service version is unavailable");
  if (!hashPattern.test(request.brief.content_hash) || !Number.isSafeInteger(request.brief.revision) || request.brief.revision < 1) throw new ServiceClientError("invalid_request", "The reviewed brief is invalid");
  for (const input of service.inputs) { const value = request.brief.values[input.id]; if (input.required && value === undefined) throw new ServiceClientError("invalid_request", `Missing required input: ${input.id}`); if (value !== undefined && input.type === "integer" && !Number.isSafeInteger(value)) throw new ServiceClientError("invalid_request", `Invalid input: ${input.id}`); if (value !== undefined && input.type !== "integer" && typeof value !== input.type) throw new ServiceClientError("invalid_request", `Invalid input: ${input.id}`); if (typeof value === "string" && input.max_length !== null && value.length > input.max_length) throw new ServiceClientError("invalid_request", `Input too long: ${input.id}`); }
  for (const reference of request.references) { const requirement = service.accepted_references.find((item) => item.media_types.includes(reference.media_type)); if (!requirement || reference.byte_length > requirement.max_bytes || !hashPattern.test(reference.content_hash)) throw new ServiceClientError("invalid_request", `Unsupported reference: ${reference.filename}`); }
  for (const requirement of service.accepted_references.filter((item) => item.required)) if (!request.references.some((item) => requirement.media_types.includes(item.media_type))) throw new ServiceClientError("invalid_request", `Missing required reference: ${requirement.id}`);
}

function ownedBytes(bytes: Uint8Array): Uint8Array<ArrayBuffer> {
  const owned = new Uint8Array(new ArrayBuffer(bytes.byteLength));
  owned.set(bytes);
  return owned;
}
async function sha256(bytes: Uint8Array): Promise<Sha256> { const digest = await crypto.subtle.digest("SHA-256", ownedBytes(bytes).buffer); return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join(""); }
function canonicalJson(value: unknown): string {
  if (value === null || typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") { if (!Number.isFinite(value)) throw new ServiceClientError("invalid_request", "Non-finite numbers are not supported"); return JSON.stringify(value); }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  if (typeof value === "object") { const item = value as Record<string, unknown>; return `{${Object.keys(item).sort().map((key) => `${JSON.stringify(key)}:${canonicalJson(item[key])}`).join(",")}}`; }
  throw new ServiceClientError("invalid_request", "The request contains an unsupported value");
}

export function encryptedIntakeAuthorization(prepared: PreparedEncryptedSubmission): EncryptedIntakeAuthorizationV1 {
  if (!identifierPattern.test(prepared.provider_id) || !identifierPattern.test(prepared.request_id) || !identifierPattern.test(prepared.idempotency_key) || !hashPattern.test(prepared.intake_digest) || !hashPattern.test(prepared.envelope_digest) || !visibleAsciiPattern.test(prepared.recipient_key_id) || !Number.isSafeInteger(prepared.expires_at_ms) || prepared.expires_at_ms < 0) throw new ServiceClientError("invalid_request", "Prepared encrypted submission metadata is invalid");
  return {schema: "service.encrypted-intake-authorization.v1", provider_id: prepared.provider_id, request_id: prepared.request_id, idempotency_key: prepared.idempotency_key, intake_digest_sha256: prepared.intake_digest, envelope_digest_sha256: prepared.envelope_digest, recipient_key_id: prepared.recipient_key_id, envelope_expires_at_ms: prepared.expires_at_ms};
}

export function encryptedIntakeAuthorizationBytes(prepared: PreparedEncryptedSubmission): Uint8Array {
  return ownedBytes(new TextEncoder().encode(canonicalJson(encryptedIntakeAuthorization(prepared))));
}

export function clientReadAuthorizationBytes(request: Pick<AuthorizationRequest, "operation" | "resource" | "method" | "body_digest">): Uint8Array {
  if (request.method !== "GET" || request.body_digest !== null || (request.operation !== "request.status" && request.operation !== "artifact.get" && request.operation !== "receipt.get")) throw new ServiceClientError("invalid_request", "Unsupported client read authorization");
  const prefixes: Record<ClientReadAuthorizationV1["operation"], readonly string[]> = {"request.status": ["requests/"], "artifact.get": ["artifacts/"], "receipt.get": ["process-runtime/receipts/", "service-management/receipts/", "secs/receipts/"]};
  if (typeof request.resource !== "string" || !prefixes[request.operation].some((prefix) => request.resource.startsWith(prefix)) || request.resource.length > 4096 || request.resource.includes("\0")) throw new ServiceClientError("invalid_request", "Invalid client read resource");
  const value: ClientReadAuthorizationV1 = {schema: "service.client-read-authorization.v1", operation: request.operation, resource: request.resource};
  return ownedBytes(new TextEncoder().encode(canonicalJson(value)));
}

export class ServiceClient {
  readonly baseUrl: string; readonly authorize: Authorize; readonly fetch: typeof globalThis.fetch;
  readonly trustedIntakeOrigins: ReadonlySet<string>;
  readonly trustedCredentialOrigins: ReadonlySet<string>;
  readonly trustedReadOrigins: ReadonlySet<string>;
  readonly responseBaseUrl: string | null;
  constructor(options: { baseUrl: string; authorize: Authorize; fetch?: typeof globalThis.fetch; trustedIntakeOrigins?: string[]; trustedCredentialOrigins?: string[]; trustedReadOrigins?: string[]; responseBaseUrl?: string }) {
    this.baseUrl = options.baseUrl.replace(/\/$/, ""); this.authorize = options.authorize; this.fetch = options.fetch ?? globalThis.fetch.bind(globalThis);
    const origins = [new URL(this.baseUrl).origin, ...(options.trustedIntakeOrigins ?? []).map((value) => new URL(value).origin)];
    this.trustedIntakeOrigins = new Set(origins);
    this.trustedCredentialOrigins = new Set([new URL(this.baseUrl).origin, ...(options.trustedCredentialOrigins ?? []).map((value) => new URL(value).origin)]);
    this.trustedReadOrigins = new Set([new URL(this.baseUrl).origin, ...(options.trustedReadOrigins ?? []).map((value) => new URL(value).origin)]);
    if (options.responseBaseUrl === undefined) this.responseBaseUrl = null;
    else {
      const parsed = new URL(options.responseBaseUrl), segments = parsed.pathname === "/" ? [] : parsed.pathname.split("/").slice(1);
      if (parsed.protocol !== "https:" || options.responseBaseUrl.endsWith("/") || parsed.username || parsed.password || parsed.search || parsed.hash || segments.some((segment) => !/^[A-Za-z0-9._~-]+$/.test(segment) || segment === "." || segment === "..")) throw new ServiceClientError("invalid_request", "Provider response base URL is invalid");
      this.responseBaseUrl = this.providerUrl(options.responseBaseUrl).replace(/\/$/, "");
    }
  }
  async catalog(): Promise<ProviderCatalog> { const response = await this.fetch(`${this.baseUrl}/v1/provider`, {headers: {Accept: "application/json"}, credentials: "omit", redirect: "error"}); return parseProviderCatalog(await this.response(response, false)); }
  async putArtifact(manifest: ArtifactManifest, bytes: Uint8Array): Promise<ArtifactManifest> { const body = ownedBytes(bytes); if (body.byteLength !== manifest.byte_length || await sha256(body) !== manifest.content_hash) throw new ServiceClientError("invalid_request", "Artifact bytes do not match the immutable manifest"); const url = `${this.baseUrl}/v1/client/artifacts/${encodeURIComponent(manifest.content_hash)}`; const headers = await this.authorize({operation: "artifact.put", resource: `artifacts/${manifest.content_hash}`, method: "PUT", url, body_digest: manifest.content_hash}); const response = await this.fetch(url, {method: "PUT", headers: {...headers, "Content-Type": manifest.media_type, "Content-Length": String(body.byteLength), "X-Artifact-Id": manifest.artifact_id, "X-Artifact-Filename": encodeURIComponent(manifest.filename)}, body: body.buffer, credentials: "omit", redirect: "error"}); return parseArtifact(await this.response(response, true)); }
  async submit(request: IntakeRequest, catalog?: ProviderCatalog): Promise<IntakeResult> { if (catalog) validateIntake(request, catalog); const valuesDigest = await sha256(new TextEncoder().encode(canonicalJson(request.brief.values))); if (valuesDigest !== request.brief.content_hash) throw new ServiceClientError("invalid_request", "Reviewed brief values do not match content_hash"); const body = ownedBytes(new TextEncoder().encode(canonicalJson(request))); const bodyDigest = await sha256(body); const url = `${this.baseUrl}/v1/client/requests`; const headers = await this.authorize({operation: "request.submit", resource: `requests/${request.request_id}`, method: "POST", url, body_digest: bodyDigest}); let response: Response; try { response = await this.fetch(url, {method: "POST", headers: {...headers, "Content-Type": "application/json", "Idempotency-Key": request.idempotency_key}, body: body.buffer, credentials: "omit", redirect: "error"}); } catch { throw new ServiceClientError("transport_error", "The submission outcome is unknown; retry the exact request.", {retryable: true, uncertain: true}); } return parseIntakeResult(await this.response(response, true)); }
  async prepareEncrypted(request: IntakeRequest, catalog: EncryptedProviderCatalog, options: { authority: Pick<EncryptedSubmissionAuthority, "evidence">; sealer: IntakeEnvelopeSealer; now?: number }): Promise<PreparedEncryptedSubmission> {
    validateIntake(request, catalog);
    const valuesDigest = await sha256(new TextEncoder().encode(canonicalJson(request.brief.values)));
    if (valuesDigest !== request.brief.content_hash) throw new ServiceClientError("invalid_request", "Reviewed brief values do not match content_hash");
    const intake = ownedBytes(new TextEncoder().encode(canonicalJson(request))), intakeDigest = await sha256(intake);
    const now = options.now ?? Date.now(), notBefore = Date.parse(catalog.intake.envelope.not_before), notAfter = Date.parse(catalog.intake.envelope.not_after);
    if (!Number.isSafeInteger(now) || now < notBefore || now >= notAfter) throw new ServiceClientError("expired", "The provider intake key is not currently valid");
    const expiresAt = Math.min(now + catalog.intake.max_retention_seconds * 1000, notAfter);
    if (expiresAt - now < 60000) throw new ServiceClientError("expired", "The provider intake key expires too soon");
    const url = this.intakeUrl(catalog.intake.endpoint);
    const authorization = {operation: "request.submit", resource: `requests/${request.request_id}`, method: "POST", url, body_digest: intakeDigest, provider_id: request.service.provider_id, request_id: request.request_id, idempotency_key: request.idempotency_key, recipient_key_id: catalog.intake.envelope.recipient_key_id, expires_at_ms: expiresAt} as const;
    const requesterEvidence = await options.authority.evidence({...authorization, intake: ownedBytes(intake)});
    if (!(requesterEvidence instanceof Uint8Array) || requesterEvidence.byteLength < 1 || requesterEvidence.byteLength > maxRequesterEvidence) throw new ServiceClientError("invalid_request", "Requester evidence is invalid");
    const envelope = ownedBytes(await options.sealer.seal({intake, requester_evidence: ownedBytes(requesterEvidence), profile: catalog.intake.envelope, expires_at_ms: expiresAt}));
    if (envelope.byteLength < 1 || envelope.byteLength > maxEncryptedEnvelope) throw new ServiceClientError("invalid_request", "Encrypted intake envelope is invalid");
    const envelopeDigest = await sha256(envelope);
    return {endpoint: url, envelope: ownedBytes(envelope), envelope_digest: envelopeDigest, intake_digest: intakeDigest, provider_id: request.service.provider_id, request_id: request.request_id, idempotency_key: request.idempotency_key, recipient_key_id: catalog.intake.envelope.recipient_key_id, expires_at_ms: expiresAt};
  }
  async sendPreparedEncrypted(prepared: PreparedEncryptedSubmission, authority: Pick<EncryptedSubmissionAuthority, "authorize">, now = Date.now()): Promise<IntakeResult> {
    const envelope = ownedBytes(prepared.envelope);
    if (!Number.isSafeInteger(now) || !Number.isSafeInteger(prepared.expires_at_ms) || now >= prepared.expires_at_ms) throw new ServiceClientError("expired", "The prepared encrypted intake has expired");
    if (!identifierPattern.test(prepared.provider_id) || !identifierPattern.test(prepared.request_id) || !identifierPattern.test(prepared.idempotency_key) || !visibleAsciiPattern.test(prepared.recipient_key_id) || !hashPattern.test(prepared.intake_digest) || !hashPattern.test(prepared.envelope_digest) || envelope.byteLength < 1 || envelope.byteLength > maxEncryptedEnvelope) throw new ServiceClientError("invalid_request", "Prepared encrypted submission is invalid");
    if (await sha256(envelope) !== prepared.envelope_digest) throw new ServiceClientError("invalid_request", "Prepared encrypted envelope was changed");
    const url = this.intakeUrl(prepared.endpoint);
    const authorization = {operation: "request.submit", resource: `requests/${prepared.request_id}`, method: "POST", url, body_digest: prepared.intake_digest, provider_id: prepared.provider_id, request_id: prepared.request_id, idempotency_key: prepared.idempotency_key, recipient_key_id: prepared.recipient_key_id, expires_at_ms: prepared.expires_at_ms, envelope_digest: prepared.envelope_digest} as const;
    const authorizedHeaders = await authority.authorize(authorization);
    const headers: Record<string, string> = {};
    const reserved = new Set(["content-type", "content-length", "host", "idempotency-key", "x-zenith-request-id", "x-zenith-provider-id", "x-zenith-intake-sha256", "x-zenith-envelope-key-id", "x-zenith-envelope-expires-at"]);
    for (const [key, value] of Object.entries(authorizedHeaders)) { if (reserved.has(key.toLowerCase()) || typeof value !== "string" || /[\r\n]/.test(value)) throw new ServiceClientError("invalid_request", "Encrypted submission headers are invalid"); headers[key] = value; }
    Object.assign(headers, {"Content-Type": "application/vnd.zenith.service-intake-envelope-v1", "Content-Length": String(envelope.byteLength), "Idempotency-Key": prepared.idempotency_key, "X-Zenith-Request-Id": prepared.request_id, "X-Zenith-Provider-Id": prepared.provider_id, "X-Zenith-Intake-SHA256": prepared.intake_digest, "X-Zenith-Envelope-Key-Id": prepared.recipient_key_id, "X-Zenith-Envelope-Expires-At": String(prepared.expires_at_ms)});
    let response: Response; try { response = await this.fetch(url, {method: "POST", headers, body: envelope.buffer, credentials: "omit", redirect: "error"}); } catch { throw new ServiceClientError("transport_error", "The encrypted submission outcome is unknown; retry the exact envelope.", {retryable: true, uncertain: true}); }
    return parseIntakeResult(await this.response(response, true));
  }
  async submitEncrypted(request: IntakeRequest, catalog: EncryptedProviderCatalog, options: { authority: EncryptedSubmissionAuthority; sealer: IntakeEnvelopeSealer; now?: number }): Promise<IntakeResult> {
    const prepared = await this.prepareEncrypted(request, catalog, options);
    return this.sendPreparedEncrypted(prepared, options.authority, options.now);
  }
  async requestCredential(endpoint: string, request: CastaliaCredentialIssuanceRequestV1): Promise<RequestCredentialV1> {
    const membership = parseMembership(request.membership), caller = parseCaller(request.caller, "caller");
    if (request.schema !== "service.castalia-credential-issuance.v1" || !hashPattern.test(request.request_digest_sha256) || !hashPattern.test(request.disclosure_digest_sha256) || !noncePattern.test(request.nonce)) throw new ServiceClientError("invalid_request", "Credential issuance request is invalid");
    const body = ownedBytes(new TextEncoder().encode(canonicalJson({schema: request.schema, membership, request_digest_sha256: request.request_digest_sha256, disclosure_digest_sha256: request.disclosure_digest_sha256, caller, nonce: request.nonce})));
    const url = this.credentialUrl(endpoint);
    const response = await this.fetch(url, {method: "POST", headers: {"Content-Type": "application/json", "Content-Length": String(body.byteLength)}, body: body.buffer, credentials: "omit", redirect: "error"});
    return parseRequestCredential(await this.response(response, false));
  }
  async status(statusUrl: string, requestId: Identifier): Promise<ClientProjection> { const url = this.providerUrl(statusUrl); const headers = await this.authorize({operation: "request.status", resource: `requests/${requestId}`, method: "GET", url, body_digest: null}); return parseClientProjection(await this.response(await this.fetch(url, {headers, credentials: "omit", redirect: "error"}), false)); }
  async statusForRequest(requestId: Identifier): Promise<ClientProjection> { if (!identifierPattern.test(requestId) || this.responseBaseUrl === null) throw new ServiceClientError("invalid_request", "A configured provider response base is required"); return this.status(`${this.responseBaseUrl}/v1/client/requests/${encodeURIComponent(requestId)}`, requestId); }
  async artifact(href: string, contentHash: Sha256): Promise<Uint8Array> { const url = this.providerUrl(href); const headers = await this.authorize({operation: "artifact.get", resource: `artifacts/${contentHash}`, method: "GET", url, body_digest: null}); const response = await this.fetch(url, {headers, credentials: "omit", redirect: "error"}); if (!response.ok) await this.response(response, false); const bytes = new Uint8Array(await response.arrayBuffer()); if (await sha256(bytes) !== contentHash) throw new ServiceClientError("artifact_mismatch", "Downloaded artifact bytes do not match the descriptor"); return bytes; }
  async receipt(reference: ReceiptReference): Promise<unknown> { const url = this.providerUrl(reference.href); const headers = await this.authorize({operation: "receipt.get", resource: `${reference.owner}/receipts/${reference.receipt_id}`, method: "GET", url, body_digest: null}); const response = await this.fetch(url, {headers, credentials: "omit", redirect: "error"}); if (!response.ok) return this.response(response, false); const bytes = new Uint8Array(await response.arrayBuffer()); if (await sha256(bytes) !== reference.content_hash) throw new ServiceClientError("receipt_mismatch", "Receipt bytes do not match the descriptor"); try { return JSON.parse(new TextDecoder("utf-8", {fatal: true}).decode(bytes)); } catch { throw new ServiceClientError("incompatible_response", "The canonical receipt is not valid UTF-8 JSON"); } }
  private intakeUrl(href: string): string { const url = new URL(href); if (!["http:", "https:"].includes(url.protocol) || !this.trustedIntakeOrigins.has(url.origin)) throw new ServiceClientError("invalid_request", "Provider intake origin is not explicitly trusted"); return url.toString(); }
  private credentialUrl(href: string): string { const url = new URL(href); if (!["http:", "https:"].includes(url.protocol) || !this.trustedCredentialOrigins.has(url.origin)) throw new ServiceClientError("invalid_request", "Provider credential origin is not explicitly trusted"); return url.toString(); }
  private providerUrl(href: string): string { const base = new URL(`${this.baseUrl}/`); const url = new URL(href, base); if (!this.trustedReadOrigins.has(url.origin) || !["http:", "https:"].includes(url.protocol)) throw new ServiceClientError("invalid_request", "Provider read origin is not explicitly trusted"); return url.toString(); }
  private async response(response: Response, command: boolean): Promise<unknown> { let value: unknown; try { value = await response.json(); } catch { throw new ServiceClientError("incompatible_response", "The provider returned an unreadable response", {status: response.status, uncertain: command && response.ok}); } if (response.ok) return value; try { const body = record(value, "error"); exact(body, ["schema", "request_id", "error"], "error"); if (body.schema !== "service.client-error.v1") throw new Error(); const error = record(body.error, "error detail"); exact(error, ["code", "message", "retryable"], "error detail"); throw new ServiceClientError(string(error.code, "error.code"), string(error.message, "error.message"), {retryable: error.retryable === true, status: response.status, uncertain: command && response.status >= 500}); } catch (cause) { if (cause instanceof ServiceClientError) throw cause; throw new ServiceClientError("incompatible_response", "The provider returned an unsupported error", {status: response.status, uncertain: command && response.status >= 500}); } }
}
