# Changelog

## [Unreleased]

- Install the pinned Vercel Queue and Castalia verifier extras in public-source
  CI so the required Queue entrypoint and its runtime OIDC binding are exercised
  by the same dependency profile used in the provider release bundle.
- Route the separately encrypted reference-object endpoint through the production Vercel handler and regression-test every public rewrite.
- Document the required Vercel Queue acceptance gate, including the reviewed
  topic/group candidates, 24-hour retention, offline enqueue, local pre-ack
  commit, authoritative response proof, evidence set and rollback sequence.
- Bind every Vercel Queue publication to the platform-injected runtime OIDC
  request header and reject missing, malformed or duplicate header contexts;
  never capture a build-time token in the cached gateway composition.

### Fixed
- Align the live Vercel Queue gateway and current provider-catalog v4 fixture
  with Vercel's 24-hour maximum retention while keeping older catalog versions
  readable for stored-client compatibility.
- Permit an exact numeric-loopback HTTP browser origin for local candidate
  acceptance while preserving HTTPS-only production environment composition.
- Correct provider-catalog v2-v4 fixture recipient key identifiers to the canonical secS X25519 public-key SHA-256 prefix and enforce that interop invariant in the TypeScript suite.

### Added
- Add provider-catalog v4 and a distinct encrypted reference-object route with
  exact browser retry, Castalia authorization, independent queue consumption,
  secS native opening, durable pre-ack storage, and admission gating. The first
  profile carries at most one verified original up to 512 KiB into the immutable
  Runtime reference-manifest artifact; larger or multiple files fail closed.
- Add pinned Castalia Wallet Service/Runtime authority adapters, durable
  explicit-resume admission and handoff state, and one-shot pull/admit/recover
  worker commands — close the local provider composition gap without allowing
  retries to reissue an uncertain native command.
- Add the narrow Zenith Anima brand-package lifecycle worker. It durably
  qualifies, accepts, converts and plans an admitted request, commits the
  reviewed brief and reference manifest as content-addressed Runtime artifacts,
  and approves only the configured immutable process pin. Every Service and
  Runtime mutation has an explicit retained-command resume path.
- Derive the first service's outbox identity from its stable Case and immutable
  plan revision, expose a read-only activation preview, and deliver only the
  exact retained handoff selected by finite Runtime authority.
- Add provider-catalog v3, dependency-free TypeScript client and fixtures
  for provider-neutral discovery, reviewed intake, authoritative request/Case
  projection, deliverables and canonical receipt references.
- Add receiver-authorized client reads over the retained requester binding,
  canonical ServiceRequest/Case state, exact Runtime Run/output/artifact data and
  canonical Runtime receipts. Frozen browser contract bundles v1-v3 remain
  unchanged; v4 adds the closed client-read authorization value and the
  independently encrypted reference-object profile.
- Add an explicit separate read-origin trust set and a numeric-loopback,
  GET/OPTIONS-only projection listener suitable for an operator-approved HTTPS
  Tailscale Funnel. Intake can return the configured path-capable response base,
  and an unknown outcome can reconcile its stable request ID from the same
  explicitly configured base, while mutation methods remain disabled on the Mac
  listener.
- Add durable encrypted intake, exact retry admission, native secS opening,
  Castalia requester evidence and receiver-credential issuance, plus a bounded
  credential-bound Vercel HTTP gateway composition.
- Clean public source baseline — make component implementation inspectable while preserving private history, live state and qualification evidence.
