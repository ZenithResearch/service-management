# Required Vercel Queue acceptance

This is the release gate for the first Anima-to-Zenith provider delivery. Vercel
Queue is required: it keeps encrypted work available while the operator Mac,
Service Management, Process Runtime and Frank are offline. Matrix is the next
carrier for the same immutable inner envelopes; it does not replace this gate.
The future synchronization sidecar is outside both intake paths.

The Queue acknowledgement is transport evidence only. It never means the
request was admitted, a Case was created, a process ran or a deliverable exists.

## Reviewed candidate

| Setting | Candidate value |
| --- | --- |
| Vercel project | `zenith-provider-intake` |
| Queue region | `sfo1` |
| Request topic | `zenith-intake-v1` |
| Reference topic | `zenith-reference-v1` |
| Request consumer group | `zenith-provider-mac` |
| Reference consumer group | `zenith-provider-mac-reference` |
| Request/reference retention | `604800` seconds |
| Public routes | `/v1/request-credential`, `/v1/client/requests`, `/v1/client/reference-objects` |

Topic names and consumer groups are release configuration. Changing one creates
a distinct transport stream and requires a new acceptance record. The current
provider-catalog v4 fixture advertises 604,800 seconds for both request and
reference retention. Stored v2/v3 catalogs remain decoder-compatible but are
not valid inputs for a new production review.

## Values that must come from reviewed state

Do not invent, generate or copy these values into source control:

| Variable | Required source |
| --- | --- |
| `ZENITH_ANIMA_ORIGIN` | Exact deployed Anima HTTPS origin selected for this acceptance |
| `ZENITH_RECIPIENT_KEY_ID` | Released secS provider intake public-key identifier |
| `ZENITH_RECEIVER_ISSUER`, `ZENITH_RECEIVER_KEY_ID`, `ZENITH_RECEIVER_PUBLIC_KEY_HEX` | Reviewed Wallet receiver-credential signer identity |
| `ZENITH_RECEIVER_SIGNING_SEED_B64` | Matching protected Vercel secret; never a file, client value or repository value |
| `ZENITH_RECEIVER_AUDIENCE` | Reviewed Wallet Auth audience |
| `ZENITH_REQUESTER_POLICY_DIGEST_SHA256` | Digest of the exact installed requester policy |
| `ZENITH_MEMBERSHIP_ROOTS_JSON` | Closed list of accepted Zenith membership issuer roots |
| `ZENITH_STATUS_BASE_URL` | Exact authorized HTTPS projection base, once the read listener is activated |

`ZENITH_PROVIDER_ID=zenith`, `ZENITH_QUEUE_REGION=sfo1`,
`ZENITH_QUEUE_TOPIC=zenith-intake-v1` and
`ZENITH_REFERENCE_QUEUE_TOPIC=zenith-reference-v1` are the proposed non-secret
values. The public function requires Vercel's runtime `x-vercel-oidc-token`
header and never captures a build-time token. For the first qualification, the
local one-shot poll worker receives a freshly issued development OIDC token only
through its owner-private `0600` token file. Development tokens expire after 12
hours; refresh the file before this test. A supervised long-running poller needs
a separately reviewed refresh composition before production qualification.

## Acceptance sequence

1. Pin the merged Service Management release, the released secS browser sealer,
   the released native opener and the reviewed provider-catalog v4 bytes.
2. Review the exact non-secret settings above, the real Anima origin, membership
   roots, receiver public identity and requester-policy digest. Verify that the
   protected signing seed derives the published receiver public key.
3. Create the Vercel project and configure its protected and non-secret values.
   Deploy the checked-in `vercel.json` and `api/provider.py` from the reviewed
   release. Confirm only the three documented public routes exist and each
   Queue publication uses the runtime OIDC request header.
4. Keep the operator Mac provider stack stopped. In Anima, prepare one new v4
   request with stable client request and idempotency IDs, optional one-reference
   metadata, and the exact reviewed brief. Obtain explicit Castalia Wallet
   consent and seal the request and reference locally.
5. Submit the request and optional reference. Retain the exact ciphertext,
   requester evidence and logical IDs for retries. Confirm the browser reports
   only `pending` transport retention and does not invent Service or Case state.
6. Start the released local provider composition. Poll the request and reference
   topics with the named consumer groups. Prove each ciphertext is opened by the
   pinned native secS executable, requester authority is verified at authenticated
   Queue acceptance time, and exact bytes are committed before acknowledgement.
7. Admit the retained request through finite Castalia Wallet Service authority.
   Prove an exact duplicate returns the retained result and changed bytes under
   the same identity fail with `idempotency_conflict`.
8. Activate the GET-only authorized response listener. Reconcile the stable
   request ID from Anima and show the authoritative ServiceRequest/Case status,
   then run the pinned `zenith.anima.brand-package` process to real artifacts and
   canonical receipts.
9. Stop and restart the local provider between pull, admission and response
   phases. Repeat one lost-response retry with the exact prepared envelope and
   verify there is still one logical request, one Case and one selected Run.

## Evidence to retain

- exact Git commit, release artifact digests and provider-catalog v4 digest;
- Vercel project identity, deployment identity, region, topics, consumer groups
  and configured retention without secret values;
- Anima origin, stable request/idempotency/reference IDs and envelope digests;
- transport receipt IDs/timestamps and local pre-ack commit records;
- ServiceRequest, Case, plan revision, handoff, Run, artifact and canonical
  receipt IDs;
- authorized, denied, duplicate, unknown-outcome, restart and expired-message
  traces; and
- a final check that Queue payloads, browser storage, process arguments and logs
  contain no private keys, provider authority or local paths.

## Abort and rollback

Disable the Vercel deployment before rotating or deleting anything. Leave
unacknowledged messages to expire or reconcile them from the retained exact
client envelopes; never acknowledge a message that was not durably committed.
Close local Service and Runtime admission before changing authority. Preserve
the intake and Service databases, release pins and audit receipts. A failed
deployment may be rolled back to its previous immutable Vercel deployment, but
a changed key, origin, policy digest, topic or catalog requires a new reviewed
client request rather than mutating an existing one.
