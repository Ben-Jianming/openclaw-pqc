---
summary: "Push V2 protocol, release acceptance criteria, and verified security boundaries"
read_when:
  - You are implementing or reviewing the OpenClaw PQC Push V2 protocol
  - You need evidence for a PQC installation or release claim
title: "PQC production acceptance"
---

# PQC production acceptance

## Candidate key lifecycle policy

This section describes a local integration candidate, not a shipped release or
completed installed-Gateway acceptance. Its strict browser contract requires
`keyPolicyVersion: 1` and separate `keyPolicy.ed25519` and `keyPolicy.mldsa65`
records from the authenticated `push.pqc.keys` connection. Each record binds
algorithm, sender, key ID and the exact public key, and carries `status`,
`validFromMs`, `validUntilMs` and a persistent positive `revision`.

Validity is the half-open interval `validFromMs <= nowMs < validUntilMs`.
Missing policies, unsupported policy versions, malformed bounds, revoked keys
and mismatched public keys are rejected. Signed payloads and untrusted wake
messages cannot supply or override this trust policy.

Existing installations need an explicit maintenance enrollment before using
this candidate. Preserve the existing identity database, its wrapping material
and the dedicated Ed25519 push key. Enrollment reads existing keys only; it does
not generate replacements, extend an existing lifetime or reactivate revoked
records. The two policies are registered in one SQLite transaction in the
shared state database. The additive table does not bump the schema version.

### First installation and existing-key enrollment

The additive installed commands below belong to this local candidate. Their
presence in source is not evidence that an older installation has them or that
the candidate has passed installation, Doctor, CI or live-delivery acceptance.
Check the installed build with `openclaw security push-key --help` first.

Use a separate, previously unused profile for a first-install exercise. A named
profile normally isolates state under `~/.openclaw-<name>`, but explicit
`OPENCLAW_STATE_DIR` or `OPENCLAW_CONFIG_PATH` overrides can select other paths.
Inspect those overrides before proceeding; never reuse an active Gateway
profile for an installation, revocation or recovery drill.

```sh
openclaw --profile pqc-first-install config file
openclaw --profile pqc-first-install setup --baseline --workspace /absolute/path/to/new-workspace
openclaw --profile pqc-first-install config validate --json
openclaw --profile pqc-first-install security push-key status --json
```

On an empty profile, status reports `ready: false`, state `uninitialized`, and
exit status `1`; this is the expected pre-provisioning result. Run the commands
individually rather than treating that initial status as a successful gate.

`setup --baseline` creates the baseline configuration, workspace and session
folders; it does not complete provider onboarding or establish push delivery.
For interactive model, channel and Gateway configuration, use
`openclaw --profile pqc-first-install setup --wizard`. The existing
`openclaw --profile pqc-first-install config --section gateway` command opens
the guided Gateway section. Keep the same selected profile throughout.
See [Setup](/cli/setup) and [Config](/cli/config).

For a fresh profile without existing push identity/key material, explicitly
provision and enroll the two signing identities with operator-selected Unix
millisecond bounds:

```sh
openclaw --profile pqc-first-install security push-key init \
  --valid-from-ms <activation-ms> --valid-until-ms <expiry-ms>
openclaw --profile pqc-first-install security push-key status --json
openclaw --profile pqc-first-install doctor --lint --only core/doctor/push-key-policy --json
```

Angle-bracket values are placeholders. Supply nonnegative safe integers with
`activation-ms < expiry-ms`; choose a currently active interval for a signing
acceptance exercise. Do not infer validity from file modification times or use
an unbounded default. Validity includes the activation instant and excludes the
expiry instant: `validFromMs <= nowMs < validUntilMs`.

`init` is explicit first provisioning. If either signing identity or its key
material already exists, use enrollment or documented recovery instead of
replacement. Preserve both original public identities, the state database,
wrapping material and dedicated Ed25519 push key. For that existing profile,
run:

```sh
openclaw --profile <existing-profile> security push-key enroll \
  --valid-from-ms <activation-ms> --valid-until-ms <expiry-ms>
openclaw --profile <existing-profile> security push-key status --json
openclaw --profile <existing-profile> doctor --lint --only core/doctor/push-key-policy --json
```

Enrollment reads existing keys and registers both policies in one shared-state
SQLite transaction. It does not generate replacement identities, change an
already enrolled lifetime or reactivate a revoked key. Missing or partial key
material is a provisioning/recovery failure, not permission to regenerate the
existing identity. Repeating enrollment with the same active records and bounds
is idempotent. Status and the selected Doctor lint check inspect state without
generating signing keys or automatically enrolling policies. Status exits `0`
only when `ready: true`; incomplete, unenrolled, future, expired or revoked
material remains not ready. A clean Doctor result is limited to the named local
lifecycle check, not whole-product readiness.

The registered profile policy set anchors one dual-key identity. Initial
enrollment requires an empty set. A nonempty set must be exactly the two records
matching the current sender, algorithms, key IDs and public keys; partial,
additional or mismatched records reject enrollment and renewal. Existing policy
rows also prevent `init` before key generation, even when both key materials are
absent. Status reports that missing-material state as `incomplete`, not a fresh
profile. Do not overwrite or remove key files, delete policies or rerun `init`
to bypass revocation or stale trust. Restore the matching original identity
material. A change of identity requires a separately reviewed rotation workflow;
these commands do not implement rotation.

Prefer explicit renewal before expiry. Read both policy records with status,
keep their original `validFromMs`, and supply a later expiry:

```sh
openclaw --profile <existing-profile> security push-key renew \
  --valid-from-ms <original-activation-ms> --valid-until-ms <extended-expiry-ms> --json
openclaw --profile <existing-profile> doctor --lint --only core/doctor/push-key-policy --json
```

Renewal requires both enrolled, unrevoked records to match the current keys and
sender. The supplied start must equal both original starts; the new expiry must
be strictly later than each existing expiry and the execution time. The pair
updates in one SQLite transaction and each revision increases by one. A missing,
revoked or mismatched member rejects the whole renewal. No identity or public
key is replaced. Expired but unrevoked records may be explicitly renewed to
restore service; expiry still blocks delivery until renewal completes. Neither
enrollment nor diagnostics renew policies automatically. A renewal source path
is not evidence that an installed package or published release passed this
workflow.

To revoke a registered key, select the same profile and use the public sender
and key identifiers from status:

```sh
openclaw --profile <existing-profile> security push-key revoke \
  --sender-id <sender-id> --algorithm ed25519 --key-id <key-id>
```

The other supported algorithm is `ml-dsa-65`. Revocation is idempotent and
persists across database reopen. Recipient RPCs cannot mutate these policies.
The signer checks current persisted policy before signing; an unregistered,
expired or revoked key stops signing without a fallback signature. Revoking
either member prevents dual-signature delivery until an explicitly reviewed
rotation or recovery procedure supplies a usable pair. Do not run revocation
against a working profile merely to test installation.

The browser refreshes policy per object before accepting content, again before
durable acceptance, and after Service Worker readiness before business display.
Previously verified inbox entries are revalidated during recovery. A refresh
failure or rejection retains pending work without presenting business content
or prematurely acknowledging the reference. Expired wake references can be
discarded. A displayed entry whose key is later revoked can remain pending
until reference expiry; this candidate does not add a post-revocation cleanup
or notification-retraction protocol.

A successful final policy response is not atomic with OS presentation. A
revocation committed after that response can race an in-flight notification.
This candidate does not claim instantaneous global revocation, offline policy
acceptance, database rollback protection, automatic rotation or historical-key
delivery after rotation.

The updated browser advertises `push-key-policy-v1` in its authenticated connect
capabilities. Key retrieval, reference read/acknowledgement and new Web Push
subscriptions require that capability on the established connection, returning
`PUSH_KEY_POLICY_CAPABILITY_REQUIRED` when it is absent. Node aliases share the
same gate after their existing pairing checks. Non-push methods, VAPID public
key retrieval and subscription removal remain available to legacy clients.
An existing legacy subscription may still receive a generic wake, but the old
connection cannot redeem the signed business object. Native clients must not
advertise this capability until they enforce the same lifecycle contract.

This capability is an honest-client compatibility declaration, not remote
attestation or proof that a malicious client actually validates signatures.
It relies on the authenticated Gateway transport and does not replace role,
scope, pairing or recipient checks. Do not deploy the browser patch alone.
Before release, complete reviewed migration/provisioning and exact-build
installation, full authenticated Gateway/browser acceptance and live delivery.
Component tests and historical CI passes do not satisfy those gates.

Use this reference to decide which PQC guarantees a particular installation can claim. It defines the Push V2 signed transcript and the eight acceptance groups needed to connect the paper components to installed clients. A signature helper, a source inspection, and a green job with skipped tests establish different facts. Record the exact build and the checks that ran before making a product claim.

## Implementation and release status

The initial review baseline is commit `c86174b5002e77ed33ca0da5118c497797043ecf`. Published commits `6bea43974092e82caa035c192fd96e35f0882c77` and `cd43b868669f49d6e634f4e6b1a6bbb4c7f2988a` add automatic key wrapping, restricted key files, bounded recovery inputs, and the production paths described below. GitHub source publication does not establish that an older installation or a released binary contains these changes.

Commit `ced780262c42828886ffc400b72bb873ba8350b9` has recorded passes for [built behavior on Windows and Linux](https://github.com/Ben-Jianming/openclaw-pqc/actions/runs/38177049286), [Android, Apple shared-library, and Linux interoperability](https://github.com/Ben-Jianming/openclaw-pqc/actions/runs/38177049345), and [Install Smoke](https://github.com/Ben-Jianming/openclaw-pqc/actions/runs/38177107960). Its full CI still found routing, test-environment, generated-inventory, and dependency issues addressed by the subsequent corrective changes. A pass belongs to its exact commit and named cases; it must not be inherited by a later candidate. Run that candidate's checks before making a release claim. Physical devices and live delivery remain separate acceptance requirements; no complete R1–R8 field pass is asserted here.

Native clients already have ML-DSA migration code, including a portable Apple provider for systems without the native API. Nostr already has ML-KEM message paths and a `required` mode. These facts do not establish Push V2 receiver verification, a standardized NIP-44 protocol, or physical-device acceptance.

The subsequent commit `aee260c2b9a08c48f44e7596ea88dac7f31af944` passed [built installation behavior on Windows and Linux](https://github.com/Ben-Jianming/openclaw-pqc/actions/runs/38182369977) and the Android, Apple shared-library, and Linux jobs in [native interoperability](https://github.com/Ben-Jianming/openclaw-pqc/actions/runs/38182369963). Its new iOS lifecycle job stopped at Swift formatting before running the simulator tests, and its [full CI](https://github.com/Ben-Jianming/openclaw-pqc/actions/runs/38182369971) identified additional typing and test-routing corrections. Those results describe that exact revision; the corrective revision must pass its own checks.

| Source path                                                                           | Implemented boundary                                                                                                                          | Evidence still needed                                                                                                                                        |
| ------------------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| `src/security/push-dual-signature.ts`, `src/infra/push-envelope.ts`                   | Versioned dual signatures, recipient binding, strict verification, and persistent sender sequence allocation.                                 | Run the candidate's negative tests and installed key-recovery checks; document any changed trust-key lifecycle.                                              |
| `src/infra/pqc-push-state.ts`                                                         | Shared SQLite reference consumption, sender/replay state, recipient bindings, and redemption counters.                                        | Run multi-process consumption, restart, rollback/retry, and installed-profile tests for the exact candidate.                                                 |
| `src/gateway/server-methods/push.ts`, `src/gateway/server-methods.ts`                 | Authenticated key retrieval and one-time redemption registered in the lazy dispatch table; separate operator and current paired-node methods. | Run built RPC checks and revoked/replaced-node tests; record real paired-client redemption separately.                                                       |
| `src/infra/push-web-m11.ts`, `src/infra/push-apns-wake.ts`                            | Sensitive content replaced by a bounded generic wake reference.                                                                               | Run provider-failure and payload-boundary tests, then record actual provider delivery.                                                                       |
| `ui/public/sw.js`, `ui/src/app/pqc-push.ts`                                           | Fixed generic wake display, authenticated fetch, independent dual verification, and durable replay state before canonical display.            | Run the real Chromium project, including IndexedDB retries and tampering, then real Web Push acceptance. The jsdom lane does not substitute for these tests. |
| `apps/shared/OpenClawKit/Sources/OpenClawKit/PushV2Verifier.swift`, iOS wake receiver | Independent Swift transcript, portable ML-DSA verification, durable wake queue, and fetch over the authenticated node route.                  | Run both shared-library interoperability and the separate iOS app lifecycle job; physical-device and OS-display policy tests remain necessary.               |
| `src/security/nip44-v2.ts`, `extensions/nostr/src/nostr-pqc-runtime.ts`               | One shared experimental `pqc3` implementation with authenticated outer-event context and explicit required mode.                              | Run channel/context, replay, rotation, and downgrade tests; record external-client interoperability separately.                                              |
| `scripts/bench-pqc-production.ts`                                                     | Raw-sample runner with source/runtime provenance, fresh valid acceptance inputs, and balanced rotated schedules.                              | Preserve the complete exact-SHA experiment archive; label process-local measurements separately from persistent-state, RPC, network, and device timing.      |

## Trust and capability boundaries

- Local state writers, installed plugins, and the host account remain trusted operator boundaries. Key wrapping reduces exposure of device-key database rows; it does not protect against a compromised process that can use the active wrapping key.
- Both Ed25519 and ML-DSA-65 signatures must verify for Push V2 acceptance. The classical signature does not serve as a fallback for a failed PQC signature.
- Obtain trusted gateway keys through the authenticated pairing or configuration path. A notification, relay response, or self-declared public key cannot establish trust.
- Push providers and relays carry an opaque wake reference. They must not supply actionable approval content, trusted navigation, or the canonical notification body.
- A compromised delivery service can still send generic wakeups or suppress delivery. Authentication of fetched content does not remove that availability risk.
- Approval actions still require an authenticated gateway read of current approval state. Neither a wake reference nor a verified notification alone grants approval.
- Feishu's official client cannot verify a custom PQC envelope. Sending-side audit records are the available guarantee unless a controlled receiver implements and passes the acceptance checks. Do not label the official-client channel as end-to-end PQC authenticated.
- The experimental `pqc3` construction is an OpenClaw protocol; `pqc2` is its unbound legacy format. Using ML-KEM does not make either [standard NIP-44](https://github.com/nostr-protocol/nips/blob/master/44.md) or a standardized PQC HPKE suite. State confidentiality, sender authentication, replay protection, and downgrade behavior separately.
- Local push objects hold the canonical payload in the trusted state database. The limits below do not imply encryption of notification bodies at rest. Clearing or restoring a receiver database changes its replay history and requires a documented lifecycle policy.

## Push V2 signed envelope

`src/security/push-dual-signature.ts` owns the envelope and transcript. This reference describes version 2; a change to signed-field interpretation requires a new, coordinated protocol version and fixed vectors.

| Field            | Required meaning                                                                            |
| ---------------- | ------------------------------------------------------------------------------------------- |
| `version`        | The integer `2`.                                                                            |
| `algorithms`     | Exactly `["ed25519", "ml-dsa-65"]`, in that order.                                          |
| `sender_id`      | The authenticated sender identity bound to both trusted keys.                               |
| `recipient_id`   | The intended local receiver identity, checked independently of the message.                 |
| `key_id_ed25519` | The Ed25519 registry entry identifier.                                                      |
| `key_id_mldsa65` | The ML-DSA-65 registry entry identifier.                                                    |
| `created_at_ms`  | A nonnegative safe integer representing Unix time in milliseconds.                          |
| `sequence`       | A nonnegative safe integer, monotonically increasing in the sender and recipient namespace. |
| `nonce`          | Canonical, unpadded base64url encoding of 24 random bytes.                                  |
| `payload_type`   | A signed application content type.                                                          |
| `payload_sha256` | Canonical, unpadded base64url encoding of SHA-256 over the exact UTF-8 payload string.      |
| `ed25519_sig`    | Canonical, unpadded base64url encoding of a 64-byte signature.                              |
| `mldsa65_sig`    | Canonical, unpadded base64url encoding of a 3309-byte ML-DSA-65 signature.                  |

Identity and content-type strings must be nonempty, Unicode NFC, and free of unpaired surrogates. Measure limits in UTF-8 bytes: identity strings have a 256-byte limit, key identifiers have a 128-byte limit, and the signing content type has a 128-byte limit. Reject integers outside the interoperable safe range `0` through `9007199254740991`. Noncanonical base64url, including padding or alternate encodings, is invalid.

### Encode the transcript

Begin the binary transcript with ASCII `OpenClaw-PQC/Push/V2` followed by a zero byte. Append the following twelve fields in order. A tag is one byte. Integer fields contain the tag followed by an unsigned 64-bit big-endian integer. Text and byte fields contain the tag, a four-byte unsigned big-endian length, then exactly that many bytes.

| Tag | Value                    | Encoding after the tag    |
| --- | ------------------------ | ------------------------- |
| 1   | `version`                | Unsigned 64-bit integer.  |
| 2   | `algorithms[0]`          | Length-prefixed UTF-8.    |
| 3   | `algorithms[1]`          | Length-prefixed UTF-8.    |
| 4   | `sender_id`              | Length-prefixed UTF-8.    |
| 5   | `recipient_id`           | Length-prefixed UTF-8.    |
| 6   | `key_id_ed25519`         | Length-prefixed UTF-8.    |
| 7   | `key_id_mldsa65`         | Length-prefixed UTF-8.    |
| 8   | `created_at_ms`          | Unsigned 64-bit integer.  |
| 9   | `sequence`               | Unsigned 64-bit integer.  |
| 10  | Decoded `nonce`          | Length-prefixed 24 bytes. |
| 11  | `payload_type`           | Length-prefixed UTF-8.    |
| 12  | Decoded `payload_sha256` | Length-prefixed 32 bytes. |

Both signatures cover the UTF-8 bytes of this ASCII string:

```text
openclaw-push-v2-binary:BASE64URL_UNPADDED(binary_transcript)
```

They do not sign JSON serialization or the raw binary transcript directly. JSON member ordering is therefore irrelevant, but changing any of the twelve signed values changes the transcript. Do not reinterpret unknown fields as signed application actions. The payload hash covers the exact payload bytes, without receiver-side JSON reserialization or Unicode normalization.

### Apply the Accept gate

The production receiver must use strict verification with both `expectedRecipientId` and a replay guard reused across messages. Passing the low-level cryptographic verifier without these checks is not product acceptance.

1. Parse and bound the envelope, then require the exact version, algorithms, canonical encodings, and integer ranges.
2. Compare `recipient_id` with the local identity established by pairing and the authenticated device binding.
3. Check the signed timestamp. The component default maximum age is five minutes, with at most thirty seconds of future clock skew. A product policy must preserve its documented bounds.
4. Recompute the payload hash over the received UTF-8 bytes.
5. Resolve both key IDs from the trusted registry. Require matching algorithms, identifiers, sender identity, validity intervals, and revocation policy.
6. Verify both signatures over the same transcript.
7. Atomically reject a fresh repeated nonce or a sequence not greater than the stored high-water mark. Commit replay state with the verified inbox or the local business effect and its completion record.
8. Drain accepted work before acknowledging the reference. Retry a retained pending item after interruption; for completed work, return the retained result or retry acknowledgement without repeating the effect. Revalidate signatures, recipient, keys and age on recovery. Approval still performs the authenticated gateway read described above.

Failed recipient, key, time, hash, or signature checks must not consume replay state. The initial sequence policy rejects lower sequence numbers even when delivery is merely out of order. Supporting reordering requires a separately specified bounded window and new tests; it must not silently reset the high-water mark.

## Deliver and redeem a wake reference

The notification carries a reference descriptor, not the signed sensitive body. The component reference format has `version: 1`, an `object_id`, a canonical 32-byte random bearer token encoded as 43 base64url characters, and `expires_at_ms`. The reference version is separate from signed-envelope version 2.

The gateway stores the canonical payload and envelope, recipient binding, token digest, and authoritative expiry. Redemption uses the existing authenticated gateway connection. Derive the authorized recipient from the session's verified device and its subscription or APNs binding; a caller-supplied recipient string and possession of the token are insufficient.

Before reading or acknowledging the object, validate descriptor format and size, authoritative expiry, device ownership, and token digest. Compare fixed-length digests with a constant-time primitive. A wrong device, token, descriptor version, or expiry must not delete a valid object. Never record the token in diagnostics, telemetry, URLs, or audit payloads.

Reading is non-destructive, so a lost read response remains retryable until expiry. After durable local acceptance and processing, call the same redemption method with the descriptor fields plus `acknowledge: true`. The response is `{ acknowledged: true }`. Deletion and a recipient-bound token-digest receipt commit together; repeating a valid acknowledgement succeeds until the original expiry, while subsequent reads do not return the body. Read and acknowledgement each have a separate sixty-attempt per-device, one-minute budget. Expiry still bounds retries; it does not establish physical erasure of SQLite pages, WAL files or backups.

Older receivers can still read the object but do not send the new acknowledgement. Their objects occupy the existing server quota until expiry, and upgrading the server alone does not repair their replay-before-presentation loss. Deploy the matching receiver update and account for the five-minute retention window when sizing the bounded queue.

For synchronous business effects in the same shared SQLite database, use `consumePushPayloadDual` from `openclaw/plugin-sdk/push-envelope`. Verify application authorization before calling it. Its callback receives the owned database handle and must perform only synchronous local database writes, then return bounded JSON. Replay state, callback writes and the completion result share one commit. Recovery returns `already_completed` only after fresh cryptographic and identity checks; callback failure rolls back the entire commit. Do not pair standalone strict verification with a separate irreversible business write and assume atomicity.

Network calls, tools, payments and notification presentation cannot participate in this SQLite transaction. Browser and iOS receivers retain a verified pending item with replay acceptance, use a bounded presentation lease, and record completion before acknowledgement. Stable notification identifiers limit duplicate presentation after a crash between the OS effect and its local completion marker. This is recoverable delivery within the documented validity window, not an end-to-end exactly-once guarantee for external effects.

Size the complete transport payload, including its wrapper and provider encryption overhead. [APNs' ordinary payload limit](https://developer.apple.com/library/archive/documentation/NetworkingInternet/Conceptual/RemoteNotificationsPG/CreatingtheNotificationPayload.html) is 4096 bytes. Web Push services need not support encrypted message bodies above 4096 octets; the single-record format described by [RFC 8291](https://www.rfc-editor.org/rfc/rfc8291.html) leaves approximately 3993 octets for plaintext at that boundary. A particular service may impose additional limits. A fixed experimental envelope size is not a general transport budget.

Sign before committing a provider send. If either signature, storage, payload budget, or provider submission fails, stop that delivery and remove any newly created unreachable reference. Never send the original sensitive payload as a fallback. For subscriptions using this security protocol, a missing or malformed marker must still result only in a fixed generic wakeup, not provider-supplied title, body, URL, or approval routing.

### Gateway methods and receiver flow

| Method                 | Authorized caller                                                         | Result                                                                       |
| ---------------------- | ------------------------------------------------------------------------- | ---------------------------------------------------------------------------- |
| `push.pqc.keys`        | Authorized operator connection with a verified device identity.           | Active gateway public keys and key IDs, sender ID, and session recipient ID. |
| `push.pqc.redeem`      | Authorized operator connection with the bound verified device.            | Canonical payload and V2 envelope; `acknowledge: true` confirms deletion.    |
| `node.push.pqc.keys`   | Current paired node connection with its pairing generation still current. | Same key result, through the separate node role policy.                      |
| `node.push.pqc.redeem` | Current paired node connection with the bound verified device.            | Same retryable read or acknowledgement, through the node role policy.        |

The recipient comes from `connect.device.id`. The wake descriptor cannot select a different recipient. APNs registration uses the authenticated node identity; Web Push subscription creation and recipient binding occur together in the shared transaction. A reference is not an anonymous HTTP download URL.

The service worker stores bounded wake descriptors and displays fixed generic text. After the browser gateway handshake, the application retrieves the active keys and confirms that the returned recipient matches its local device identity. It fetches objects, verifies their signatures before sorting by sequence, then atomically commits its IndexedDB replay decision with the verified pending object before displaying a canonical title or body. Presentation failures retain that inbox; completion is recorded before acknowledgement and removal. A failed authenticated key-policy refresh, including a response with malformed identity, key encoding or lifecycle metadata, aborts the current drain, including the initial verification pass and the pre-acceptance/presentation refreshes, so later sequences cannot advance the replay watermark past unresolved policy work. The next connection/retry revalidates retained references and inbox entries. Invalid individual wake content still does not block unrelated valid content; this rule does not promise arbitrary out-of-order recovery for every redemption failure. A forged sequence must not decide processing order before verification. Expired references are cleared; failed live reads remain retryable; one bad reference must not prevent unrelated valid ones from being processed.

The iOS wake receiver uses `node.push.pqc.keys` and `node.push.pqc.redeem` on the captured authenticated gateway route. Swift verification precedes approval routing or local content rendering. Replay acceptance and the verified pending object share one SQLite transaction. Recovery rechecks current keys, recipient and time, then either claims an expired presentation lease or skips an already completed effect and retries acknowledgement. This source path does not establish that the OS cannot display an arbitrary remote alert sent by a compromised relay outside the verified path. In particular, a foreground callback or an optional notification service extension is insufficient evidence for background or terminated-app behavior.

The current key lookup returns the active pair. The low-level registry verifier can check validity and revocation metadata, but a complete receiving key-rotation/revocation workflow still needs its own acceptance evidence. Do not infer it solely from the active-key response.

### State and resource limits

The server uses additive `pqc_push_*` tables in the canonical state database. It does not create a separate JSON store or downgrade to an in-memory reference store on persistence failure.

| State or input                      | Current bound                                                                                                           |
| ----------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| Sender or replay identity pairs     | 10,000 per corresponding server table.                                                                                  |
| Live server nonce records           | 50,000; expired records are pruned.                                                                                     |
| Stored push objects                 | 2,000 globally and 100 per recipient.                                                                                   |
| Canonical payload and envelope      | 64 KiB payload and 16 KiB envelope per object.                                                                          |
| Reference lifetime                  | At most five minutes.                                                                                                   |
| Valid-format redemption attempts    | 60 reads and 60 acknowledgements per authenticated device per 60-second fixed window, persisted across gateway restart. |
| Completion records and ACK receipts | 50,000 per table; expired entries are pruned.                                                                           |
| Browser pending wake descriptors    | 64 live references.                                                                                                     |
| Browser replay nonces               | 1,000 unexpired nonces per sender/recipient pair.                                                                       |

These per-object and state limits do not constitute a provider delivery SLA, a database disk quota, or a complete ingress/source rate policy. Failed authenticated redemption has a uniform unavailable response without logging its token or canonical body. Invalid schema requests are rejected before reference lookup.

## Experimental message context

The Nostr production PQC path sends `pqc3`, with four canonical base64url parts:

```text
pqc3:CONTEXT_DIGEST.KEM_CIPHERTEXT.SYMMETRIC_CIPHERTEXT.HMAC
```

The context digest is SHA-256 over the UTF-8 JSON array in this exact order:

```text
["OpenClaw-PQC/Message",3,"ML-KEM-768+ChaCha20+HMAC-SHA256",senderPubkey,recipientPubkey,"nostr-dm",SHA256(recipientKemPublicKey)_lowercase_hex]
```

Sender and recipient public keys are lowercase, 64-character Nostr hex keys. The receiver reconstructs context from the verified outer event and its configured local identity; it does not trust context copied from the ciphertext. Key derivation includes the `OpenClaw-PQC/Message/V3` domain followed by a zero byte and this digest. The HMAC covers context, KEM ciphertext, and symmetric ciphertext.

`preferred` mode permits legacy `pqc2` and NIP-04 compatibility; outbound delivery uses `pqc3` when a trusted peer KEM key is configured. `required` rejects both legacy formats and missing outbound peer keys. Cryptographic failure does not trigger a legacy retry. The fixed `nostr-dm` purpose identifies this channel context; this is not a general authenticated-header protocol for arbitrary transports. Outer-event sender authentication remains classical, and full replay, rotation, and recovery acceptance must be recorded separately.

## Eight acceptance groups

The order below follows the paper-to-product review. Priorities describe implementation order, not a vulnerability severity score. Each group remains pending until its complete boundary is exercised and its evidence is attached to the candidate SHA.

| Group                                    | Work and pass condition                                                                                                                                                                                                                                                                                                                                  | Required proof                                                                                                                                                                                                                                                                                                                                                                                                                                  |
| ---------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| R1: source and key safety                | Build one fixed source revision containing the V2 contract and key safety changes. New device-key rows are wrapped; losing an active wrapping key never regenerates a substitute. Restrict wrapping and dedicated push-key files, including existing files and Windows ACLs. Errors reveal no key fragments; recovery input has size and work limits.    | Clean installation from the fixed revision, plaintext-row migration, lost-key failure, POSIX permissions, Windows ACL checks, redaction, and backup-input boundary tests.                                                                                                                                                                                                                                                                       |
| R2: fail-closed delivery                 | Both signatures are mandatory. Providers receive only a generic wake reference. Missing or tampered markers cannot reveal an external body or trigger a route. Budget and delivery failures leave no unreachable stored objects.                                                                                                                         | A provider test double records zero send calls for either signing failure. Test exact payload limits, oversize cleanup, provider failure, and notification fields modified or removed.                                                                                                                                                                                                                                                          |
| R3: receiver acceptance                  | Actual receivers apply the full Accept gate before displaying or routing canonical content. Registry keys come from an authenticated trust path; receiver identity and replay state cannot be omitted.                                                                                                                                                   | Production receiver tests for wrong recipient, time window, each signed field, either signature, unknown or revoked keys, repeated nonce, and sequence order. Node-to-Swift fixed vectors plus actual Swift-generated Ed25519 and ML-DSA-65 signatures accepted by the Node strict verifier, with transcript equality, tampered-payload and wrong-recipient rejection, and replay rejection.                                                    |
| R4: authenticated redemption             | Only the bound, authenticated device can redeem, even when another device possesses the correct token. Reads remain retryable until expiry. Authenticated acknowledgement atomically deletes the body and records a bound receipt; a lost acknowledgement response can be retried. Invalid requests do not delete. Device and source quotas bound abuse. | Real gateway handshake and redemption tests for anonymous access, wrong device, wrong token, changed expiry or version, concurrency, rate limits, and redacted diagnostics.                                                                                                                                                                                                                                                                     |
| R5: durable bounded state                | Server counters, nonce records, recipient bindings, acknowledgement receipts, and local completion records survive restarts in shared SQLite transactions. Actual receivers persist their own replay gate in canonical native state or browser IndexedDB. Object, byte, peer, and per-device limits are explicit.                                        | Restart and multi-process tests; old messages stay rejected while a restarted sender's new sequence succeeds. Exercise concurrent acceptance, expiration, capacity limits, crash recovery, profiles, and key rotation.                                                                                                                                                                                                                          |
| R6: authenticated experimental messaging | Both core and Nostr implementations bind the protocol version, suite, sender, recipient, purpose, channel, and authenticated headers. State which layer authenticates the sender. Required mode never silently falls back to a legacy format.                                                                                                            | Production send and receive tests for wrong keys, modified ciphertext, cross-context transplantation, replay, key rotation, and downgrade refusal. Protocol name and tags match the actual experimental format.                                                                                                                                                                                                                                 |
| R7: installed-product and channel tests  | Execute behavior through the installed build, not only source-string checks. Separate protocol interoperability, platform unit tests, simulator tests, physical-device tests, and real delivery tests.                                                                                                                                                   | An isolated installed-build test covers identity loading, strict push verification, and wrapping export/restore. Also launch the built gateway on loopback in isolated state, complete a valid ML-DSA device-proof handshake, and prove an invalid device proof is refused. Include the Swift-to-Node signature artifact check, real client pairing and upgrade checks, and separately recorded APNs, Web Push, and controlled Feishu delivery. |
| R8: performance and provenance           | Benchmark full strict acceptance using fresh valid sequence numbers and nonces. Label cryptographic, state-transaction, redemption, network, and display costs separately. Archive reproducible source and build identities.                                                                                                                             | Balanced operation and payload schedules, raw samples, analysis scripts, environment and dependency records, exact commands, full source at a fixed SHA, lockfile and artifact hashes. Preserve historical results with their original scope.                                                                                                                                                                                                   |

Before retrieval, iOS persists only the canonical opaque capability in `pqc_push_wakes`, bounded to 64 live records with expiration and duplicate suppression in SQLite transactions. After verification, `pqc_push_completions` retains the signed object and presentation state for recovery within the validity window; payloads are not encrypted at rest by these tables. A completed remote-notification callback does not require the current process to remain alive. Pending references are retried through the existing background-refresh handler and on foreground/relaunch; the 60-second in-process timer is only a foreground optimization. `BGTaskScheduler` scheduling and silent APNs delivery remain discretionary: a request does not guarantee execution before the five-minute capability expires. Storage failure rejects the unverified remote content; no memory-only fallback is used.

For R5, use the existing shared state database and synchronous write transaction helpers. Additive tables do not require a schema-version bump when older readers can safely ignore them. Do not create parallel JSON state or fall back to an in-memory store after persistence fails. Receiver nonce pruning must not allow an unexpired signed message to be accepted again; sender counters and receiver high-water marks need a coordinated lifecycle.

For R6, outer Nostr event verification already supplies classical authentication. Preserve that check, but do not describe it as ML-DSA sender authentication. If an interim design only permits experimental ciphertext inside an authenticated outer protocol, state that narrower guarantee until a reviewed PQC-authenticated profile passes interoperability tests.

## Record product evidence

Create an evidence record for each release candidate before running the acceptance gates. The record must contain:

- Full source SHA, clean or dirty state, lockfile hash, build command, and artifact hash.
- Operating system, architecture, Node version, package manager version, and loaded cryptographic library versions.
- Actual command, test suite or device workflow, execution time, result, and output artifact.
- The group and assertion proved, plus skipped cases and blocked checks.
- Client build and OS version, delivery channel, and whether the receiver was a unit fixture, simulator, or physical device.

Keep secret values, push tokens, wrapping keys, private keys, and private notification bodies out of these records. A successful overall workflow with skipped jobs does not satisfy the skipped assertions.

### Check installation behavior

Use a separate state directory and test credentials. Do not run destructive migration, recovery, or rotation exercises against a user's active gateway. Follow the [Node installation requirements](/install/node) and use the repository's selected test route.

These checks establish different scopes:

| Check                                  | Establishes                                                                                                                               | Does not establish                                                            |
| -------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------------------- |
| Built CLI `--version` and `--help`     | The built entry point starts and exits for those commands.                                                                                | Device authentication, signature verification, or recovery.                   |
| Source contract inspection             | Selected source files contain an expected declaration or call.                                                                            | That the installed build executes the call correctly.                         |
| Cryptographic component test           | The tested algorithms and input cases behave as recorded.                                                                                 | A wired receiver, authenticated redemption, or transport delivery.            |
| Native identity interoperability test  | The named device-proof or identity vectors work on that platform.                                                                         | Push V2 transcript or physical-device delivery.                               |
| Swift-to-Node Push V2 interoperability | Node verifies the public artifact's actual native-generated dual signatures, matching transcript, recipient binding, and replay behavior. | A physical-device handshake, APNs delivery, or iOS background display policy. |
| Built loopback device-proof handshake  | The isolated built gateway accepts a valid ML-DSA proof and refuses an invalid proof over its actual connection path.                     | Physical clients, remote deployment, or real push providers.                  |
| Installed gateway and receiver test    | The named built authentication, redemption, and Accept flow works.                                                                        | Unexercised platforms or real provider delivery.                              |
| Physical-device and real-provider test | The recorded build, device, and channel completed that workflow.                                                                          | Other devices, configurations, channels, or later releases.                   |

The installation verifier must print the checks it actually executes. Until the required installed-build behavior exists and passes, do not print that all production wiring or end-to-end PQC capability is ready.

For Swift-to-Node acceptance, `PushV2VerifierTests.nativeSignaturesCanBeExportedForServerVerification` generates actual native signatures and writes public-only JSON when `PQC_PUSH_INTEROP_OUTPUT` is set. `scripts/verify-native-push-v2.ts` must consume that artifact and execute strict Node dual-signature verification; checking that the test name or source string exists is insufficient. Record the actual native job result for the candidate being delivered, separately from iOS simulator lifecycle and physical-device results.

The additional installation gate starts the built gateway on loopback with temporary, isolated state and exercises both successful ML-DSA authentication and invalid-proof rejection through the built gateway-client SDK. It also calls the registered key and redemption methods. The recorded Windows and Linux production-acceptance run above exercised this built-process path. Repeat it for the delivered candidate; it does not replace the physical-device or live-provider checks below.

Run focused source tests with the repository runner and the matching project configuration, for example:

```bash
node scripts/run-vitest.mjs run --config test/vitest/vitest.unit-security.config.ts src/security/push-dual-signature.test.ts src/security/push-reference.test.ts src/security/pqc-message-context.test.ts
node scripts/run-vitest.mjs run --config test/vitest/vitest.infra.config.ts src/infra/pqc-push-state.test.ts src/infra/pqc-push-consumer.test.ts src/infra/push-envelope.test.ts src/infra/push-browser-interop.test.ts
```

Inspect each report to confirm the requested files ran; the project configurations can permit an empty test selection. These commands do not build the product, run native clients, exercise a built gateway handshake, or validate a real provider.

### Exercise recovery separately

The local key safety implementation includes these CLI operations:

```bash
openclaw security wrap-key status --json
openclaw security wrap-key export --output <new-backup-file> --passphrase-file <private-passphrase-file>
openclaw security wrap-key import --input <backup-file> --output <new-key-file> --passphrase-file <private-passphrase-file>
openclaw security wrap-key rotate --output <new-key-file> --key-id <new-key-id>
```

Output files must not already exist. Keep the passphrase file private and do not place the passphrase directly on the command line. Import creates a key file; it does not by itself prove an identity database can be restored. Test the backup together with the matching state database in an isolated profile, confirm the restored public identity, and record the actual configuration needed to select the restored key. After rotation, prove that the new key opens the rows and that the prior key cannot open the new wrapped rows. Preserve the prior backup until the recovery drill passes.

An absent wrapping key for already wrapped rows is a recovery failure. Do not fix it by generating a fresh key, silently replacing the identity, or suppressing the error.

### Complete physical and live-channel acceptance

Record separate results for each supported client and channel:

1. Pair a fresh client and verify that the negotiated device algorithm matches its actual proof.
2. Upgrade an existing paired client and verify identity preservation or the documented migration and re-pairing behavior.
3. Deliver a generic wakeup through the actual provider, redeem through the authenticated gateway, and verify canonical content before rendering.
4. Tamper with each provider-visible field using a controlled relay or receiver test fixture. Confirm that the client never displays injected body text or takes an injected route.
5. Repeat in background, terminated-app, reconnect, duplicate-delivery, and expired-reference conditions relevant to the platform.
6. Confirm that approvals always re-read current gateway state and cannot be completed from notification content alone.

Real APNs acceptance needs a signed app, physical Apple device, authorized APNs credentials, and the intended application environment. A simulator or mock HTTP/2 endpoint cannot supply that evidence. Feishu's official client remains sending-side audit only; live end-to-end custom verification requires a controlled receiver or official protocol support. If credentials, a receiver, or a physical device are unavailable, record the check as blocked or pending rather than passed.

For iOS, include an adversarial relay test that replaces the whole APNs payload, removes its PQC marker or extension trigger, and sends an ordinary alert while the app is backgrounded or terminated. Until an enforceable OS/display policy and those device tests reject attacker-controlled visible content, retain the compromised-relay limitation. Passing the authenticated fetch verifier or foreground display test alone is insufficient.

## Benchmark the strict path

Cryptographic verification and full Accept are separate benchmark operations. Reusing one valid envelope with a persistent replay guard measures first acceptance followed by rejection, not repeated successful acceptance. For the strict benchmark, create a fresh legal nonce and increasing sequence for every accepted sample while reusing the real guard and persistence backend.

Record operation order and payload order, and use an actually balanced schedule when comparing positions. Similar random seeds do not prove position balance. Include warmup policy, repetitions, failures, medians or distributions, and the precise timed boundary. Keep network and rendering measurements separate from local cryptographic and transaction measurements.

Archive raw samples and analysis inputs with the exact source and dependency identity captured at execution. A later archive can freeze existing materials, but cannot retroactively prove which source or runtime generated historical measurements. Keep older microbenchmarks labeled with their original coverage instead of relabeling them as full Accept or field performance.

The new runner rejects tracked dirty state and records the source SHA, selected source-file hashes, lockfile hash, Node version, OS, CPU, process ID, operation schedule, warmup policy, and raw samples. It measures 13 operations over 64-, 1024-, and 16384-byte inputs, with 10 warmups and 100 timed samples for each operation/input pair. Run each index `0` through `38` in a fresh process to complete the 13-operation by 3-payload balanced cycle. A single index is only part of that cycle.

```bash
node --import tsx scripts/bench-pqc-production.ts 0 .artifacts/pqc-benchmark
```

Replace `0` with each remaining index after committing the exact candidate source. This creates new measurements; it does not reproduce or relabel the paper's historical 15-process data. The runner's strict acceptance uses a process-local replay guard and fresh valid messages. It excludes SQLite, gateway RPC, network delivery, and device display latency. Measure and label those persistent/product boundaries separately before claiming full production acceptance performance. Retain the complete fixed source, dependencies, build artifacts, raw results, and analysis alongside their digests; selected source hashes alone are not a complete release archive.

## Related guidance

- [PQC security scope](/security/pqc-whitepaper)
- [Gateway security](/gateway/security)
- [Nostr channel](/channels/nostr)
- [Node installation requirements](/install/node)
