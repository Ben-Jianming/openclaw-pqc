---
title: "Secure push recovery"
summary: "Ordered publication and bounded immutable snapshots for missed signed notifications"
---

# Secure push recovery

This development candidate recovers unacknowledged signed notifications after a missed provider wake. The published installation preview `pqc-preview-2026.11.03` does not contain it. Source tests, browser harnesses and generated clients do not establish real provider delivery, closed-browser acceptance or production readiness.

## Authentication and compatibility

Upgrade Gateway and Control UI together. A client requests `push-recovery-snapshot-v1`; the server advertises support back on that connection. It advertises `push-recovery-snapshot-active-v1` only for an operator session that authenticated with its device token and proved its device key in the signed handshake. Recovery also requires current pairing, a live operator token, read scope and `push-key-policy-v1`.

The ordinary UI authentication selection is unchanged. The push lifecycle explicitly prepares one reconnect using the stored, scoped device token when the server supports snapshots but the current session is not active. It does not replace a revoked device token with shared credentials to authorize recovery. A session requiring recovery holds queued work until that upgrade succeeds. Clients or servers without negotiated recovery retain the original per-object capability read/ACK path; tokenless recovered inboxes never fall back to it.

Every listing and ACK rechecks pairing, public-key binding, current roles/scopes and the SHA-256 fingerprint of the credential that authenticated the session. A replaced or revoked token cannot authorize an old session merely because another token is now active. A negotiated recovery session with stale pairing or credentials is invalidated and closed; the existing reconnect supervisor reloads the stored device token. Automatic reauthentication requires the replacement token to be available in that device's scoped storage. It cannot manufacture a replacement credential. Device IDs in request parameters never grant access. This is request-time authorization, not instantaneous withdrawal of data already returned or notifications already handed to the OS. Native recovery and APNs acceptance remain unverified.

## Ordered publication

Production Web Push and APNs build their opaque wakes through the shared SQLite store. Sequence allocation, synchronous dual signing, object admission, publication marking and the per-sender/recipient published watermark commit in one immediate transaction. Existing nested savepoints are reused. Signing/admission failures and a publishing process exiting before commit roll back the allocation and object together. A stale or already published sequence cannot be published later.

Custom reference stores do not participate in the SQLite recovery RPC or its guarantees. Existing objects created outside atomic publication are marked as legacy. Recovery fails closed while live legacy objects remain for the recipient; it neither silently excludes them nor deletes them to make a check pass. Before deploying this candidate, stop old writers and allow their original finite TTL to drain, or complete an explicitly reviewed migration. Do not alter a live operator profile or regenerate identities as an upgrade shortcut. Mixed old/new writers and production migration have not been accepted.

## Immutable pages

| Method                 | Params                                   | Successful result                                                                                   |
| ---------------------- | ---------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `push.pqc.pending`     | `{}` or `{after: {snapshotId, offset}}`  | `{snapshotId, items: [{object_id, expires_at_ms, value: {payload, envelope, recipientId}}], next?}` |
| `push.pqc.pending.ack` | `{version: 1, object_id, expires_at_ms}` | `{acknowledged: true}`                                                                              |

A first listing fixes the complete visible object membership in the same database transaction. Later pages use an offset into that immutable membership, bound to the recipient and session credential fingerprint. A concurrent insertion cannot move ahead of a cursor and appear only after a higher sequence has been accepted. Atomic publication ensures later publications have later sequences in the same sender/recipient domain. ACKed or expired objects can disappear from a snapshot, but later insertions cannot join it.

Snapshots contain object identifiers and original expiry only, not a second copy of plaintext. They expire after 60 seconds, with at most four active snapshots per recipient, 128 globally and 32 KiB of membership JSON each. A changed credential cannot continue an old snapshot. Expired snapshots are reclaimed; a new authenticated scan does not renew any message's original lifetime. Lost pages can be retried while the same snapshot and object remain live.

Each response contains at most 16 objects and 2 MiB of JSON including escaping. The client bounds a scan to 32 pages. The existing limits remain: 100 outstanding objects per device, 2,000 globally, 64 KiB payload, 16 KiB envelope, original lifetime at most five minutes, and separate read and ACK budgets of 60 operations per minute. Capacity or expiry failures are explicit, not an unlimited delivery guarantee.

## Replay, inbox and failures

In active snapshot mode, the receiver gathers the complete snapshot before advancing replay state for any combined recovered or capability-bound work. A failed or partial snapshot holds that work for retry. Continuing a higher capability sequence during such a failure would burn unseen lower sequences; the legacy compatibility path is therefore separate from negotiated strict recovery.

Every member of a completed snapshot uses the recovery read/ACK path, including an object already present as a legacy wake with a valid bearer capability. That capability cannot bypass the current pairing and credential checks at ACK time. Active recovery is advertised only when both recovery and key-policy capabilities have been negotiated.

The receiver verifies both signatures, context, payload hash, signed time window and current key policies before sorting by sequence. Replay state and the verified inbox commit together in IndexedDB. Policies are refreshed again before presentation, and ACK follows the durable display-completion marker. Wake/inbox queues remain bounded at 64 live entries. A stable OS notification tag reduces duplicates across a crash, but presentation is not exactly once.

The Gateway enforces reference TTL using its own clock. The client does not infer that clock from an additional browser-relative upper TTL bound; signed-envelope age/future-skew checks, expired-reference rejection and key validity still apply. Unsynchronized clocks are not generally supported.

Connected clients poll every 60 seconds and dispose their retry timer. Browser suspension, whole-device network loss, snapshot expiry, queue saturation or an offline interval exceeding original message TTL can prevent delivery. None is evidence of indefinite offline storage.

## Acceptance still required

Bind the final artifact and source revision to default installation, actual signed Gateway handshakes, no-wake discovery, browser close/reopen within TTL, concurrent publication, server restart, lost pages/ACK, token rotation and revocation between pages, legacy drain, expiry and capacity. Keep provider acceptance, browser receipt, cryptographic acceptance, presentation and ACK as distinct observations. Physical network-disconnection, visible popup/click, real APNs and third-party reproduction remain separate gates. Do not infer them from unit/harness results or an earlier installation preview.
