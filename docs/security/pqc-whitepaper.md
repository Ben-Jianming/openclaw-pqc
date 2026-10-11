---
summary: "Implemented PQC guarantees, compatibility boundaries, and release checks"
title: "PQC security scope"
---

# PQC security scope

OpenClaw PQC is a staged migration. This page describes the current source implementation and its limits. Check the exact downloaded revision and its test evidence before applying these statements to an installed build. The [PQC production acceptance reference](/security/pqc-production-v2) defines the eight release acceptance groups and the Push V2 wire contract.

## Implemented source paths

- Node and CLI device identities use ML-DSA-65 (FIPS 204). The gateway derives the device ID from the public key and verifies the signed connect payload, nonce, timestamp, role, scopes, client metadata, and authentication token binding.
- Apple, Android, Linux, and browser clients have ML-DSA-65 generation and signing paths. Apple uses the system provider when available and the bundled portable provider on older systems. Existing Ed25519 identities remain an explicit compatibility path. The gateway verifies the declared algorithm through the mandatory device-proof path; a declaration that does not match the key is rejected. Cross-language identity tests are separate from physical-device pairing and upgrade acceptance.
- New Node/CLI ML-DSA private-key rows are always wrapped. Without an explicit key, the runtime provisions a private key at `credentials/device-identity-wrap.key` under the canonical state directory. Existing plaintext rows are atomically wrapped on the next load. Wrapped rows fail closed if their key is missing.
- PQC security events use the structured PQC audit stream. An audit record is evidence that an operation was attempted or completed; it is not by itself an end-to-end channel guarantee.
- Push V2 binds both signatures to the sender, recipient, key IDs, timestamp, sequence, nonce, content type, and exact payload hash. APNs and Web Push send a generic wake reference; the canonical body stays in the gateway until authenticated, one-time redemption. Sender counters, server replay state, recipient bindings, stored references, and redemption limits use the canonical SQLite state database.
- The browser receives the reference after its gateway handshake, verifies both signatures with keys from that authenticated connection, commits replay state in IndexedDB, and then displays the canonical body. The service worker displays only fixed generic text when a wake arrives, including malformed or missing markers. Clearing browser storage clears its local replay history; it is not a permanent trust store.
- The Nostr send and receive paths support the experimental `pqc3` ML-KEM-768 construction for configured peers. It binds the suite, version, sender, recipient, purpose, and recipient KEM key to key derivation and authentication. See [Nostr](/channels/nostr) for explicit compatibility and required-mode rules.

Source implementation and focused tests do not establish a released installation. The key safety work was implemented in local commit `6bea43974092e82caa035c192fd96e35f0882c77` before publication; release evidence must identify a published descendant containing it. Push V2 integration needs final build, review, CI, and installed-product evidence for its candidate revision.

## Current limits

- `pqc3` is an experimental OpenClaw format, not standard NIP-44 or a standardized HPKE suite. The outer Nostr event still authenticates the sender with the classical Nostr signature. ML-KEM confidentiality does not make that sender authentication post-quantum. Peer KEM keys require authenticated provisioning; this is not automatic protocol negotiation for every channel.
- `preferred` Nostr mode permits NIP-04 fallback and accepts legacy `pqc2` messages. Use `required` with trusted peer keys when legacy fallback is unacceptable. Required mode rejects both legacy formats instead of retrying them after a PQC failure.
- APNs and Web Push cross third-party delivery services. A provider can suppress delivery or generate wakeups. Approval always requires an authenticated gateway read; push content alone never approves an action. One-time redemption does not guarantee delivery if its response is lost.
- The generic APNs payload protects the honest gateway send path. It does not prove that iOS rejects an arbitrary alert sent by a compromised relay while the app is backgrounded or terminated. Foreground callbacks and a notification service extension cannot establish that broader OS-display guarantee by themselves. Physical-device tests and an enforceable display policy are still required.
- Feishu's official client cannot verify a custom PQC envelope. It remains sending-side audit only unless a controlled receiver implements verification or Feishu adds protocol support. Real APNs, Web Push, and controlled Feishu interoperability must be recorded separately from local fixtures.
- Stored canonical push payloads are bounded local state, not a new encrypted-message-at-rest guarantee. The trusted host and its filesystem protection remain part of the security boundary.

## Key wrapping

The runtime creates a random 32-byte key on first device-identity creation if no key is configured. Its default location is `credentials/device-identity-wrap.key` under the canonical state directory. The file must have mode `0600` on POSIX. On Windows, the runtime restricts and verifies the ACL to the current user and SYSTEM before writing key material; failure prevents identity creation. Operators can instead set `OPENCLAW_WRAP_KEY_FILE` to an absolute path containing one base64url-encoded 32-byte key. `OPENCLAW_PQC_WRAP_KEY` remains available for managed environments. Keep an offline backup of the key and state database; losing the wrapping key makes wrapped identities unrecoverable. Replace an active key only through the rotation command, not by changing the file in place.

Use `openclaw security wrap-key status` to inspect the store. `export` and `import` use a passphrase file so the passphrase does not appear in shell history. `rotate --output <new-file> --key-id <new-id>` atomically re-wraps every identity row and writes the new raw key to a file that must not already exist. Test a backup/restore before deleting an old key.

## Release verification

Inspect the actual checks run by `verify.sh`, `verify.bat`, and `scripts/verify-source-install.mjs`. CLI `--version` and `--help` establish startup for those commands. Source-contract assertions establish the named declarations and call sites. Neither is an installed gateway handshake, a Push V2 recipient/replay test, or a wrapping-key restore drill. CI must additionally run unit, integration, platform, and clean-install jobs against the candidate build; skipped jobs are not coverage.

Use the [acceptance matrix](/security/pqc-production-v2#eight-acceptance-groups) to record the source SHA, artifact digest, runtime, command, assertions, and remaining field checks. Focused tests are useful evidence for their tested boundary, but do not substitute for a fresh build or real devices. Benchmark results also need their execution-time provenance and timed scope; cryptographic checks with an in-memory replay guard do not measure SQLite, network, or rendering latency.
