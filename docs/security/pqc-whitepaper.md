---
summary: "Implemented PQC guarantees, compatibility boundaries, and release checks"
title: "PQC security scope"
---

# PQC security scope

OpenClaw PQC is a staged migration. This page states what the product enforces today and what remains conventional cryptography.

## Production guarantees

- Node and CLI device identities use ML-DSA-65 (FIPS 204). The gateway derives the device ID from the public key and verifies the signed connect payload, nonce, timestamp, role, scopes, client metadata, and authentication token binding.
- Apple, Android, Linux, and browser clients currently use Ed25519 device keys. They declare `algorithm: ed25519`; the gateway verifies that proof through the same mandatory authentication path. A declared algorithm that does not match the key is rejected.
- Existing plaintext ML-DSA private-key rows are atomically wrapped when `OPENCLAW_WRAP_KEY_FILE` or `OPENCLAW_PQC_WRAP_KEY` becomes available. Wrapped rows fail closed if their key is missing.
- PQC security events use the structured PQC audit stream. An audit record is evidence that an operation was attempted or completed; it is not by itself an end-to-end channel guarantee.

## Current limits

- ML-KEM-768 and NIP-44 PQC helpers are cryptographic building blocks. The production Nostr channel still uses its documented NIP-04 protocol. Nostr is therefore not claimed as post-quantum secure.
- APNs, Web Push, and Feishu cross third-party delivery services. Until a receiving client validates a pinned gateway signature before rendering content, these paths do not provide end-to-end PQC authenticity. Approval always requires an authenticated gateway read; push content alone never approves an action.
- A hosted APNs relay can deliver notifications to a token enrolled with that relay. Treat the relay as a delivery trust dependency. Use direct APNs or disable visible relay notifications when that trust is unacceptable.
- Hybrid KEM transport negotiation, key distribution, and downgrade policy are not part of the current production protocol. The software does not silently advertise them as active.

## Key wrapping

Set `OPENCLAW_WRAP_KEY_FILE` to an absolute path containing one base64url-encoded 32-byte key. On POSIX the file must have mode `0600`. `OPENCLAW_PQC_WRAP_KEY` remains available for managed environments, but a key file avoids shell-history exposure. Keep an offline backup; losing the wrapping key makes wrapped identities unrecoverable.

Use `openclaw security wrap-key status` to inspect the store. `export` and `import` use a passphrase file so the passphrase does not appear in shell history. `rotate --output <new-file> --key-id <new-id>` atomically re-wraps every identity row and writes the new raw key to a file that must not already exist. Test a backup/restore before deleting an old key.

## Release verification

`verify.sh`, `verify.bat`, and the source verification script check the built CLI and execute the installed production-contract test. The contract verifies the fixed Ed25519 interoperability vector, declared algorithms for every shipping client, and the gateway proof call path. CI must additionally run unit, integration, platform, and clean-install jobs.

Passing these checks proves the named contracts only. It does not turn an unwired KEM helper, an audit-only signature, or a third-party transport into an end-to-end PQC channel.
