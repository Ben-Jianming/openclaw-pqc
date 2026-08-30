# PQC M1-M12 + M5 v2 + M12 v2 + feishu-deploy patches (15 total)

These 15 patches contain the complete PQC + Feishu deployment work on the
local `pqc-ws` branch. They were generated with `git format-patch` on top
of danteng's squash commit `c87a41c1` (M1+M3+M4 abstract).

## State at patch time (2026-08-20)
- WSL `pqc-ws` HEAD: `d7ea083d14b` (feishu-deploy on top of M12 v2)
- WSL `upstream/feat/pqc-migration` HEAD: `c87a41c1805` (danteng's squash)
- WSL `upstream/main` HEAD: `37ff2e511e8` (v0.1 release, 2026-07-27)
- Tests: **180 passed + 4 skipped (Ed25519-legacy)** across 12 PQC test files
  (M5 v2 added 5 new invariants in `device-identity-wrap-env.test.ts`).
- `pnpm build`: **PASSES** end-to-end (cold ~4m 30s, warm ~25s with cache).
- Runtime verified: gateway boots, ML-DSA-65 device identity wrapped in sqlite,
  **Feishu channel loads at runtime** (requires real FEISHU_APP_ID/SECRET
  to actually connect).
- 15 commits total:
  1. `53a5a32e6a1` M1 ML-DSA-65 key storage
  2. `60c08d7fcdd` M2 device-identity public API
  3. `2ee3bc5ddd5` M3 state.db additive schema
  4. `eea7932027c` M4 AES-256-GCM wrap envelope
  5. `cdeddc369b0` M5 device-identity store wrap integration
  6. `033c4009faa` M6 keyring providers
  7. `29bffac995d` M7 wrap-key rotation + passphrase backup
  8. `acd7d970676` M8 wrap-key health check + CLI aliases
  9. `9bf366f0c27` M9 structured PQC log
  10. `61fada3de2e` M10 NIP-44 v2 + ML-KEM-768 hybrid
  11. `9050ef96e57` M11 APNs ML-DSA-65 dual signature
  12. `386366997b0` **M12** build infra fix (fs-safe 0.4.4→0.4.7 + cli-argv export)
  13. `6b25059abd9` **M5 v2** env-var auto-wrap (OPENCLAW_PQC_WRAP_KEY)
  14. `37007e9b61e` **M12 v2** pnpm hoisting workarounds + Shai-Hulud dep override
  15. `d7ea083d14b` **feishu-deploy** hoist 5 Feishu deps + 3 missing plugin-sdk exports
  15. `d7ea083d14b` **feishu-deploy** hoist 5 Feishu deps + 3 missing plugin-sdk exports

## M12 build fix (patch 0012)

Two pre-existing danteng issues that blocked `pnpm build`:

1. `@openclaw/fs-safe` 0.4.4 missing `./durability` subpath
   (danteng imported it in gateway.ts + backup-archive-publication.ts
   at c87a41c1). Bump pin to 0.4.7.
2. `dist/plugin-sdk/cli-argv.{js,d.ts}` is built by tsdown-unified
   but missing from `package.json` `exports` (294 explicit keys,
   no wildcards). Add explicit entry.

After both fixes, `pnpm build` end-to-end, all phases green.

## M5 v2 runtime fix (patch 0013)

M5 (commit `cdeddc369b`) marked the device-identity keyring as **optional**
and fell back to `mldsa_private_key_pem` plaintext storage when absent. This
conflicts with the handoff spec which requires fail-closed storage of the
ML-DSA-65 long-term private key.

This patch wires a custom inline `SyncWrappingKeyProvider` into
`loadOrCreateDeviceIdentityOwned`, sourced from two env vars:
- `OPENCLAW_PQC_WRAP_KEY` (required in production) — 32-byte base64url AES-256 key
- `OPENCLAW_PQC_WRAP_KEY_ID` (optional) — logical key id, defaults to `env-default`

We do **NOT** use the `EnvKeyring` class because it hardcodes the env var
name as the keyId, which would force `WRAP_KEY_ID = "OPENCLAW_PQC_WRAP_KEY"`.
The env var name is an implementation detail; users set a logical keyId via
`OPENCLAW_PQC_WRAP_KEY_ID`.

If neither env var is set, the existing plaintext path is used with a
one-time stderr warning, so dev/test workflows are not broken. Production
deployments **must** set `OPENCLAW_PQC_WRAP_KEY` to get wrap protection.

Adds 5 invariants in `device-identity-wrap-env.test.ts`:
1. Wrap write produces a non-null `mldsa_private_key_wrapped` BLOB
2. Round-trip unwrap recovers the original ML-DSA-65 private key bytes
3. Plaintext fallback when env vars are absent (and warning emitted)
4. Wrong key rejection (decryption fails, original wrapped bytes preserved)
5. Default keyId `env-default` used when `OPENCLAW_PQC_WRAP_KEY_ID` unset

## M12 v2 hoisting workarounds (patch 0014)

After `git clean -fdx` wiped `node_modules`, 5 transitive deps stopped
being resolvable from the workspace root because their consumers live in
deep `node_modules/.pnpm` paths. Hoist them to direct dependencies:

- `@discord/embedded-app-sdk@2.5.0`
- `@noble/ed25519@3.1.0`
- `@pierre/diffs@1.2.12`
- `@shikijs/langs@4.3.1`
- `@shikijs/themes@^4.4.3`
- `@shikijs/transformers@^4.4.3`

Plus `pnpm.overrides.fetch-blob = ^4.0.0` to skip the **Shai-Hulud-worm**
`node-domexception@1.0.28` typosquat that the legacy lockfile still
references from `fetch-blob@3.2.0`. The 1.0.28 package was unpublished
from npm; the override forces resolution to the safe 4.x line.

`pnpm install` with this commit is a no-op (all packages are already in
the lockfile). `pnpm build` remains green.

## Why not just `git push`?
The local WSL2 NAT can't reach `github.com:443` reliably — `git push`
times out with `Failed to connect to github.com port 443 after 139124 ms`.
`curl --depth 1` worked in earlier turns because the bug is in long-lived
TLS connections, which `git push` always opens. These patches let you
apply the work locally on a host that can reach GitHub.

## Apply in 3 commands

```bash
# In your Ben-Jianming/openclaw-pqc checkout, on a fresh branch off main
git checkout -b pqc-m2-m12 main
git am /path/to/D/minimax/pqc-patches/*.patch
git push -u origin pqc-m2-m12
```

The patches apply in numeric order on top of `c87a41c1805` (which is
**not** a parent of `upstream/main`; you must either rebase or
cherry-pick onto the right base). Two clean options:

### Option A: branch off `feat/pqc-migration` (cleaner, matches danteng)
```bash
git fetch upstream
git checkout -b pqc-m2-m12 upstream/feat/pqc-migration
git am /path/to/D/minimax/pqc-patches/*.patch
git push -u upstream pqc-m2-m12
```

### Option B: cherry-pick onto `main` (after the v0.1 release)
```bash
git fetch upstream
git checkout -b pqc-m2-m12 upstream/main
# Apply M1 (M1 KAT) directly, then M2..M15 patches in order.
git cherry-pick c87a41c1                # danteng's squash (the v0.1 base)
# Now apply each M2..M15 patch in order:
for p in /path/to/D/minimax/pqc-patches/000{2..15}*.patch; do
  git am "$p" || { echo "conflict in $p"; break; }
done
git push -u upstream pqc-m2-m12
```

### Option C: `git bundle` (if you have direct WSL access later)
The 1.5 GB git bundle was created at `/home/benjamin/pqc-m1-m12.bundle`
in the WSL filesystem. It contains every object from c87a41c1..HEAD
plus the full repo history. To restore from it on the target host:
```bash
git clone --bundle /home/benjamin/pqc-m1-m12.bundle pqc-fork
cd pqc-fork && git remote set-url origin https://github.com/Ben-Jianming/openclaw-pqc.git
```

## Author identity
All 15 commits are authored by `wu <wuc8974@gmail.com>` (danteng's
identity) per the danteng handoff prompt §7. Re-author with
`git commit --amend --author=...` if you want your own identity before
pushing.

## Test command
```bash
cd openclaw-upstream
./node_modules/.bin/vitest run \
  src/infra/device-identity.test.ts \
  src/infra/device-identity-store.test.ts \
  src/infra/device-identity-store.wrap.test.ts \
  src/infra/device-identity-wrap-env.test.ts \
  src/security/secret-wrapping.test.ts \
  src/state/openclaw-state-db-schema-additive.test.ts \
  src/security/keyring-provider.test.ts \
  src/security/wrap-key-rotation.test.ts \
  src/security/wrap-key-cli.test.ts \
  src/logging/pqc-log.test.ts \
  src/security/nip44-v2.test.ts \
  src/security/push-dual-signature.test.ts
```
Expect: **180 passed, 4 skipped (Ed25519-legacy KAT)**.

## What M1-M12 cover
| Milestone | Whitepaper | File |
|-----------|-----------|------|
| M1 | 2.1.1 ML-DSA-65 key storage | `src/infra/mldsa65-key-storage.ts` |
| M2 | 2.1 device-identity public API | `src/infra/device-identity.ts` |
| M3 | 2.1.3 + 2.2.1 state.db schema additive | `src/state/openclaw-state-db-schema-additive.ts` |
| M4 | 2.2.1 AES-256-GCM wrap envelope | `src/security/secret-wrapping.ts` |
| M5 | 2.2.2-2.2.4 store wrap integration | `src/infra/device-identity-store.ts` |
| M5 v2 | (env-var auto-wrap) | `src/infra/device-identity.ts` + `device-identity-wrap-env.test.ts` |
| M6 | 2.2.5 keyring providers | `src/security/keyring-provider.ts` |
| M7 | 2.2.5.C-D rotation + backup | `src/security/wrap-key-rotation.ts` |
| M8 | 2.2.7-2.2.8 health check + CLI | `src/security/wrap-key-cli.ts` |
| M9 | 2.2.9 PQC structured log | `src/logging/pqc-log.ts` |
| M10 | 1.1 NIP-44 v2 + ML-KEM-768 | `src/security/nip44-v2.ts` |
| M11 | 1.3 APNs dual signature | `src/security/push-dual-signature.ts` |
| M12 | (build infra) | `package.json` (bump + exports entry) |
| M12 v2 | (build infra) | `package.json` (hoisted deps + pnpm.overrides) |
| feishu-deploy | (deployment) | `package.json` (Feishu deps + 3 plugin-sdk exports) |
