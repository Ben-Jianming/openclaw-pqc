# Install OpenClaw PQC

This repository is the post-quantum cryptography fork of OpenClaw. Its installer uses this source tree, the committed lockfile, and the pinned pnpm version. It then builds and verifies the CLI and PQC sources.

> Do not use `npm install -g openclaw@latest` for this fork. That command installs upstream OpenClaw without this repository's PQC changes.

## Requirements

- 64-bit Windows 10/11, macOS, or a common Linux distribution
- Node.js 22.22.3+, 24.15.0+, or 25.9.0+ (Node 23 is unsupported; Node 26 recommended)
- Internet access to the npm package registry
- Git only when cloning; a ZIP installation does not need Git

Check Node with `node --version`.

## Get the complete source

Clone the repository:

```bash
git clone https://github.com/Ben-Jianming/openclaw-pqc.git
cd openclaw-pqc
```

Or open the [GitHub repository](https://github.com/Ben-Jianming/openclaw-pqc), select **Code → Download ZIP**, and fully extract the archive. A ZIP received from another person works the same way. Do not run the installer from an archive preview window.

## Install

On Windows, double-click `install.bat`, or open PowerShell in the extracted directory and run:

```powershell
.\install.ps1
```

If PowerShell blocks the script for this session:

```powershell
Set-ExecutionPolicy -Scope Process Bypass
.\install.ps1
```

On macOS or Linux:

```bash
chmod +x install.sh start.sh stop.sh verify.sh
./install.sh
```

The installation can be run again safely after an update. It accepts only the pnpm version pinned by this repository. When that version is not already available, the installer uses npm to download and run it temporarily.

## First-time setup

Run the guided setup from the project directory:

```bash
node openclaw.mjs onboard --install-daemon
```

Provide API keys only through the setup wizard, secure storage, or environment variables. Never save keys in launcher scripts or commit them to GitHub.

For encrypted device-key storage, create a file containing one base64url-encoded 32-byte key, keep it outside the repository, and set `OPENCLAW_WRAP_KEY_FILE` to its absolute path. On macOS/Linux run `chmod 600 <file>`. Copy `.env.example` to `~/.openclaw/.env` for a daemon and set the path there. Back up this key offline: wrapped identities cannot be recovered without it. An existing plaintext identity is wrapped automatically on the next start after the variable is configured.

### Provision or enroll dual-signature push keys

These additive commands belong to this local candidate. They do not establish that GitHub `main` or an older package includes the changes. Check `node openclaw.mjs security push-key --help` first. Full default installation, full CI, cross-platform installation and closed-browser offline delivery require separate acceptance.

**New identity:** before first identity creation, use a previously unused named profile for an isolated exercise. Inspect `OPENCLAW_STATE_DIR` and `OPENCLAW_CONFIG_PATH` first: explicit paths can override profile isolation. Never reuse active Gateway state. Replace the workspace placeholder with a new absolute path and select the same profile for every command:

```bash
node openclaw.mjs --profile pqc-first-install config file
node openclaw.mjs --profile pqc-first-install setup --baseline --workspace <absolute-new-workspace>
node openclaw.mjs --profile pqc-first-install config validate --json
node openclaw.mjs --profile pqc-first-install security push-key status --json
node openclaw.mjs --profile pqc-first-install security push-key init --valid-from-ms <activation-ms> --valid-until-ms <expiry-ms>
node openclaw.mjs --profile pqc-first-install security push-key status --json
node openclaw.mjs --profile pqc-first-install doctor --lint --only core/doctor/push-key-policy --json
```

Angle-bracket values are placeholders. Validity bounds are nonnegative safe integers in Unix milliseconds, with activation before expiry. The interval is `validFromMs <= nowMs < validUntilMs`; the exact expiry instant is invalid. Initial status reports `uninitialized`, `ready: false`, and exit `1`. Run commands individually; that initial failure is expected. Only a currently usable dual-key pair produces `ready: true` and status exit `0`.

`setup --baseline` creates baseline configuration, workspace and session folders; it does not configure inference or push delivery. After provisioning, use `node openclaw.mjs --profile pqc-first-install setup --wizard` for this same isolated instance. The default-profile launcher scripts below do not select that named instance.

**Existing identity:** use enrollment, not `init`. Preserve and back up the existing state database, wrapping material and dedicated Ed25519 push key; verify the original identity before enrolling the existing profile:

```bash
node openclaw.mjs --profile <existing-profile> security push-key enroll --valid-from-ms <activation-ms> --valid-until-ms <expiry-ms>
node openclaw.mjs --profile <existing-profile> security push-key status --json
node openclaw.mjs --profile <existing-profile> doctor --lint --only core/doctor/push-key-policy --json
```

Enrollment preserves both signing identities. It cannot change an enrolled lifetime or reactivate a revoked key. Missing or partial material requires recovery, not replacement identities. Installation/verification scripts and this Doctor check do not silently enroll trust policies; status and this Doctor check do not generate signing keys. A clean named Doctor result establishes local key-policy readiness, not provider delivery.

**Recovery boundary:** a profile's registered policy set anchors its original dual-key identity. Initial enrollment requires an empty set; an existing set must contain exactly the two records matching the current sender, algorithms, key IDs and public keys. Partial, extra or mismatched records reject enrollment and renewal. If both keys are lost but policies remain, status is `incomplete` and `init` refuses before generating keys. Do not overwrite/remove key files, delete policies or rerun `init` to bypass revocation or stale trust. Restore the matching original identity material. Replacing an identity requires a separately reviewed rotation workflow; these commands do not implement rotation.

**Renewal:** schedule maintenance before expiry where possible. Enrollment does not renew a policy. Read the original validity start from `status --json`, then explicitly run:

```bash
node openclaw.mjs --profile <existing-profile> security push-key renew --valid-from-ms <original-activation-ms> --valid-until-ms <extended-expiry-ms> --json
node openclaw.mjs --profile <existing-profile> doctor --lint --only core/doctor/push-key-policy --json
```

Renewal preserves both identities and public keys. The supplied start must exactly match both enrolled records; the new expiry must exceed each existing expiry and the execution time. Both updates commit atomically, each with its revision incremented by one. Any missing, revoked or mismatched member rejects the pair. Expired but unrevoked keys can be explicitly renewed to restore service; expired policies block sending until renewal completes. Renewal is never automatic and cannot reactivate revoked keys or substitute identities. Source implementation alone is not completed installed-build acceptance.

For intentional revocation, select the same profile and run `node openclaw.mjs --profile <existing-profile> security push-key revoke --sender-id <sender-id> --algorithm ed25519 --key-id <key-id>`. The other algorithm is `ml-dsa-65`. Revoking either member prevents that dual-signature pair from sending; do not revoke a working key merely to test installation.

See [production acceptance and key lifecycle](docs/security/pqc-production-v2.md) for the full boundaries.

## Run and verify

On Windows:

```text
start.bat
verify.bat
stop.bat
```

On macOS or Linux:

```bash
./start.sh
./verify.sh
./stop.sh
```

After installing the daemon, use `node openclaw.mjs gateway status` first. The start script runs the Gateway in the foreground when no service is running; press `Ctrl+C` to stop it. The verify script checks the build, CLI, device-proof algorithms, and production wiring contract.

## Troubleshooting

- **Node is missing:** install Node 24 LTS, then reopen the terminal.
- **The pinned pnpm cannot start:** verify that `npm --version` works and that npm can reach its registry. The installer obtains the correct pnpm version automatically.
- **Dependency download fails:** check access to the npm registry and rerun the installer.
- **A required file is missing:** download the repository ZIP again or request the complete project directory.
- **The port is busy:** run the stop script or inspect the current service with `node openclaw.mjs gateway status`.

For implementation scope and design, read the [PQC whitepaper](docs/security/pqc-whitepaper.md). Chinese instructions are available in [INSTALL.zh-CN.md](INSTALL.zh-CN.md).
