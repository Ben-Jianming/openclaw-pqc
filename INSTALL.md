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
