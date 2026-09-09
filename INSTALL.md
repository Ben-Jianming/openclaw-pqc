# Install OpenClaw PQC

This repository is the post-quantum cryptography fork of OpenClaw. Its installer uses this source tree, the committed lockfile, and the pinned pnpm version. It then builds and verifies the CLI and PQC sources.

> Do not use `npm install -g openclaw@latest` for this fork. That command installs upstream OpenClaw without this repository's PQC changes.

## Requirements

- 64-bit Windows 10/11, macOS, or a common Linux distribution
- Node.js 24.16.0 or newer (Node 24 LTS recommended)
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

The installation can be run again safely after an update.

## First-time setup

Run the guided setup from the project directory:

```bash
node openclaw.mjs onboard --install-daemon
```

Provide API keys only through the setup wizard, secure storage, or environment variables. Never save keys in launcher scripts or commit them to GitHub.

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

After installing the daemon, use `node openclaw.mjs gateway status` first. The start script runs the Gateway in the foreground when no service is running; press `Ctrl+C` to stop it. The verify script checks the PQC sources, build output, CLI version, and CLI help.

## Troubleshooting

- **Node is missing:** install Node 24 LTS, then reopen the terminal.
- **Dependency download fails:** check access to the npm registry and rerun the installer.
- **A required file is missing:** download the repository ZIP again or request the complete project directory.
- **The port is busy:** run the stop script or inspect the current service with `node openclaw.mjs gateway status`.

For implementation scope and design, read the [PQC whitepaper](docs/security/pqc-whitepaper.md). Chinese instructions are available in [INSTALL.zh-CN.md](INSTALL.zh-CN.md).
