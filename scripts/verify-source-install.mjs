#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const requiredSources = [
  "src/infra/mldsa65-key-storage.ts",
  "src/logging/pqc-log.ts",
  "src/security/secret-wrapping.ts",
  "src/cli/wrap-key-cli.ts",
  "src/infra/device-identity-wrap-operations.ts",
  "docs/security/pqc-whitepaper.md",
  "docs/.generated/plugin-sdk-api-baseline.sha256",
];

for (const source of requiredSources) {
  if (!existsSync(path.join(repoRoot, source))) {
    throw new Error(`Missing PQC source: ${source}`);
  }
}

if (
  !existsSync(path.join(repoRoot, "dist", "entry.js")) &&
  !existsSync(path.join(repoRoot, "dist", "entry.mjs"))
) {
  throw new Error("Build output is missing. Run install.bat, install.ps1, or ./install.sh first.");
}

function verifyCli(argument) {
  const result = spawnSync(process.execPath, [path.join(repoRoot, "openclaw.mjs"), argument], {
    cwd: repoRoot,
    encoding: "utf8",
    timeout: 30_000,
    windowsHide: true,
  });
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    throw new Error(`openclaw ${argument} failed: ${result.stderr || result.stdout}`);
  }
}

verifyCli("--version");
verifyCli("--help");

const contract = spawnSync(
  process.execPath,
  [path.join(repoRoot, "scripts/verify-installed-pqc.mjs")],
  { cwd: repoRoot, encoding: "utf8", timeout: 240_000, windowsHide: true },
);
if (contract.error) {
  throw contract.error;
}
if (contract.status !== 0) {
  throw new Error(`Installed PQC behavior failed:\n${contract.stderr || contract.stdout}`);
}
process.stdout.write(
  "OpenClaw PQC local installation checks passed: built CLI, encrypted identity, strict push verification and key recovery. Native devices and live delivery still require separate acceptance.\n",
);
