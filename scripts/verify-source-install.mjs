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

const vitestEntry = path.join(repoRoot, "node_modules", "vitest", "vitest.mjs");
if (!existsSync(vitestEntry)) {
  throw new Error("Runtime verification dependency is missing. Re-run the repository installer.");
}
const contract = spawnSync(
  process.execPath,
  [vitestEntry, "run", "src/infra/pqc-production-contract.test.ts"],
  { cwd: repoRoot, encoding: "utf8", timeout: 120_000, windowsHide: true },
);
if (contract.error) {
  throw contract.error;
}
if (contract.status !== 0) {
  throw new Error(`PQC production contract failed:\n${contract.stderr || contract.stdout}`);
}
process.stdout.write(
  "OpenClaw PQC installation verified: build, CLI, device-proof algorithms, and production wiring are ready.\n",
);
