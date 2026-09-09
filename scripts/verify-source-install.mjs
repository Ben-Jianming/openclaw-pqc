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
process.stdout.write(
  "OpenClaw PQC installation verified: PQC sources, build output, and CLI are ready.\n",
);
