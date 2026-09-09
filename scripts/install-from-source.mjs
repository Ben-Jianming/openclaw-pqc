#!/usr/bin/env node
import { spawnSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const checkOnly = process.argv.includes("--check");
const toolEnv = {
  ...process.env,
  COREPACK_HOME: process.env.COREPACK_HOME || path.join(repoRoot, ".corepack"),
};

function parseVersion(value) {
  const match = /^(\d+)\.(\d+)\.(\d+)/u.exec(value);
  return match ? match.slice(1).map(Number) : null;
}

function atLeast(version, minimum) {
  for (let index = 0; index < 3; index += 1) {
    if (version[index] !== minimum[index]) {
      return version[index] > minimum[index];
    }
  }
  return true;
}

function nodeVersionIsSupported(version) {
  const [major] = version;
  if (major === 22) {
    return atLeast(version, [22, 22, 3]);
  }
  if (major === 24) {
    return atLeast(version, [24, 16, 0]);
  }
  if (major === 25) {
    return atLeast(version, [25, 9, 0]);
  }
  return major > 25;
}

function commandResult(command, args) {
  return spawnPortable(command, args, {
    cwd: repoRoot,
    encoding: "utf8",
    env: toolEnv,
    windowsHide: true,
  });
}

function spawnPortable(command, args, options) {
  if (process.platform !== "win32" || !command.endsWith(".cmd")) {
    return spawnSync(command, args, options);
  }
  const commandLine = [command, ...args].join(" ");
  return spawnSync(process.env.ComSpec || "cmd.exe", ["/d", "/s", "/c", commandLine], options);
}

function resolvePnpm(packageManager) {
  const suffix = process.platform === "win32" ? ".cmd" : "";
  const pinnedVersion = /^pnpm@([^+]+)/u.exec(packageManager ?? "")?.[1];
  const candidates = [
    { command: `corepack${suffix}`, prefix: ["pnpm"] },
    { command: `pnpm${suffix}`, prefix: [] },
  ];
  if (pinnedVersion) {
    candidates.push({
      command: `npm${suffix}`,
      prefix: ["exec", "--yes", "--package", `pnpm@${pinnedVersion}`, "--", "pnpm"],
    });
  }
  for (const candidate of candidates) {
    const probe = commandResult(candidate.command, [...candidate.prefix, "--version"]);
    if (!probe.error && probe.status === 0) {
      return candidate;
    }
  }
  throw new Error(
    "Unable to start the repository's pinned pnpm version. Check npm access, then rerun this installer.",
  );
}

function run(command, args, label) {
  process.stdout.write(`\n==> ${label}\n`);
  const result = spawnPortable(command, args, {
    cwd: repoRoot,
    env: toolEnv,
    stdio: "inherit",
    windowsHide: true,
  });
  if (result.error) {
    throw result.error;
  }
  if (result.status !== 0) {
    throw new Error(`${label} failed with exit code ${result.status}`);
  }
}

for (const required of ["package.json", "pnpm-lock.yaml", "openclaw.mjs"]) {
  if (!existsSync(path.join(repoRoot, required))) {
    throw new Error(`Incomplete source package: missing ${required}`);
  }
}

const packageJson = JSON.parse(readFileSync(path.join(repoRoot, "package.json"), "utf8"));
if (packageJson.repository?.url !== "git+https://github.com/Ben-Jianming/openclaw-pqc.git") {
  throw new Error("This package does not identify itself as the OpenClaw PQC repository");
}

const nodeVersion = parseVersion(process.versions.node);
if (!nodeVersion || !nodeVersionIsSupported(nodeVersion)) {
  throw new Error(
    `Unsupported Node ${process.versions.node}. Use Node 24.16.0 or newer (Node 22 requires 22.22.3+).`,
  );
}

const pnpm = resolvePnpm(packageJson.packageManager);
process.stdout.write(
  `OpenClaw PQC source package is complete. Node ${process.versions.node} is supported.\n`,
);
if (checkOnly) {
  process.exit(0);
}

run(pnpm.command, [...pnpm.prefix, "install", "--frozen-lockfile"], "Install dependencies");
run(pnpm.command, [...pnpm.prefix, "build"], "Build OpenClaw PQC");
run(
  process.execPath,
  [path.join(repoRoot, "scripts", "verify-source-install.mjs")],
  "Verify installation",
);

process.stdout.write(
  "\nInstallation complete. Run onboarding next:\n" +
    "  node openclaw.mjs onboard --install-daemon\n\n" +
    "Then start with start.bat (Windows) or ./start.sh (macOS/Linux).\n",
);
