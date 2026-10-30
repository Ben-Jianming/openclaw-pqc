#!/usr/bin/env node

import { execFileSync } from "node:child_process";
// Guards pnpm package patches against unapproved additions.
import { createHash } from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import YAML from "yaml";

const ALLOWED_PATCHED_DEPENDENCIES = new Map([
  ["baileys@7.0.0-rc12", "patches/baileys@7.0.0-rc12.patch"],
  ["baileys@7.0.0-rc13", "patches/baileys@7.0.0-rc13.patch"],
]);

const PINNED_PATCHES = new Map([
  [
    "@discord/embedded-app-sdk@2.5.0",
    {
      path: "patches/@discord__embedded-app-sdk@2.5.0.patch",
      sha256: "7eee7156035b90c5058a80c2870ba303d12288299403c2ee1c021dd04c4aaf6f",
    },
  ],
  [
    "@a2ui/web_core@0.10.5",
    {
      path: "patches/@a2ui__web_core@0.10.5.patch",
      sha256: "d007224317121fda6be15bab86fdf80f168bad216173beda65c226b3cffbfce6",
    },
  ],
]);
for (const [specifier, pin] of PINNED_PATCHES) {
  ALLOWED_PATCHED_DEPENDENCIES.set(specifier, pin.path);
}

const ALLOWED_PATCH_FILES = new Set(["patches/.gitkeep", ...ALLOWED_PATCHED_DEPENDENCIES.values()]);

function listTrackedFiles(cwd, patterns) {
  return execFileSync("git", ["ls-files", "-z", "--", ...patterns], {
    cwd,
    encoding: "utf8",
  })
    .split("\0")
    .filter(Boolean)
    .toSorted((left, right) => left.localeCompare(right));
}

function readYamlFile(cwd, relativePath) {
  const filePath = path.join(cwd, relativePath);
  if (!fs.existsSync(filePath)) {
    return {};
  }
  return YAML.parse(fs.readFileSync(filePath, "utf8")) ?? {};
}

function readJsonFile(cwd, relativePath) {
  const filePath = path.join(cwd, relativePath);
  if (!fs.existsSync(filePath)) {
    return undefined;
  }
  return JSON.parse(fs.readFileSync(filePath, "utf8"));
}

function collectPatchedDependencyViolations(file, patchedDependencies, violations, options = {}) {
  for (const [specifier, patchPathOrHash] of Object.entries(patchedDependencies ?? {})) {
    if (
      options.allowAnyValueForLegacy === true
        ? PINNED_PATCHES.has(specifier)
          ? PINNED_PATCHES.get(specifier).sha256 === patchPathOrHash
          : ALLOWED_PATCHED_DEPENDENCIES.has(specifier)
        : ALLOWED_PATCHED_DEPENDENCIES.get(specifier) === patchPathOrHash
    ) {
      continue;
    }
    violations.push({
      file,
      kind: "patchedDependency",
      detail: `${specifier} -> ${String(patchPathOrHash)}`,
    });
  }
}

function collectWorkspacePatchViolations(cwd, violations) {
  const workspace = readYamlFile(cwd, "pnpm-workspace.yaml");
  collectPatchedDependencyViolations(
    "pnpm-workspace.yaml",
    workspace?.patchedDependencies,
    violations,
  );
}

function collectLockfilePatchViolations(cwd, violations) {
  const lockfile = readYamlFile(cwd, "pnpm-lock.yaml");
  collectPatchedDependencyViolations("pnpm-lock.yaml", lockfile?.patchedDependencies, violations, {
    allowAnyValueForLegacy: true,
  });
}

function collectPackageJsonPatchViolations(cwd, violations) {
  for (const relativePath of listTrackedFiles(cwd, ["*package.json"])) {
    const packageJson = readJsonFile(cwd, relativePath);
    const patchedDependencies = packageJson?.pnpm?.patchedDependencies;
    for (const [specifier, patchPath] of Object.entries(patchedDependencies ?? {})) {
      violations.push({
        file: relativePath,
        kind: "packageJsonPatchedDependency",
        detail: `${specifier} -> ${String(patchPath)}`,
      });
    }
  }
}

function collectPatchFileViolations(cwd, violations) {
  for (const relativePath of listTrackedFiles(cwd, ["*.patch"])) {
    if (!fs.existsSync(path.join(cwd, relativePath))) {
      continue;
    }
    if (ALLOWED_PATCH_FILES.has(relativePath)) {
      continue;
    }
    violations.push({
      file: relativePath,
      kind: "patchFile",
      detail: "new package patch file",
    });
  }
}

function collectPinnedPatchContentViolations(cwd, violations) {
  const workspace = readYamlFile(cwd, "pnpm-workspace.yaml");
  const lockfile = readYamlFile(cwd, "pnpm-lock.yaml");
  for (const [specifier, pin] of PINNED_PATCHES) {
    if (workspace.patchedDependencies?.[specifier] !== pin.path) {
      violations.push({
        file: "pnpm-workspace.yaml",
        kind: "requiredPatch",
        detail: `${specifier} requires ${pin.path}`,
      });
    }
    if (lockfile.patchedDependencies?.[specifier] !== pin.sha256) {
      violations.push({
        file: "pnpm-lock.yaml",
        kind: "requiredPatch",
        detail: `${specifier} requires ${pin.sha256}`,
      });
    }
    const file = path.join(cwd, pin.path);
    if (!fs.existsSync(file)) {
      violations.push({ file: pin.path, kind: "patchHash", detail: "approved patch file missing" });
      continue;
    }
    const digest = createHash("sha256").update(fs.readFileSync(file)).digest("hex");
    if (digest !== pin.sha256) {
      violations.push({
        file: pin.path,
        kind: "patchHash",
        detail: "approved patch bytes changed",
      });
    }
  }
}

/**
 * Collects disallowed package patch declarations and patch files.
 */
export function collectPackagePatchViolations(cwd = process.cwd()) {
  const violations = [];
  collectWorkspacePatchViolations(cwd, violations);
  collectLockfilePatchViolations(cwd, violations);
  collectPackageJsonPatchViolations(cwd, violations);
  collectPinnedPatchContentViolations(cwd, violations);
  collectPatchFileViolations(cwd, violations);
  return violations;
}

/**
 * Runs the package patch guard.
 */
export async function main() {
  const violations = collectPackagePatchViolations();
  if (violations.length === 0) {
    process.stdout.write(
      `PASS package patch guard: only approved pnpm patches; ${ALLOWED_PATCHED_DEPENDENCIES.size} approved patches allowlisted.\n`,
    );
    return;
  }

  console.error(
    "FAIL package patch guard: new pnpm package patches are not allowed. Upstream the fix, publish a new package version, then bump the dependency instead.",
  );
  for (const violation of violations) {
    console.error(`- ${violation.file}: ${violation.kind}: ${violation.detail}`);
  }
  process.exitCode = 1;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  main().catch(
    /** @param {unknown} error */ (error) => {
      console.error(error);
      process.exit(1);
    },
  );
}
