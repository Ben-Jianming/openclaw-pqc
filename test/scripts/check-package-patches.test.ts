// Check Package Patches tests cover check package patches script behavior.
import { execFileSync } from "node:child_process";
import { mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { collectPackagePatchViolations } from "../../scripts/check-package-patches.mjs";
import { cleanupTempDirs, makeTempRepoRoot, writeJsonFile } from "../helpers/temp-repo.js";

const tempDirs: string[] = [];

const nestedGitEnvKeys = [
  "GIT_ALTERNATE_OBJECT_DIRECTORIES",
  "GIT_DIR",
  "GIT_INDEX_FILE",
  "GIT_OBJECT_DIRECTORY",
  "GIT_QUARANTINE_PATH",
  "GIT_WORK_TREE",
] as const;

function createNestedGitEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_TERMINAL_PROMPT: "0",
  };
  for (const key of nestedGitEnvKeys) {
    delete env[key];
  }
  return env;
}

function git(cwd: string, args: string[]) {
  execFileSync("git", args, {
    cwd,
    encoding: "utf8",
    env: createNestedGitEnv(),
  });
}

function makeRepo() {
  const dir = makeTempRepoRoot(tempDirs, "openclaw-package-patches-");
  git(dir, ["init", "-q", "--initial-branch=main"]);
  writeJsonFile(path.join(dir, "package.json"), { name: "fixture" });
  writeFileSync(path.join(dir, "pnpm-workspace.yaml"), "packages:\n  - .\n", "utf8");
  writeFileSync(path.join(dir, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n", "utf8");
  git(dir, ["add", "package.json", "pnpm-workspace.yaml", "pnpm-lock.yaml"]);
  return dir;
}

afterEach(() => {
  cleanupTempDirs(tempDirs);
});

const SECURITY_PATCHES = [
  [
    "@discord/embedded-app-sdk@2.5.0",
    "@discord__embedded-app-sdk@2.5.0.patch",
    "7eee7156035b90c5058a80c2870ba303d12288299403c2ee1c021dd04c4aaf6f",
  ],
  [
    "@a2ui/web_core@0.10.5",
    "@a2ui__web_core@0.10.5.patch",
    "d007224317121fda6be15bab86fdf80f168bad216173beda65c226b3cffbfce6",
  ],
] as const;

function addMandatorySecurityPins(dir: string) {
  mkdirSync(path.join(dir, "patches"), { recursive: true });
  for (const [name, isLock] of [
    ["pnpm-workspace.yaml", false],
    ["pnpm-lock.yaml", true],
  ] as const) {
    const file = path.join(dir, name);
    let text = readFileSync(file, "utf8");
    const entries = SECURITY_PATCHES.map(
      ([specifier, patch, hash]) => `  "${specifier}": ${isLock ? hash : `patches/${patch}`}\n`,
    ).join("");
    text = text.includes("patchedDependencies:\n")
      ? text.replace("patchedDependencies:\n", `patchedDependencies:\n${entries}`)
      : `${text}\npatchedDependencies:\n${entries}`;
    writeFileSync(file, text);
  }
  for (const [, patch] of SECURITY_PATCHES) {
    writeFileSync(
      path.join(dir, "patches", patch),
      readFileSync(new URL(`../../patches/${patch}`, import.meta.url)),
    );
  }
  git(dir, ["add", "pnpm-workspace.yaml", "pnpm-lock.yaml", "patches"]);
}

describe("check-package-patches", () => {
  it("allows approved pnpm patches", () => {
    const dir = makeRepo();
    mkdirSync(path.join(dir, "patches"), { recursive: true });
    writeFileSync(
      path.join(dir, "pnpm-workspace.yaml"),
      `packages:
  - .
patchedDependencies:
  "baileys@7.0.0-rc12": "patches/baileys@7.0.0-rc12.patch"
`,
      "utf8",
    );
    writeFileSync(
      path.join(dir, "pnpm-lock.yaml"),
      `lockfileVersion: '9.0'
patchedDependencies:
  baileys@7.0.0-rc12: a9aea1790d2c65b1ae543c77faca4119bbfb91ee3b6ca6c38d1cad4f5702ada2
`,
      "utf8",
    );
    writeFileSync(path.join(dir, "patches", "baileys@7.0.0-rc12.patch"), "diff\n", "utf8");
    git(dir, ["add", "pnpm-workspace.yaml", "pnpm-lock.yaml", "patches"]);

    addMandatorySecurityPins(dir);
    expect(collectPackagePatchViolations(dir)).toEqual([]);
  });

  it("rejects new workspace patchedDependencies and patch files", () => {
    const dir = makeRepo();
    mkdirSync(path.join(dir, "patches"), { recursive: true });
    mkdirSync(path.join(dir, "fixtures"), { recursive: true });
    writeFileSync(
      path.join(dir, "pnpm-workspace.yaml"),
      `packages:
  - .
patchedDependencies:
  "left-pad@1.3.0": "patches/left-pad@1.3.0.patch"
`,
      "utf8",
    );
    writeFileSync(path.join(dir, "patches", "left-pad@1.3.0.patch"), "diff\n", "utf8");
    writeFileSync(path.join(dir, "fixtures", "fixture.patch"), "diff\n", "utf8");
    git(dir, ["add", "pnpm-workspace.yaml", "patches", "fixtures"]);

    addMandatorySecurityPins(dir);
    expect(collectPackagePatchViolations(dir)).toEqual([
      {
        file: "pnpm-workspace.yaml",
        kind: "patchedDependency",
        detail: "left-pad@1.3.0 -> patches/left-pad@1.3.0.patch",
      },
      {
        file: "fixtures/fixture.patch",
        kind: "patchFile",
        detail: "new package patch file",
      },
      {
        file: "patches/left-pad@1.3.0.patch",
        kind: "patchFile",
        detail: "new package patch file",
      },
    ]);
  });

  it("allows deleted legacy patch files during the commit that removes them", () => {
    const dir = makeRepo();
    mkdirSync(path.join(dir, "patches"), { recursive: true });
    writeFileSync(
      path.join(dir, "patches", "@agentclientprotocol__claude-agent-acp@0.33.1.patch"),
      "diff\n",
      "utf8",
    );
    git(dir, ["add", "patches"]);
    rmSync(path.join(dir, "patches", "@agentclientprotocol__claude-agent-acp@0.33.1.patch"));

    addMandatorySecurityPins(dir);
    expect(collectPackagePatchViolations(dir)).toEqual([]);
  });

  it("rejects lockfile-only and package-local patch declarations", () => {
    const dir = makeRepo();
    writeJsonFile(path.join(dir, "package.json"), {
      name: "fixture",
      pnpm: {
        patchedDependencies: {
          "nested@1.0.0": "patches/nested.patch",
        },
      },
    });
    writeFileSync(
      path.join(dir, "pnpm-lock.yaml"),
      `lockfileVersion: '9.0'
patchedDependencies:
  hidden@1.0.0: abc123
`,
      "utf8",
    );
    git(dir, ["add", "package.json", "pnpm-lock.yaml"]);

    addMandatorySecurityPins(dir);
    expect(collectPackagePatchViolations(dir)).toEqual([
      {
        file: "pnpm-lock.yaml",
        kind: "patchedDependency",
        detail: "hidden@1.0.0 -> abc123",
      },
      {
        file: "package.json",
        kind: "packageJsonPatchedDependency",
        detail: "nested@1.0.0 -> patches/nested.patch",
      },
    ]);
  });

  it("skips tracked package manifests deleted in the worktree", () => {
    const dir = makeRepo();
    mkdirSync(path.join(dir, "packages", "deleted"), { recursive: true });
    writeJsonFile(path.join(dir, "packages", "deleted", "package.json"), {
      name: "deleted",
      pnpm: {
        patchedDependencies: {
          "deleted-only@1.0.0": "patches/deleted-only.patch",
        },
      },
    });
    git(dir, ["add", "packages/deleted/package.json"]);
    rmSync(path.join(dir, "packages", "deleted", "package.json"));

    addMandatorySecurityPins(dir);
    expect(collectPackagePatchViolations(dir)).toEqual([]);
  });
});

describe("pinned security migration patches", () => {
  const pins = SECURITY_PATCHES;
  function pinnedRepo() {
    const dir = makeRepo();
    mkdirSync(path.join(dir, "patches"));
    let workspace = "packages:\n  - .\npatchedDependencies:\n";
    let lock = "lockfileVersion: '9.0'\npatchedDependencies:\n";
    for (const [specifier, file, hash] of pins) {
      workspace += `  "${specifier}": patches/${file}\n`;
      lock += `  "${specifier}": ${hash}\n`;
      writeFileSync(
        path.join(dir, "patches", file),
        readFileSync(new URL(`../../patches/${file}`, import.meta.url)),
      );
    }
    writeFileSync(path.join(dir, "pnpm-workspace.yaml"), workspace);
    writeFileSync(path.join(dir, "pnpm-lock.yaml"), lock);
    git(dir, ["add", "--all"]);
    return dir;
  }
  it("accepts the approved bytes and lock hashes", () => {
    expect(collectPackagePatchViolations(pinnedRepo())).toEqual([]);
  });
  it.each(pins)("rejects changed patch bytes for %s", (_specifier, file) => {
    const dir = pinnedRepo();
    writeFileSync(path.join(dir, "patches", file), "modified patch\n");
    expect(collectPackagePatchViolations(dir)).toContainEqual({
      file: `patches/${file}`,
      kind: "patchHash",
      detail: "approved patch bytes changed",
    });
  });
  it("rejects an altered lock hash", () => {
    const dir = pinnedRepo();
    const file = path.join(dir, "pnpm-lock.yaml");
    writeFileSync(file, readFileSync(file, "utf8").replace(pins[0][2], "0".repeat(64)));
    expect(collectPackagePatchViolations(dir)).toContainEqual(
      expect.objectContaining({ file: "pnpm-lock.yaml" }),
    );
  });
  it("rejects a declared patch whose file was removed", () => {
    const dir = pinnedRepo();
    rmSync(path.join(dir, "patches", pins[0][1]));
    expect(collectPackagePatchViolations(dir)).toContainEqual({
      file: `patches/${pins[0][1]}`,
      kind: "patchHash",
      detail: "approved patch file missing",
    });
  });
  it.each(["pnpm-workspace.yaml", "pnpm-lock.yaml"])(
    "rejects removed declaration in %s",
    (name) => {
      const dir = pinnedRepo();
      writeFileSync(
        path.join(dir, name),
        name === "pnpm-lock.yaml" ? "lockfileVersion: '9.0'\n" : "packages:\n  - .\n",
      );
      expect(collectPackagePatchViolations(dir)).toContainEqual(
        expect.objectContaining({ file: name, kind: "requiredPatch" }),
      );
    },
  );
  it("rejects complete removal of both pinned declarations and untracked patch files", () => {
    const dir = pinnedRepo();
    writeFileSync(path.join(dir, "pnpm-workspace.yaml"), "packages:\n  - .\n");
    writeFileSync(path.join(dir, "pnpm-lock.yaml"), "lockfileVersion: '9.0'\n");
    for (const [, file] of pins) {
      git(dir, ["rm", "--cached", `patches/${file}`]);
      rmSync(path.join(dir, "patches", file));
    }
    const violations = collectPackagePatchViolations(dir);
    expect(
      violations.filter(
        (v) => typeof v === "object" && v !== null && "kind" in v && v.kind === "requiredPatch",
      ),
    ).toHaveLength(4);
    expect(violations).toContainEqual(
      expect.objectContaining({ kind: "patchHash", detail: "approved patch file missing" }),
    );
  });
});
