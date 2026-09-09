import { spawnSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

describe("OpenClaw PQC source package", () => {
  it("passes the distributable source preflight", () => {
    const result = spawnSync(process.execPath, ["scripts/install-from-source.mjs", "--check"], {
      cwd: process.cwd(),
      encoding: "utf8",
      timeout: 30_000,
      windowsHide: true,
    });
    expect(result.status, result.stderr).toBe(0);
    expect(result.stdout).toContain("OpenClaw PQC source package is complete");
  });

  it("documents the fork download and does not embed API keys in launchers", () => {
    const read = (file: string) => readFileSync(file, "utf8");
    expect(read("README.md")).toContain("Ben-Jianming/openclaw-pqc");
    expect(read("INSTALL.md")).toContain("Code → Download ZIP");
    expect(read("INSTALL.zh-CN.md")).toContain("Code → Download ZIP");
    for (const launcher of ["install.bat", "install.ps1", "install.sh", "start.bat", "start.sh"]) {
      expect(read(launcher)).not.toMatch(/sk-api-[A-Za-z0-9_-]+/u);
    }
  });
});
