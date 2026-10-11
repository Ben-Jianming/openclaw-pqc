// Vitest UI package config tests validate UI package test project settings.
import path from "node:path";
import fg from "fast-glob";
import { describe, expect, it } from "vitest";
import uiConfig from "../ui/vitest.config.ts";
import uiNodeConfig from "../ui/vitest.node.config.ts";
import { createUiVitestConfig } from "./vitest/vitest.ui.config.ts";

type ExpectedTestConfig = {
  isolate?: boolean;
  name?: string;
  pool?: string;
  projects?: unknown[];
  runner?: string;
  include?: string[];
  exclude?: string[];
  browser?: { enabled?: boolean };
};

function requireTestConfig(config: unknown): ExpectedTestConfig {
  if (!config || typeof config !== "object" || !("test" in config) || !config.test) {
    throw new Error("expected ui package vitest test config");
  }
  return config.test as ExpectedTestConfig;
}

describe("ui package vitest config", () => {
  it("runs PQC IndexedDB/WebCrypto acceptance only in the real Chromium project", () => {
    const file = "src/app/pqc-push.browser.test.ts";
    const projects = (requireTestConfig(uiConfig).projects ?? []).map(requireTestConfig);
    const matches = projects.filter((project) =>
      fg
        .sync(project.include ?? [], {
          cwd: path.resolve("ui"),
          ignore: project.exclude ?? [],
        })
        .includes(file),
    );
    expect(matches).toHaveLength(1);
    expect(matches[0]?.browser?.enabled).toBe(true);
    const rootUiConfig = requireTestConfig(createUiVitestConfig());
    expect(
      fg.sync(rootUiConfig.include ?? [], {
        cwd: process.cwd(),
        ignore: rootUiConfig.exclude ?? [],
      }),
    ).not.toContain(`ui/${file}`);
  });

  it("keeps the standalone ui package on thread workers without broad isolation", () => {
    const testConfig = requireTestConfig(uiConfig);

    expect(testConfig.pool).toBe("threads");
    expect(testConfig.isolate).toBe(false);
    expect(testConfig.projects).toHaveLength(4);

    for (const project of testConfig.projects ?? []) {
      const projectTestConfig = requireTestConfig(project);
      expect(projectTestConfig.pool).toBe("threads");
      expect(projectTestConfig.isolate).toBe(projectTestConfig.name === "unit-mock-registry");
      expect(projectTestConfig.runner).toBeUndefined();
    }
  });

  it("keeps the standalone ui node config on thread workers without isolation", () => {
    const testConfig = requireTestConfig(uiNodeConfig);

    expect(testConfig.pool).toBe("threads");
    expect(testConfig.isolate).toBe(false);
    expect(testConfig.runner).toBeUndefined();
  });
});
