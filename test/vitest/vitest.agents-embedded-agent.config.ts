// Vitest agents embedded agent config wires the agents embedded agent test shard.
import { defineConfig } from "vitest/config";
import { agentsEmbeddedTestPatterns } from "./vitest.agents-paths.mjs";
import { createScopedVitestConfig } from "./vitest.scoped-config.ts";

export function createAgentsEmbeddedVitestConfig(env?: Record<string, string | undefined>) {
  const config = createScopedVitestConfig(agentsEmbeddedTestPatterns, {
    dir: "src/agents",
    env,
    fileParallelism: false,
    name: "agents-embedded-agent",
  });
  return defineConfig({
    ...config,
    test: {
      ...config.test,
      // Long runtime suites need per-test progress for the no-output watchdog.
      reporters: ["verbose"],
    },
  });
}

export default createAgentsEmbeddedVitestConfig();
