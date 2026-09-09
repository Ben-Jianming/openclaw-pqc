// Vitest cli config wires the cli test shard.
import { createScopedVitestConfig } from "./vitest.scoped-config.ts";

export function createCliVitestConfig(env?: Record<string, string | undefined>) {
  const config = createScopedVitestConfig(["src/cli/**/*.test.ts"], {
    dir: "src/cli",
    env,
    name: "cli",
    passWithNoTests: true,
  });
  return {
    ...config,
    test: {
      ...config.test,
      env: {
        ...config.test?.env,
        // Avoid TSX's unbounded wait on esbuild's synchronous worker IPC in source-child tests.
        ESBUILD_WORKER_THREADS: "0",
      },
    },
  };
}

export default createCliVitestConfig();
