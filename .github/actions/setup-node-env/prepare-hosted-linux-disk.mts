import { spawnSync } from "node:child_process";
import { existsSync } from "node:fs";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

type DiskPreparationOptions = {
  env?: NodeJS.ProcessEnv;
  platform?: string;
  isContainer?: boolean;
  run?: (
    command: string,
    args: string[],
    options: { stdio: "inherit" },
  ) => { status: number | null; error?: Error };
};

export function prepareHostedLinuxDisk({
  env = process.env,
  platform = process.platform,
  isContainer = existsSync("/.dockerenv"),
  run = spawnSync,
}: DiskPreparationOptions = {}): boolean {
  // Never reclaim software on operator-owned machines or inside job containers.
  if (
    env.RUNNER_ENVIRONMENT !== "github-hosted" ||
    env.RUNNER_OS !== "Linux" ||
    platform !== "linux" ||
    isContainer
  ) {
    return false;
  }

  function checked(command: string, args: string[]) {
    const result = run(command, args, { stdio: "inherit" });
    if (result.error || result.status !== 0) {
      throw new Error(`Hosted runner disk preparation failed: ${command}`, {
        cause: result.error ?? new Error(`exit status ${result.status}`),
      });
    }
  }

  checked("df", ["-h", "/"]);
  // The Node workspace does not use .NET or Haskell. These are fixed image
  // toolchains, never workspace/cache paths; keep Android, Java, Go and Docker.
  checked("sudo", ["-n", "rm", "-rf", "--", "/usr/share/dotnet", "/usr/local/.ghcup", "/opt/ghc"]);
  checked("df", ["-h", "/"]);
  return true;
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  prepareHostedLinuxDisk();
}
