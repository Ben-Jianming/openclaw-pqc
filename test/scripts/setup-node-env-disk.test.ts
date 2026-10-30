import { describe, expect, it, vi } from "vitest";
import { prepareHostedLinuxDisk } from "../../.github/actions/setup-node-env/prepare-hosted-linux-disk.mjs";

const hostedEnv = { RUNNER_ENVIRONMENT: "github-hosted", RUNNER_OS: "Linux" };

describe("hosted Node dependency disk preparation", () => {
  it.each([
    { env: {}, platform: "linux", isContainer: false },
    {
      env: { ...hostedEnv, RUNNER_ENVIRONMENT: "self-hosted" },
      platform: "linux",
      isContainer: false,
    },
    { env: { ...hostedEnv, RUNNER_OS: "Windows" }, platform: "linux", isContainer: false },
    { env: hostedEnv, platform: "darwin", isContainer: false },
    { env: hostedEnv, platform: "win32", isContainer: false },
    { env: hostedEnv, platform: "linux", isContainer: true },
  ])("does not modify ineligible runners: %j", (options) => {
    const run = vi.fn();
    expect(prepareHostedLinuxDisk({ ...options, run })).toBe(false);
    expect(run).not.toHaveBeenCalled();
  });

  it("reclaims only fixed unused image toolchains and records before/after space", () => {
    const run = vi.fn(() => ({ status: 0 }));
    expect(
      prepareHostedLinuxDisk({ env: hostedEnv, platform: "linux", isContainer: false, run }),
    ).toBe(true);
    expect(run.mock.calls).toEqual([
      ["df", ["-h", "/"], { stdio: "inherit" }],
      [
        "sudo",
        ["-n", "rm", "-rf", "--", "/usr/share/dotnet", "/usr/local/.ghcup", "/opt/ghc"],
        { stdio: "inherit" },
      ],
      ["df", ["-h", "/"], { stdio: "inherit" }],
    ]);
  });

  it("stops before cleanup if the initial disk probe fails", () => {
    const run = vi.fn(() => ({ status: 1 }));
    expect(() =>
      prepareHostedLinuxDisk({ env: hostedEnv, platform: "linux", isContainer: false, run }),
    ).toThrow("disk preparation failed: df");
    expect(run).toHaveBeenCalledTimes(1);
  });

  it("does not report success after cleanup fails", () => {
    const run = vi.fn().mockReturnValueOnce({ status: 0 }).mockReturnValueOnce({ status: 1 });
    expect(() =>
      prepareHostedLinuxDisk({ env: hostedEnv, platform: "linux", isContainer: false, run }),
    ).toThrow("disk preparation failed: sudo");
    expect(run).toHaveBeenCalledTimes(2);
  });

  it("propagates process launch errors instead of hiding them", () => {
    const error = new Error("missing df");
    const run = vi.fn(() => ({ status: null, error }));
    expect(() =>
      prepareHostedLinuxDisk({ env: hostedEnv, platform: "linux", isContainer: false, run }),
    ).toThrow(expect.objectContaining({ cause: error }));
    expect(run).toHaveBeenCalledTimes(1);
  });
});
