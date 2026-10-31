import { afterEach, describe, expect, it, vi } from "vitest";

function firstIssueMessage(result: {
  success: boolean;
  error?: { issues: Array<{ message: string }> };
}): string {
  if (result.success) {
    throw new Error("expected parse failure");
  }
  return result.error?.issues[0]?.message ?? "";
}

describe("zod default locale", () => {
  afterEach(() => {
    vi.resetModules();
  });

  it("restores real issue messages when the bundled locale registration was tree-shaken", async () => {
    vi.resetModules();
    const { z } = await import("zod");
    const previousLocaleError = z.config().localeError;

    try {
      // Simulate a built dist: zod@4 is sideEffects:false, so its implicit
      // locale registration can be dropped by bundling.
      // Zod 4.6 also installs its locale during schema construction. Clear it
      // after building the probe so this still exercises the missing-locale state.
      const probe = z.object({ expected: z.string() }).strict();
      z.config({ localeError: undefined });
      const degraded = probe.safeParse({ unexpected: true });
      expect(firstIssueMessage(degraded)).toBe("Invalid input");

      const { OpenClawSchema } = await import("./zod-schema.js");
      const restored = OpenClawSchema.safeParse({
        agents: { defaults: { session: { pruneAfter: "1d" } } },
      });
      expect(firstIssueMessage(restored)).toBe('Unrecognized key: "session"');
      const typeError = OpenClawSchema.safeParse({ gateway: { port: "not-a-number" } });
      expect(firstIssueMessage(typeError)).toBe("Invalid input: expected number, received string");
    } finally {
      z.config({ localeError: previousLocaleError });
    }
  });
});
