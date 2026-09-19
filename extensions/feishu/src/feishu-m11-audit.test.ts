import { describe, expect, it, vi } from "vitest";

const pqcLogCalls: Array<{ level: string; payload: Record<string, unknown> }> = [];
const signCalls: Array<Record<string, unknown>> = [];
let signingFails = false;

vi.mock("openclaw/plugin-sdk/pqc-log", () => ({
  pqcLog: {
    info: (payload: Record<string, unknown>) => pqcLogCalls.push({ level: "info", payload }),
    warn: (payload: Record<string, unknown>) => pqcLogCalls.push({ level: "warn", payload }),
  },
}));

vi.mock("openclaw/plugin-sdk/push-envelope", () => ({
  trySignPushEnvelope: (options: Record<string, unknown>) => {
    signCalls.push(options);
    if (signingFails) {
      return null;
    }
    return {
      payload: options.payload,
      keyIdEd25519: "gateway-ed-key",
      keyIdMldsa65: "primary",
      envelope: {
        algorithms: ["ed25519", "ml-dsa-65"],
        ed25519_sig: "ed-signature",
        mldsa65_sig: "ml-signature",
        key_id_ed25519: "gateway-ed-key",
        key_id_mldsa65: "primary",
      },
    };
  },
}));

import { auditFeishuSendWithM11 } from "./feishu-m11-audit.js";

describe("Feishu canonical M11 audit", () => {
  it("uses the gateway signer and preserves its key identities", () => {
    pqcLogCalls.length = 0;
    signCalls.length = 0;
    signingFails = false;
    const env = { OPENCLAW_STATE_DIR: "/isolated/state" };
    const result = auditFeishuSendWithM11("hello 飞书 🚀", env);

    expect(signCalls).toEqual([{ payload: "hello 飞书 🚀", env }]);
    expect(result.signed).toBe(true);
    expect(result.envelope?.key_id_ed25519).toBe("gateway-ed-key");
    expect(result.envelope?.key_id_mldsa65).toBe("primary");
    expect(result.contentSha256).toMatch(/^[0-9a-f]{64}$/);
    expect(pqcLogCalls.some((call) => call.payload.status === "ok")).toBe(true);
  });

  it("makes degraded audit state explicit when canonical signing fails", () => {
    pqcLogCalls.length = 0;
    signCalls.length = 0;
    signingFails = true;
    const result = auditFeishuSendWithM11("sensitive content");

    expect(result).toMatchObject({ signed: false, envelope: null });
    expect(result.error).toMatch(/canonical gateway/);
    expect(pqcLogCalls.some((call) => call.payload.status === "fail")).toBe(true);
  });
});
