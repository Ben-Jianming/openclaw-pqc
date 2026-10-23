import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SqlitePushReferenceStore } from "../../infra/pqc-push-state.js";
import type { PushDualEnvelope } from "../../security/push-dual-signature.js";
import { PUSH_KEY_POLICY_CAPABILITY } from "../../shared/push-key-policy.js";
import { closeOpenClawStateDatabase } from "../../state/openclaw-state-db.js";
import { coreGatewayHandlers } from "../server-methods.js";
import type { GatewayRequestHandlerOptions } from "./types.js";

let directory: string;
beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), "pqc-rpc-test-"));
  vi.stubEnv("OPENCLAW_STATE_DIR", directory);
});
afterEach(() => {
  closeOpenClawStateDatabase();
  vi.unstubAllEnvs();
  rmSync(directory, { recursive: true, force: true });
});

async function invoke(
  method: string,
  params: unknown,
  deviceId?: string,
  registry?: unknown,
  caps: string[] = [PUSH_KEY_POLICY_CAPABILITY],
) {
  const respond = vi.fn();
  await coreGatewayHandlers[method]!({
    req: { type: "req", id: "test", method, params },
    params,
    respond,
    client: deviceId
      ? { connId: "connection", connect: { device: { id: deviceId }, caps } }
      : undefined,
    context: { nodeRegistry: registry },
  } as unknown as GatewayRequestHandlerOptions);
  return respond;
}

describe("authenticated V2 push redemption", () => {
  it.each([{ caps: [] }, { caps: ["push-key-policy-v0"] }, { caps: ["tool-events"] }])(
    "rejects unsupported capability $caps without consuming or acknowledging content",
    async ({ caps }) => {
      const store = new SqlitePushReferenceStore();
      const descriptor = store.create({
        payload: "retained",
        recipientId: "alice",
        envelope: { recipient_id: "alice" } as PushDualEnvelope,
      });
      for (const [method, params] of [
        ["push.pqc.keys", {}],
        ["push.pqc.redeem", descriptor],
        ["push.pqc.redeem", { ...descriptor, acknowledge: true }],
        [
          "push.web.subscribe",
          { endpoint: "https://example.com/push", keys: { p256dh: "AA", auth: "AA" } },
        ],
      ] as const) {
        const response = await invoke(method, params, "alice", undefined, caps);
        expect(response.mock.calls[0]![0]).toBe(false);
        expect(response.mock.calls[0]![2].details).toMatchObject({
          code: "PUSH_KEY_POLICY_CAPABILITY_REQUIRED",
          requiredCapability: PUSH_KEY_POLICY_CAPABILITY,
        });
      }
      expect(store.redeem(descriptor, "alice").payload).toBe("retained");
      expect((await invoke("push.pqc.redeem", descriptor, "alice")).mock.calls[0]![0]).toBe(true);
    },
  );

  it("returns enrolled policies only to authenticated recipients and exposes committed revocation", async () => {
    const { getOrCreatePushSigningKey } = await import("../../infra/push-signing-key.js");
    const { loadOrCreateProcessDeviceIdentity } = await import("../../infra/device-identity.js");
    const { enrollExistingPushKeys, revokePushKeyPolicy } =
      await import("../../infra/push-key-policy-store.js");
    expect((await invoke("push.pqc.keys", {}, "alice")).mock.calls[0]![0]).toBe(false);
    getOrCreatePushSigningKey();
    loadOrCreateProcessDeviceIdentity();
    expect((await invoke("push.pqc.keys", {}, "alice")).mock.calls[0]![0]).toBe(false);
    const nowMs = Date.now();
    enrollExistingPushKeys({ validFromMs: nowMs - 1000, validUntilMs: nowMs + 60000 });
    expect((await invoke("push.pqc.keys", {})).mock.calls[0]![0]).toBe(false);
    expect(
      (await invoke("push.pqc.keys", { keyPolicy: "attacker" }, "alice")).mock.calls[0]![0],
    ).toBe(false);
    const response = await invoke("push.pqc.keys", {}, "alice");
    expect(response.mock.calls[0]![0]).toBe(true);
    const keys = response.mock.calls[0]![1];
    expect(keys).toMatchObject({
      recipientId: "alice",
      keyPolicyVersion: 1,
      keyPolicy: {
        ed25519: { status: "active", revision: 1 },
        mldsa65: { status: "active", revision: 1 },
      },
    });
    revokePushKeyPolicy({
      senderId: keys.senderId,
      algorithm: "ed25519",
      keyId: keys.keyIdEd25519,
    });
    closeOpenClawStateDatabase();
    const refreshed = await invoke("push.pqc.keys", {}, "alice");
    expect(refreshed.mock.calls[0]![1].keyPolicy.ed25519).toMatchObject({
      status: "revoked",
      revision: 2,
    });
  });

  it("rejects anonymous, malformed and wrong-recipient requests without burning the object", async () => {
    const store = new SqlitePushReferenceStore();
    const descriptor = store.create({
      payload: "private body",
      recipientId: "alice",
      envelope: { recipient_id: "alice" } as PushDualEnvelope,
    });
    expect((await invoke("push.pqc.redeem", descriptor)).mock.calls[0]![0]).toBe(false);
    expect(
      (await invoke("push.pqc.redeem", { ...descriptor, extra: true }, "alice")).mock.calls[0]![0],
    ).toBe(false);
    const wrong = await invoke("push.pqc.redeem", descriptor, "bob");
    expect(wrong.mock.calls[0]![0]).toBe(false);
    expect(JSON.stringify(wrong.mock.calls)).not.toContain(descriptor.token);
    expect((await invoke("push.pqc.redeem", descriptor, "alice")).mock.calls[0]).toEqual([
      true,
      expect.objectContaining({ payload: "private body" }),
      undefined,
    ]);
    expect((await invoke("push.pqc.redeem", descriptor, "alice")).mock.calls[0]![0]).toBe(true);
    expect(
      (await invoke("push.pqc.redeem", { ...descriptor, acknowledge: true }, "bob")).mock
        .calls[0]![0],
    ).toBe(false);
    expect(
      (await invoke("push.pqc.redeem", { ...descriptor, acknowledge: true }, "alice")).mock
        .calls[0],
    ).toEqual([true, { acknowledged: true }, undefined]);
    closeOpenClawStateDatabase();
    expect(
      (await invoke("push.pqc.redeem", { ...descriptor, acknowledge: true }, "alice")).mock
        .calls[0]![0],
    ).toBe(true);
    expect((await invoke("push.pqc.redeem", descriptor, "alice")).mock.calls[0]![0]).toBe(false);
  });

  it("refuses a revoked/replaced node connection before consuming its capability", async () => {
    const descriptor = new SqlitePushReferenceStore().create({
      payload: "x",
      recipientId: "alice",
      envelope: { recipient_id: "alice" } as PushDualEnvelope,
    });
    const registry = {
      get: () => ({ pairingGeneration: "generation" }),
      getForPairingGeneration: vi.fn(() => ({
        connId: "connection",
        pairingGeneration: "generation",
      })),
      isConnectionCurrentPairingState: vi.fn(async () => false),
    };
    expect(
      (await invoke("node.push.pqc.redeem", descriptor, "alice", registry)).mock.calls[0]![0],
    ).toBe(false);
    registry.isConnectionCurrentPairingState.mockImplementation(async () => {
      registry.getForPairingGeneration.mockReturnValue({
        connId: "replaced",
        pairingGeneration: "generation",
      });
      return true;
    });
    expect(
      (await invoke("node.push.pqc.redeem", descriptor, "alice", registry)).mock.calls[0]![0],
    ).toBe(false);
    registry.getForPairingGeneration.mockReturnValue({
      connId: "connection",
      pairingGeneration: "generation",
    });
    registry.isConnectionCurrentPairingState.mockResolvedValue(true);
    expect(
      (await invoke("node.push.pqc.redeem", descriptor, "alice", registry)).mock.calls[0]![0],
    ).toBe(true);
  });
});
