import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { SqlitePushReferenceStore } from "../../infra/pqc-push-state.js";
import type { PushDualEnvelope } from "../../security/push-dual-signature.js";
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

async function invoke(method: string, params: unknown, deviceId?: string, registry?: unknown) {
  const respond = vi.fn();
  await coreGatewayHandlers[method]!({
    req: { type: "req", id: "test", method, params },
    params,
    respond,
    client: deviceId ? { connId: "connection", connect: { device: { id: deviceId } } } : undefined,
    context: { nodeRegistry: registry },
  } as unknown as GatewayRequestHandlerOptions);
  return respond;
}

describe("authenticated V2 push redemption", () => {
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
