import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { getPairedDevice } from "../../infra/device-pairing.js";
import { nextPushSequence, SqlitePushReferenceStore } from "../../infra/pqc-push-state.js";
import type { PushDualEnvelope } from "../../security/push-dual-signature.js";
import { closeOpenClawStateDatabase } from "../../state/openclaw-state-db.js";
import { pushHandlers } from "./push.js";
import type { GatewayRequestHandlerOptions } from "./types.js";

vi.mock("../../infra/device-pairing.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../infra/device-pairing.js")>()),
  getPairedDevice: vi.fn(),
}));
let directory: string;
beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), "pqc-recovery-rpc-"));
  vi.stubEnv("OPENCLAW_STATE_DIR", directory);
  vi.mocked(getPairedDevice).mockResolvedValue({
    deviceId: "alice",
    publicKey: "verified-fixture-key",
    role: "operator",
    roles: ["operator"],
    scopes: ["operator.read"],
    approvedScopes: ["operator.read"],
    createdAtMs: 1,
    approvedAtMs: 1,
    tokens: {
      operator: {
        role: "operator",
        scopes: ["operator.read"],
        token: "fixture-placeholder",
        createdAtMs: 1,
      },
    },
  });
});
afterEach(() => {
  closeOpenClawStateDatabase();
  vi.unstubAllEnvs();
  rmSync(directory, { recursive: true, force: true });
});
const client = () => ({
  connectionKind: "gateway",
  isDeviceTokenAuth: true,
  authenticatedDeviceTokenSha256: createHash("sha256").update("fixture-placeholder").digest("hex"),
  verifiedDeviceProof: { id: "alice", publicKey: "verified-fixture-key" },
  connect: {
    role: "operator",
    device: { id: "alice" },
    scopes: ["operator.read"],
    caps: ["push-key-policy-v1", "push-recovery-snapshot-v1"],
  },
});
async function invoke(method: string, params: unknown, connection: unknown = client()) {
  const respond = vi.fn();
  await pushHandlers[method]!({
    params,
    client: connection,
    respond,
  } as unknown as GatewayRequestHandlerOptions);
  return respond.mock.calls[0]!;
}
function create(recipientId = "alice") {
  return new SqlitePushReferenceStore().createWithSignature((env) => ({
    payload: "protected",
    recipientId,
    envelope: {
      sender_id: "gateway",
      recipient_id: recipientId,
      sequence: nextPushSequence("gateway", recipientId, { env }),
    } as PushDualEnvelope,
  }));
}
function reference(d: ReturnType<typeof create>) {
  return { version: d.version, object_id: d.object_id, expires_at_ms: d.expires_at_ms };
}

describe("recovery RPC and current pairing authorization with durable store", () => {
  it("returns only the proven owner's unconsumed work and supports lost ACK retries", async () => {
    const descriptor = create();
    create("bob");
    const read = await invoke("push.pqc.pending", {});
    expect(read[0]).toBe(true);
    expect(read[1].items).toHaveLength(1);
    expect(read[1].items[0].object_id).toBe(descriptor.object_id);
    expect(JSON.stringify(read[1])).not.toContain("token");
    expect(new SqlitePushReferenceStore().redeem(descriptor, "alice").payload).toBe("protected");
    expect((await invoke("push.pqc.pending.ack", reference(descriptor)))[0]).toBe(true);
    closeOpenClawStateDatabase();
    expect((await invoke("push.pqc.pending.ack", reference(descriptor)))[0]).toBe(true);
    expect((await invoke("push.pqc.pending", {}))[1].items).toEqual([]);
  });
  it.each([
    { recipientId: "bob" },
    { recipient_id: "bob" },
    { token: "A".repeat(43) },
    { limit: 10000 },
    { after: { objectId: "bad", expiresAtMs: 1000 } },
    { after: { objectId: "a".repeat(36), expiresAtMs: -1 } },
  ])("rejects injected or malformed listing params %#", async (params) => {
    create();
    expect((await invoke("push.pqc.pending", params))[0]).toBe(false);
    expect((await invoke("push.pqc.pending", {}))[1].items).toHaveLength(1);
  });
  it("rejects no-proof, removed pairing and replaced key before releasing any payload", async () => {
    create();
    const noProof = { ...client(), verifiedDeviceProof: undefined };
    expect((await invoke("push.pqc.pending", {}, noProof))[0]).toBe(false);
    vi.mocked(getPairedDevice).mockResolvedValue(null);
    expect((await invoke("push.pqc.pending", {}))[0]).toBe(false);
  });
  it("rechecks revocation between listing and acknowledgement and keeps the object", async () => {
    const descriptor = create();
    expect((await invoke("push.pqc.pending", {}))[0]).toBe(true);
    vi.mocked(getPairedDevice).mockResolvedValue(null);
    expect((await invoke("push.pqc.pending.ack", reference(descriptor)))[0]).toBe(false);
    expect(new SqlitePushReferenceStore().redeem(descriptor, "alice").payload).toBe("protected");
  });
  it("cannot acknowledge another owner's object or extend its expiry", async () => {
    const other = create("bob"),
      own = create();
    expect((await invoke("push.pqc.pending.ack", reference(other)))[0]).toBe(false);
    expect(
      (
        await invoke("push.pqc.pending.ack", {
          ...reference(own),
          expires_at_ms: own.expires_at_ms + 1,
        })
      )[0],
    ).toBe(false);
    expect(
      (await invoke("push.pqc.pending.ack", { ...reference(own), recipientId: "bob" }))[0],
    ).toBe(false);
    expect(new SqlitePushReferenceStore().redeem(other, "bob").payload).toBe("protected");
    expect(new SqlitePushReferenceStore().redeem(own, "alice").payload).toBe("protected");
  });
  it("preserves separate durable read and ACK budgets", async () => {
    const descriptor = create();
    const first = await invoke("push.pqc.pending", {});
    expect(first[0]).toBe(true);
    for (let i = 1; i < 60; i++) {
      expect(
        (
          await invoke("push.pqc.pending", {
            after: { snapshotId: first[1].snapshotId, offset: 0 },
          })
        )[0],
      ).toBe(true);
    }
    expect((await invoke("push.pqc.pending", {}))[0]).toBe(false);
    expect((await invoke("push.pqc.pending.ack", reference(descriptor)))[0]).toBe(true);
  });
});
