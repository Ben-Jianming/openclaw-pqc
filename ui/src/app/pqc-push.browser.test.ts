import { getPublicKeyAsync, signAsync } from "@noble/ed25519";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import type { GatewayBrowserClient } from "../api/gateway.ts";
import { loadOrCreateDeviceIdentity } from "../lib/nodes/index.ts";
import {
  encodeBrowserPushTranscript,
  receivePendingPqcPushes,
  type PushV2Envelope,
} from "./pqc-push.ts";

const snapshotId = "00000000-0000-4000-8000-000000000099";
const databaseName = "openclaw-pqc-push-v2";
const originalWorker = Object.getOwnPropertyDescriptor(navigator, "serviceWorker");
const showNotification = vi.fn().mockResolvedValue(undefined);
const b64 = (bytes: Uint8Array) =>
  btoa(String.fromCharCode(...bytes))
    .replaceAll("+", "-")
    .replaceAll("/", "_")
    .replaceAll("=", "");
async function db(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const r = indexedDB.open(databaseName, 1);
    r.addEventListener(
      "upgradeneeded",
      () => {
        r.result.createObjectStore("wakes", { keyPath: "object_id" });
        r.result.createObjectStore("replay");
      },
      { once: true },
    );
    r.addEventListener("success", () => resolve(r.result), { once: true });
    r.addEventListener("error", () => reject(new Error("test database unavailable")), {
      once: true,
    });
  });
}
async function queued(rows?: Array<Record<string, unknown>>): Promise<number> {
  const database = await db();
  try {
    return await new Promise((resolve, reject) => {
      const tx = database.transaction("wakes", rows ? "readwrite" : "readonly");
      const store = tx.objectStore("wakes");
      for (const row of rows ?? []) {
        store.put(row);
      }
      const count = store.count();
      tx.addEventListener("complete", () => resolve(count.result), { once: true });
      tx.addEventListener("abort", () => reject(new Error("test transaction aborted")), {
        once: true,
      });
    });
  } finally {
    database.close();
  }
}
async function resetDatabase() {
  await new Promise<void>((resolve, reject) => {
    const r = indexedDB.deleteDatabase(databaseName);
    r.addEventListener("success", () => resolve(), { once: true });
    r.addEventListener("error", () => reject(new Error("test cleanup failed")), { once: true });
  });
}
beforeEach(async () => {
  await resetDatabase();
  localStorage.clear();
  showNotification.mockClear();
  Object.defineProperty(navigator, "serviceWorker", {
    configurable: true,
    value: { ready: Promise.resolve({ scope: "https://localhost/", showNotification }) },
  });
});
afterEach(async () => {
  await resetDatabase();
  localStorage.clear();
  if (originalWorker) {
    Object.defineProperty(navigator, "serviceWorker", originalWorker);
  } else {
    Reflect.deleteProperty(navigator, "serviceWorker");
  }
});
async function messages(count: number) {
  const identity = await loadOrCreateDeviceIdentity();
  const ed = new Uint8Array(32).fill(1);
  const ml = ml_dsa65.keygen();
  const keys = {
    senderId: "test-gateway",
    recipientId: identity.deviceId,
    keyIdEd25519: "ed",
    keyIdMldsa65: "ml",
    ed25519PublicKeyBase64Url: b64(await getPublicKeyAsync(ed)),
    mldsa65PublicKeyBase64Url: b64(ml.publicKey),
  };
  const nowMs = Date.now();
  const trustedKeys = {
    ...keys,
    keyPolicyVersion: 1 as const,
    keyPolicy: {
      ed25519: {
        algorithm: "ed25519" as const,
        keyId: keys.keyIdEd25519,
        senderId: keys.senderId,
        publicKeyBase64Url: keys.ed25519PublicKeyBase64Url,
        status: "active" as const,
        validFromMs: nowMs - 1000,
        validUntilMs: nowMs + 600000,
        revision: 1,
      },
      mldsa65: {
        algorithm: "ml-dsa-65" as const,
        keyId: keys.keyIdMldsa65,
        senderId: keys.senderId,
        publicKeyBase64Url: keys.mldsa65PublicKeyBase64Url,
        status: "active" as const,
        validFromMs: nowMs - 1000,
        validUntilMs: nowMs + 600000,
        revision: 1,
      },
    },
  };
  const values = new Map<string, { payload: string; envelope: PushV2Envelope }>();
  const rows = [];
  for (let sequence = 1; sequence <= count; sequence++) {
    const payload = JSON.stringify({
      title: "Verified " + sequence,
      body: "Authenticated content",
    });
    const envelope: PushV2Envelope = {
      version: 2,
      algorithms: ["ed25519", "ml-dsa-65"],
      sender_id: keys.senderId,
      recipient_id: identity.deviceId,
      key_id_ed25519: "ed",
      key_id_mldsa65: "ml",
      created_at_ms: Date.now(),
      sequence,
      nonce: b64(crypto.getRandomValues(new Uint8Array(24))),
      payload_type: "application/json",
      payload_sha256: b64(
        new Uint8Array(await crypto.subtle.digest("SHA-256", new TextEncoder().encode(payload))),
      ),
      ed25519_sig: "",
      mldsa65_sig: "",
    };
    const transcript = encodeBrowserPushTranscript(envelope);
    envelope.ed25519_sig = b64(await signAsync(transcript, ed));
    envelope.mldsa65_sig = b64(ml_dsa65.sign(transcript, ml.secretKey));
    const object_id = "00000000-0000-4000-8000-" + String(sequence).padStart(12, "0");
    rows.push({
      version: 1,
      object_id,
      token: b64(new Uint8Array(32).fill(sequence)),
      expires_at_ms: Date.now() + 300000,
    });
    values.set(object_id, { payload, envelope });
  }
  await queued(rows);
  return { keys: trustedKeys, values, rows };
}
describe("real browser durable wake retries", () => {
  it.each(["ed25519", "mldsa65"] as const)(
    "refreshes %s policy before display and keeps the inbox on revocation",
    async (algorithm) => {
      const m = await messages(1);
      let keyReads = 0;
      let revoked = true;
      const request = vi.fn(async (method: string, p: Record<string, unknown>) => {
        if (method === "push.pqc.pending") {
          return { snapshotId, items: [] };
        }
        if (method === "push.pqc.keys") {
          keyReads++;
          // First pass and durable acceptance see an active key; the final display check must refresh.
          if (revoked && keyReads >= 3) {
            return {
              ...m.keys,
              keyPolicy: {
                ...m.keys.keyPolicy,
                [algorithm]: { ...m.keys.keyPolicy[algorithm], status: "revoked", revision: 2 },
              },
            };
          }
          return m.keys;
        }
        if (p.acknowledge) {
          return { acknowledged: true };
        }
        return m.values.get(p.object_id as string);
      });
      const client = { request, pushRecoveryReady: true } as unknown as GatewayBrowserClient;
      await expect(receivePendingPqcPushes(client)).rejects.toThrow();
      expect(showNotification).not.toHaveBeenCalled();
      expect(await queued()).toBe(1);
      expect(request.mock.calls.filter(([, p]) => p.acknowledge)).toHaveLength(0);
      // A second drain must also revalidate a previously verified, persisted inbox.
      await expect(receivePendingPqcPushes(client)).rejects.toThrow();
      expect(showNotification).not.toHaveBeenCalled();
      expect(await queued()).toBe(1);
      // Test-only policy restoration models a transient provisioning fault, not an admin un-revoke API.
      revoked = false;
      await receivePendingPqcPushes(client);
      expect(showNotification).toHaveBeenCalledTimes(1);
      expect(await queued()).toBe(0);
      expect(
        request.mock.calls.filter(([method, p]) => method === "push.pqc.redeem" && !p.acknowledge),
      ).toHaveLength(1);
    },
  );

  it.each([1, 2, 3, 4, 5, 6])(
    "halts the drain on policy refresh failure %s and recovers both ordered messages",
    async (failAt) => {
      const m = await messages(2);
      let reads = 0;
      let fail = true;
      const request = vi.fn(async (method: string, p: Record<string, unknown>) => {
        if (method === "push.pqc.pending") {
          return { snapshotId, items: [] };
        }
        if (method === "push.pqc.keys") {
          if (++reads === failAt && fail) {
            throw new Error("transient key policy RPC failure");
          }
          return m.keys;
        }
        if (p.acknowledge) {
          return { acknowledged: true };
        }
        return m.values.get(p.object_id as string);
      });
      const client = { request, pushRecoveryReady: true } as unknown as GatewayBrowserClient;
      await expect(receivePendingPqcPushes(client)).rejects.toThrow();
      const completedBeforeFailure = failAt >= 5 ? 1 : 0;
      expect(showNotification).toHaveBeenCalledTimes(completedBeforeFailure);
      expect(await queued()).toBe(2 - completedBeforeFailure);
      expect(request.mock.calls.filter(([, p]) => p.acknowledge)).toHaveLength(
        completedBeforeFailure,
      );
      fail = false;
      await receivePendingPqcPushes(client);
      expect(showNotification.mock.calls.map(([title]) => title)).toEqual([
        "Verified 1",
        "Verified 2",
      ]);
      expect(await queued()).toBe(0);
      expect(request.mock.calls.filter(([, p]) => p.acknowledge)).toHaveLength(2);
    },
  );

  describe.each([1, 3])("unusable policy response at refresh %s", (failAt) => {
    it.each([
      "missing-policy",
      "missing-ed-policy",
      "missing-ml-policy",
      "invalid-validity",
      "missing-ed-key",
      "short-ed-key",
      "missing-sender",
      "missing-ml-key-id",
      "invalid-revision",
    ])("halts on %s and later recovers both messages", async (kind) => {
      const m = await messages(2);
      const malformed = structuredClone(m.keys) as unknown as Record<string, unknown>;
      const policies = malformed.keyPolicy as Record<string, Record<string, unknown>>;
      switch (kind) {
        case "missing-policy":
          delete malformed.keyPolicy;
          break;
        case "missing-ed-policy":
          delete policies.ed25519;
          break;
        case "missing-ml-policy":
          delete policies.mldsa65;
          break;
        case "invalid-validity":
          policies.ed25519!.validUntilMs = "tomorrow";
          break;
        case "missing-ed-key":
          delete malformed.ed25519PublicKeyBase64Url;
          break;
        case "short-ed-key":
          malformed.ed25519PublicKeyBase64Url = "AA";
          policies.ed25519!.publicKeyBase64Url = "AA";
          break;
        case "missing-sender":
          delete malformed.senderId;
          delete policies.ed25519!.senderId;
          delete policies.mldsa65!.senderId;
          break;
        case "missing-ml-key-id":
          delete malformed.keyIdMldsa65;
          delete policies.mldsa65!.keyId;
          break;
        case "invalid-revision":
          policies.mldsa65!.revision = "1";
          break;
      }
      let reads = 0;
      let fail = true;
      const request = vi.fn(async (method: string, p: Record<string, unknown>) => {
        if (method === "push.pqc.pending") {
          return { snapshotId, items: [] };
        }
        if (method === "push.pqc.keys") {
          return ++reads === failAt && fail ? malformed : m.keys;
        }
        if (p.acknowledge) {
          return { acknowledged: true };
        }
        return m.values.get(p.object_id as string);
      });
      const client = { request, pushRecoveryReady: true } as unknown as GatewayBrowserClient;
      await expect(receivePendingPqcPushes(client)).rejects.toThrow();
      expect(showNotification).not.toHaveBeenCalled();
      expect(await queued()).toBe(2);
      expect(request.mock.calls.filter(([, p]) => p.acknowledge)).toHaveLength(0);
      fail = false;
      await receivePendingPqcPushes(client);
      expect(showNotification.mock.calls.map(([title]) => title)).toEqual([
        "Verified 1",
        "Verified 2",
      ]);
      expect(await queued()).toBe(0);
    });
  });

  it("does not display or acknowledge when the final policy refresh disconnects", async () => {
    const m = await messages(1);
    let reads = 0;
    let fail = true;
    const request = vi.fn(async (method: string, p: Record<string, unknown>) => {
      if (method === "push.pqc.pending") {
        return { snapshotId, items: [] };
      }
      if (method === "push.pqc.keys") {
        if (++reads >= 3 && fail) {
          throw new Error("connection lost during policy refresh");
        }
        return m.keys;
      }
      if (p.acknowledge) {
        return { acknowledged: true };
      }
      return m.values.get(p.object_id as string);
    });
    const client = { request, pushRecoveryReady: true } as unknown as GatewayBrowserClient;
    await expect(receivePendingPqcPushes(client)).rejects.toThrow();
    expect(showNotification).not.toHaveBeenCalled();
    expect(await queued()).toBe(1);
    expect(request.mock.calls.filter(([, p]) => p.acknowledge)).toHaveLength(0);
    fail = false;
    await receivePendingPqcPushes(client);
    expect(showNotification).toHaveBeenCalledTimes(1);
    expect(await queued()).toBe(0);
  });

  it("keeps four quota failures after 60 successful redemptions and displays them after retry", async () => {
    const m = await messages(64);
    let attempts = 0;
    const client = {
      pushRecoveryReady: true,
      request: vi.fn(async (method: string, p: Record<string, unknown>) => {
        if (method === "push.pqc.pending") {
          return { snapshotId, items: [] };
        }
        if (method === "push.pqc.keys") {
          return m.keys;
        }
        if (p.acknowledge === true) {
          return { acknowledged: true };
        }
        if (++attempts > 60) {
          throw new Error("UNAVAILABLE: rate limited");
        }
        return m.values.get(p.object_id as string);
      }),
    } as unknown as GatewayBrowserClient;
    await expect(receivePendingPqcPushes(client)).rejects.toThrow("could not be verified");
    expect(await queued()).toBe(4);
    expect(showNotification).toHaveBeenCalledTimes(60);
    attempts = 0;
    await receivePendingPqcPushes(client);
    expect(await queued()).toBe(0);
    expect(showNotification).toHaveBeenCalledTimes(64);
    await receivePendingPqcPushes(client);
    expect(showNotification).toHaveBeenCalledTimes(64);
  });
  it("keeps a reference on connection failure and never displays tampered content", async () => {
    const m = await messages(1);
    let disconnected = true;
    const client = {
      pushRecoveryReady: true,
      request: vi.fn(async (method: string, p: Record<string, unknown>) => {
        if (method === "push.pqc.pending") {
          return { snapshotId, items: [] };
        }
        if (method === "push.pqc.keys") {
          return m.keys;
        }
        if (disconnected) {
          throw new Error("connection closed");
        }
        const value = m.values.get(p.object_id as string)!;
        return { ...value, payload: value.payload + "tampered" };
      }),
    } as unknown as GatewayBrowserClient;
    await expect(receivePendingPqcPushes(client)).rejects.toThrow();
    expect(await queued()).toBe(1);
    expect(showNotification).not.toHaveBeenCalled();
    disconnected = false;
    await expect(receivePendingPqcPushes(client)).rejects.toThrow();
    expect(await queued()).toBe(1);
    expect(showNotification).not.toHaveBeenCalled();
  });
  it("removes expired references without trying to redeem or display them", async () => {
    const m = await messages(1);
    await queued([{ ...m.rows[0], expires_at_ms: Date.now() - 1 }]);
    const request = vi.fn(async (method: string) =>
      method === "push.pqc.pending" ? { snapshotId, items: [] } : m.keys,
    );
    await receivePendingPqcPushes({
      request,
      pushRecoveryReady: true,
    } as unknown as GatewayBrowserClient);
    expect(request.mock.calls.map(([method]) => method)).toEqual(["push.pqc.pending"]);
    expect(await queued()).toBe(0);
    expect(showNotification).not.toHaveBeenCalled();
  });
  it("retries a failed display from the durable verified inbox without another redemption", async () => {
    const m = await messages(1);
    const request = vi.fn(async (method: string, p: Record<string, unknown>) => {
      if (method === "push.pqc.pending") {
        return { snapshotId, items: [] };
      }
      if (method === "push.pqc.keys") {
        return m.keys;
      }
      if (p.acknowledge === true) {
        return { acknowledged: true };
      }
      return m.values.get(p.object_id as string);
    });
    const client = { request, pushRecoveryReady: true } as unknown as GatewayBrowserClient;
    showNotification.mockRejectedValueOnce(new Error("presentation unavailable"));
    await expect(receivePendingPqcPushes(client)).rejects.toThrow();
    expect(await queued()).toBe(1);
    expect(
      request.mock.calls.filter(([method, p]) => method === "push.pqc.redeem" && !p.acknowledge),
    ).toHaveLength(1);
    await receivePendingPqcPushes(client);
    expect(await queued()).toBe(0);
    expect(
      request.mock.calls.filter(([method, p]) => method === "push.pqc.redeem" && !p.acknowledge),
    ).toHaveLength(1);
    expect(showNotification).toHaveBeenCalledTimes(2);
  });
  it("retries a lost acknowledgement without displaying a completed notification again", async () => {
    const m = await messages(1);
    let lost = true;
    const request = vi.fn(async (method: string, p: Record<string, unknown>) => {
      if (method === "push.pqc.pending") {
        return { snapshotId, items: [] };
      }
      if (method === "push.pqc.keys") {
        return m.keys;
      }
      if (p.acknowledge === true) {
        if (lost) {
          lost = false;
          throw new Error("ack response lost");
        }
        return { acknowledged: true };
      }
      return m.values.get(p.object_id as string);
    });
    const client = { request, pushRecoveryReady: true } as unknown as GatewayBrowserClient;
    await expect(receivePendingPqcPushes(client)).rejects.toThrow();
    expect(showNotification).toHaveBeenCalledTimes(1);
    expect(await queued()).toBe(1);
    await receivePendingPqcPushes(client);
    expect(showNotification).toHaveBeenCalledTimes(1);
    expect(await queued()).toBe(0);
  });
  it("recovers a signed object with no provider wake, keeps a verified inbox across lost ACK, and does not redisplay", async () => {
    const m = await messages(1);
    await resetDatabase();
    let failAck = true;
    let acknowledged = false;
    const request = vi.fn(async (method: string) => {
      if (method === "push.pqc.pending") {
        return {
          snapshotId,
          items: acknowledged
            ? []
            : m.rows.map((row) => ({
                object_id: row.object_id,
                expires_at_ms: row.expires_at_ms,
                value: { ...m.values.get(row.object_id), recipientId: m.keys.recipientId },
              })),
        };
      }
      if (method === "push.pqc.keys") {
        return m.keys;
      }
      if (method === "push.pqc.pending.ack") {
        if (failAck) {
          throw new Error("test lost ACK response");
        }
        acknowledged = true;
        return { acknowledged: true };
      }
      throw new Error("unexpected capability redemption on recovered object");
    });
    const client = { request, pushRecoveryReady: true } as unknown as GatewayBrowserClient;
    await expect(receivePendingPqcPushes(client)).rejects.toThrow();
    expect(showNotification).toHaveBeenCalledTimes(1);
    expect(await queued()).toBe(1);
    failAck = false;
    await receivePendingPqcPushes(client);
    expect(showNotification).toHaveBeenCalledTimes(1);
    expect(await queued()).toBe(0);
    expect(request.mock.calls.some(([method]) => method === "push.pqc.redeem")).toBe(false);
    expect(acknowledged).toBe(true);
  });
  it("verifies and orders recovered work before advancing replay, alongside an existing wake", async () => {
    const m = await messages(2);
    await resetDatabase();
    await queued([m.rows[0]!]);
    const request = vi.fn(async (method: string) => {
      if (method === "push.pqc.pending") {
        return {
          snapshotId,
          items: [...m.rows].toReversed().map((row) => ({
            object_id: row.object_id,
            expires_at_ms: row.expires_at_ms,
            value: { ...m.values.get(row.object_id), recipientId: m.keys.recipientId },
          })),
        };
      }
      if (method === "push.pqc.keys") {
        return m.keys;
      }
      if (method === "push.pqc.pending.ack") {
        return { acknowledged: true };
      }
      throw new Error("unexpected legacy redemption");
    });
    await receivePendingPqcPushes({
      request,
      pushRecoveryReady: true,
    } as unknown as GatewayBrowserClient);
    expect(showNotification.mock.calls.map(([title]) => title)).toEqual([
      "Verified 1",
      "Verified 2",
    ]);
    expect(await queued()).toBe(0);
  });
  it("rejects recovered content for another recipient without display, ACK or replay advancement", async () => {
    const m = await messages(1);
    await resetDatabase();
    const request = vi.fn(async () => ({
      snapshotId,
      items: [
        {
          object_id: m.rows[0]!.object_id,
          expires_at_ms: m.rows[0]!.expires_at_ms,
          value: { ...m.values.get(m.rows[0]!.object_id), recipientId: "other" },
        },
      ],
    }));
    await expect(
      receivePendingPqcPushes({
        request,
        pushRecoveryReady: true,
      } as unknown as GatewayBrowserClient),
    ).rejects.toThrow("binding");
    expect(showNotification).not.toHaveBeenCalled();
    expect(await queued()).toBe(0);
    expect(request).toHaveBeenCalledTimes(1);
  });
  it.each(["payload", "ed25519_sig", "mldsa65_sig"] as const)(
    "rejects corrupt recovered %s without burning replay state",
    async (field) => {
      const m = await messages(1);
      await resetDatabase();
      const row = m.rows[0]!;
      const original = m.values.get(row.object_id)!;
      let corrupt = true;
      const request = vi.fn(async (method: string) => {
        if (method === "push.pqc.keys") {
          return m.keys;
        }
        if (method === "push.pqc.pending.ack") {
          return { acknowledged: true };
        }
        if (method === "push.pqc.pending") {
          const value = {
            payload: original.payload,
            envelope: { ...original.envelope },
            recipientId: m.keys.recipientId,
          };
          if (corrupt) {
            if (field === "payload") {
              value.payload += " ";
            } else {
              const bytes = Uint8Array.from(
                atob(value.envelope[field].replaceAll("-", "+").replaceAll("_", "/")),
                (c) => c.charCodeAt(0),
              );
              bytes[0] = bytes[0]! ^ 1;
              value.envelope[field] = b64(bytes);
            }
          }
          return {
            snapshotId,
            items: [{ object_id: row.object_id, expires_at_ms: row.expires_at_ms, value }],
          };
        }
        throw new Error("unexpected method");
      });
      const client = { request, pushRecoveryReady: true } as unknown as GatewayBrowserClient;
      await expect(receivePendingPqcPushes(client)).rejects.toThrow("could not be verified");
      expect(showNotification).not.toHaveBeenCalled();
      expect(await queued()).toBe(0);
      expect(request.mock.calls.some(([method]) => method === "push.pqc.pending.ack")).toBe(false);
      corrupt = false;
      await receivePendingPqcPushes(client);
      expect(showNotification).toHaveBeenCalledTimes(1);
      expect(await queued()).toBe(0);
    },
  );
  it("lets verified recovery replace an unverified wake when the local wake budget is full", async () => {
    const m = await messages(1);
    await resetDatabase();
    const row = m.rows[0]!;
    await queued(
      Array.from({ length: 64 }, (_, i) => ({
        version: 1,
        object_id: "ffffffff-ffff-4fff-8fff-" + String(i).padStart(12, "0"),
        token: "A".repeat(43),
        expires_at_ms: Date.now() + 300000,
      })),
    );
    const request = vi.fn(async (method: string) => {
      if (method === "push.pqc.pending") {
        return {
          snapshotId,
          items: [
            {
              object_id: row.object_id,
              expires_at_ms: row.expires_at_ms,
              value: { ...m.values.get(row.object_id), recipientId: m.keys.recipientId },
            },
          ],
        };
      }
      if (method === "push.pqc.keys") {
        return m.keys;
      }
      if (method === "push.pqc.pending.ack") {
        return { acknowledged: true };
      }
      throw new Error("test invalid relay wake");
    });
    await expect(
      receivePendingPqcPushes({
        request,
        pushRecoveryReady: true,
      } as unknown as GatewayBrowserClient),
    ).rejects.toThrow("could not be verified");
    expect(showNotification).toHaveBeenCalledTimes(1);
    expect(await queued()).toBe(63);
  });
  it("does not infer the server clock from reference expiry, while retaining signed lifetime checks", async () => {
    const m = await messages(1);
    await resetDatabase();
    const row = m.rows[0]!;
    const request = vi.fn(async (method: string) => {
      if (method === "push.pqc.pending") {
        return {
          snapshotId,
          items: [
            {
              object_id: row.object_id,
              expires_at_ms: row.expires_at_ms + 90000,
              value: { ...m.values.get(row.object_id), recipientId: m.keys.recipientId },
            },
          ],
        };
      }
      if (method === "push.pqc.keys") {
        return m.keys;
      }
      if (method === "push.pqc.pending.ack") {
        return { acknowledged: true };
      }
      throw new Error("unexpected capability path");
    });
    await receivePendingPqcPushes({
      request,
      pushRecoveryReady: true,
    } as unknown as GatewayBrowserClient);
    expect(showNotification).toHaveBeenCalledTimes(1);
    expect(await queued()).toBe(0);
  });
  it("holds a higher capability sequence during a negotiated snapshot outage and later displays the full ordered batch", async () => {
    const m = await messages(2);
    await resetDatabase();
    await queued([m.rows[1]!]);
    let unavailable = true;
    const request = vi.fn(async (method: string, params: Record<string, unknown>) => {
      if (method === "push.pqc.pending") {
        if (unavailable) {
          throw new Error("test snapshot unavailable");
        }
        return {
          snapshotId,
          items: m.rows.map((row) => ({
            object_id: row.object_id,
            expires_at_ms: row.expires_at_ms,
            value: { ...m.values.get(row.object_id), recipientId: m.keys.recipientId },
          })),
        };
      }
      if (method === "push.pqc.keys") {
        return m.keys;
      }
      if (method === "push.pqc.pending.ack") {
        return { acknowledged: true };
      }
      if (method === "push.pqc.redeem") {
        return params.acknowledge
          ? { acknowledged: true }
          : m.values.get(params.object_id as string);
      }
      throw new Error("unexpected method");
    });
    const client = { request, pushRecoveryReady: true } as unknown as GatewayBrowserClient;
    await expect(receivePendingPqcPushes(client)).rejects.toThrow("snapshot unavailable");
    expect(showNotification).not.toHaveBeenCalled();
    expect(await queued()).toBe(1);
    unavailable = false;
    await receivePendingPqcPushes(client);
    expect(showNotification.mock.calls.map(([title]) => title)).toEqual([
      "Verified 1",
      "Verified 2",
    ]);
    expect(await queued()).toBe(0);
  });
  it.each(["unavailable", "forbidden", "rate limit"])(
    "keeps a valid capability wake usable when discovery is %s",
    async (reason) => {
      const m = await messages(1);
      const request = vi.fn(async (method: string, params: Record<string, unknown>) => {
        if (method === "push.pqc.pending") {
          throw new Error("test discovery " + reason);
        }
        if (method === "push.pqc.keys") {
          return m.keys;
        }
        if (method === "push.pqc.redeem") {
          return params.acknowledge
            ? { acknowledged: true }
            : m.values.get(params.object_id as string);
        }
        throw new Error("unexpected recovery ACK");
      });
      await receivePendingPqcPushes({
        request,
        pushRecoveryReady: false,
      } as unknown as GatewayBrowserClient);
      expect(showNotification).toHaveBeenCalledTimes(1);
      expect(await queued()).toBe(0);
      expect(request.mock.calls.some(([method]) => method === "push.pqc.pending.ack")).toBe(false);
    },
  );
  it("retries an existing capability inbox when the new discovery service fails", async () => {
    const m = await messages(1);
    let discoveryFails = false;
    const request = vi.fn(async (method: string, params: Record<string, unknown>) => {
      if (method === "push.pqc.pending") {
        if (discoveryFails) {
          throw new Error("test discovery outage");
        }
        return { snapshotId, items: [] };
      }
      if (method === "push.pqc.keys") {
        return m.keys;
      }
      if (method === "push.pqc.redeem") {
        return params.acknowledge
          ? { acknowledged: true }
          : m.values.get(params.object_id as string);
      }
      throw new Error("unexpected method");
    });
    const client = { request, pushRecoveryReady: false } as unknown as GatewayBrowserClient;
    showNotification.mockRejectedValueOnce(new Error("test OS presentation failure"));
    await expect(receivePendingPqcPushes(client)).rejects.toThrow();
    expect(await queued()).toBe(1);
    discoveryFails = true;
    await receivePendingPqcPushes(client);
    expect(await queued()).toBe(0);
    expect(showNotification).toHaveBeenCalledTimes(2);
    expect(
      request.mock.calls.filter(
        ([method, params]) => method === "push.pqc.redeem" && !params.acknowledge,
      ),
    ).toHaveLength(1);
  });
  it("uses recovery authorization for a snapshot member even when its legacy capability is valid", async () => {
    const m = await messages(1);
    const row = m.rows[0]!;
    await queued([row]);
    let failAck = true;
    const request = vi.fn(async (method: string) => {
      if (method === "push.pqc.pending") {
        return {
          snapshotId,
          items: [
            {
              object_id: row.object_id,
              expires_at_ms: row.expires_at_ms,
              value: { ...m.values.get(row.object_id), recipientId: m.keys.recipientId },
            },
          ],
        };
      }
      if (method === "push.pqc.keys") {
        return m.keys;
      }
      if (method === "push.pqc.redeem") {
        return m.values.get(row.object_id);
      }
      if (method === "push.pqc.pending.ack") {
        if (failAck) {
          throw new Error("test current recovery authorization rejected");
        }
        return { acknowledged: true };
      }
      throw new Error("unexpected push RPC");
    });
    const client = { request, pushRecoveryReady: true } as unknown as GatewayBrowserClient;
    await expect(receivePendingPqcPushes(client)).rejects.toThrow();
    expect(await queued()).toBe(1);
    expect(request.mock.calls.some(([method]) => method === "push.pqc.redeem")).toBe(false);
    failAck = false;
    await receivePendingPqcPushes(client);
    expect(await queued()).toBe(0);
    expect(showNotification).toHaveBeenCalledTimes(1);
    expect(request.mock.calls.some(([method]) => method === "push.pqc.redeem")).toBe(false);
  });
  it("does not degrade a tokenless recovered inbox when current recovery authorization fails", async () => {
    const m = await messages(1);
    await resetDatabase();
    let denyDiscovery = false;
    let failAck = true;
    const request = vi.fn(async (method: string) => {
      if (method === "push.pqc.pending") {
        if (denyDiscovery) {
          throw new Error("test recovery proof denied");
        }
        return {
          snapshotId,
          items: m.rows.map((row) => ({
            object_id: row.object_id,
            expires_at_ms: row.expires_at_ms,
            value: { ...m.values.get(row.object_id), recipientId: m.keys.recipientId },
          })),
        };
      }
      if (method === "push.pqc.keys") {
        return m.keys;
      }
      if (method === "push.pqc.pending.ack") {
        if (failAck) {
          throw new Error("test lost ACK");
        }
        return { acknowledged: true };
      }
      throw new Error("tokenless recovery cannot use capability RPC");
    });
    const client = { request, pushRecoveryReady: true } as unknown as GatewayBrowserClient;
    await expect(receivePendingPqcPushes(client)).rejects.toThrow();
    expect(await queued()).toBe(1);
    const priorAckCalls = request.mock.calls.filter(
      ([method]) => method === "push.pqc.pending.ack",
    ).length;
    denyDiscovery = true;
    await expect(receivePendingPqcPushes(client)).rejects.toThrow("proof denied");
    expect(showNotification).toHaveBeenCalledTimes(1);
    expect(await queued()).toBe(1);
    expect(request.mock.calls.filter(([method]) => method === "push.pqc.pending.ack")).toHaveLength(
      priorAckCalls,
    );
    denyDiscovery = false;
    failAck = false;
    await receivePendingPqcPushes(client);
    expect(await queued()).toBe(0);
    expect(showNotification).toHaveBeenCalledTimes(1);
  });
  it("discards a partial discovery batch when a later page fails and preserves legacy ordering", async () => {
    const m = await messages(2);
    await resetDatabase();
    await queued([m.rows[0]!]);
    let failSecondPage = true;
    const row = m.rows[1]!;
    const request = vi.fn(async (method: string, params: Record<string, unknown>) => {
      if (method === "push.pqc.pending") {
        if (failSecondPage && params.after) {
          throw new Error("test later-page loss");
        }
        return {
          snapshotId,
          items: [
            {
              object_id: row.object_id,
              expires_at_ms: row.expires_at_ms,
              value: { ...m.values.get(row.object_id), recipientId: m.keys.recipientId },
            },
          ],
          ...(failSecondPage ? { next: { snapshotId, offset: 1 } } : {}),
        };
      }
      if (method === "push.pqc.keys") {
        return m.keys;
      }
      if (method === "push.pqc.redeem") {
        return params.acknowledge
          ? { acknowledged: true }
          : m.values.get(params.object_id as string);
      }
      if (method === "push.pqc.pending.ack") {
        return { acknowledged: true };
      }
      throw new Error("unexpected method");
    });
    const client = { request, pushRecoveryReady: true } as unknown as GatewayBrowserClient;
    await expect(receivePendingPqcPushes(client)).rejects.toThrow("later-page loss");
    expect(showNotification).not.toHaveBeenCalled();
    failSecondPage = false;
    await receivePendingPqcPushes(client);
    expect(showNotification.mock.calls.map(([title]) => title)).toEqual([
      "Verified 1",
      "Verified 2",
    ]);
    expect(await queued()).toBe(0);
  });
});
