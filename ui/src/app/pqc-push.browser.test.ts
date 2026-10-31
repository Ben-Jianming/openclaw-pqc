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
      const client = { request } as unknown as GatewayBrowserClient;
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
      const client = { request } as unknown as GatewayBrowserClient;
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
        if (method === "push.pqc.keys") {
          return ++reads === failAt && fail ? malformed : m.keys;
        }
        if (p.acknowledge) {
          return { acknowledged: true };
        }
        return m.values.get(p.object_id as string);
      });
      const client = { request } as unknown as GatewayBrowserClient;
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
    const client = { request } as unknown as GatewayBrowserClient;
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
      request: vi.fn(async (method: string, p: Record<string, unknown>) => {
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
      request: vi.fn(async (method: string, p: Record<string, unknown>) => {
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
    const request = vi.fn(async () => m.keys);
    await receivePendingPqcPushes({ request } as unknown as GatewayBrowserClient);
    expect(request).not.toHaveBeenCalled();
    expect(await queued()).toBe(0);
    expect(showNotification).not.toHaveBeenCalled();
  });
  it("retries a failed display from the durable verified inbox without another redemption", async () => {
    const m = await messages(1);
    const request = vi.fn(async (method: string, p: Record<string, unknown>) => {
      if (method === "push.pqc.keys") {
        return m.keys;
      }
      if (p.acknowledge === true) {
        return { acknowledged: true };
      }
      return m.values.get(p.object_id as string);
    });
    const client = { request } as unknown as GatewayBrowserClient;
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
    const client = { request } as unknown as GatewayBrowserClient;
    await expect(receivePendingPqcPushes(client)).rejects.toThrow();
    expect(showNotification).toHaveBeenCalledTimes(1);
    expect(await queued()).toBe(1);
    await receivePendingPqcPushes(client);
    expect(showNotification).toHaveBeenCalledTimes(1);
    expect(await queued()).toBe(0);
  });
});
