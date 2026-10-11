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
  return { keys, values, rows };
}
describe("real browser durable wake retries", () => {
  it("keeps four quota failures after 60 successful redemptions and displays them after retry", async () => {
    const m = await messages(64);
    let attempts = 0;
    const client = {
      request: vi.fn(async (method: string, p: Record<string, unknown>) => {
        if (method === "push.pqc.keys") {
          return m.keys;
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
  it("keeps an unconsumed reference on connection failure and discards bad consumed content", async () => {
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
    expect(await queued()).toBe(0);
    expect(showNotification).not.toHaveBeenCalled();
  });
  it("removes expired references without trying to redeem or display them", async () => {
    const m = await messages(1);
    await queued([{ ...m.rows[0], expires_at_ms: Date.now() - 1 }]);
    const request = vi.fn(async () => m.keys);
    await receivePendingPqcPushes({ request } as unknown as GatewayBrowserClient);
    expect(request).toHaveBeenCalledTimes(1);
    expect(await queued()).toBe(0);
    expect(showNotification).not.toHaveBeenCalled();
  });
});
