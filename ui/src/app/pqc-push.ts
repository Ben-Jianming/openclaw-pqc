import { verifyAsync } from "@noble/ed25519";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import type { GatewayBrowserClient } from "../api/gateway.ts";
import { loadOrCreateDeviceIdentity } from "../lib/nodes/index.ts";

export type PushV2Envelope = {
  version: number;
  algorithms: string[];
  sender_id: string;
  recipient_id: string;
  key_id_ed25519: string;
  key_id_mldsa65: string;
  created_at_ms: number;
  sequence: number;
  nonce: string;
  payload_type: string;
  payload_sha256: string;
  ed25519_sig: string;
  mldsa65_sig: string;
};
export type PushV2Keys = {
  senderId: string;
  keyIdEd25519: string;
  keyIdMldsa65: string;
  ed25519PublicKeyBase64Url: string;
  mldsa65PublicKeyBase64Url: string;
};
const utf8 = new TextEncoder();
function base64(bytes: Uint8Array): string {
  return btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}
function decode(value: string, size: number): Uint8Array {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value) || value.length > 8192) {
    throw new Error("invalid push encoding");
  }
  const bytes = Uint8Array.from(atob(value.replace(/-/g, "+").replace(/_/g, "/")), (c) =>
    c.charCodeAt(0),
  );
  if (bytes.length !== size || base64(bytes) !== value) {
    throw new Error("invalid push encoding");
  }
  return bytes;
}
function text(value: string, max = 256): Uint8Array {
  if (
    typeof value !== "string" ||
    !value ||
    value !== value.normalize("NFC") ||
    value !== new TextDecoder().decode(utf8.encode(value)) ||
    utf8.encode(value).length > max
  ) {
    throw new Error("invalid push field");
  }
  return utf8.encode(value);
}
function integer(value: number): void {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new Error("invalid push integer");
  }
}
/** Independent browser encoder: fixed vectors must equal the server transcript. */
export function encodeBrowserPushTranscript(e: PushV2Envelope): Uint8Array {
  const chunks: Uint8Array[] = [utf8.encode("OpenClaw-PQC/Push/V2\0")];
  const uint = (tag: number, value: number) => {
    integer(value);
    const b = new Uint8Array(9);
    b[0] = tag;
    new DataView(b.buffer).setBigUint64(1, BigInt(value));
    chunks.push(b);
  };
  const bytes = (tag: number, value: Uint8Array) => {
    const b = new Uint8Array(5);
    b[0] = tag;
    new DataView(b.buffer).setUint32(1, value.length);
    chunks.push(b, value);
  };
  uint(1, e.version);
  bytes(2, text(e.algorithms[0]!));
  bytes(3, text(e.algorithms[1]!));
  bytes(4, text(e.sender_id));
  bytes(5, text(e.recipient_id));
  bytes(6, text(e.key_id_ed25519, 128));
  bytes(7, text(e.key_id_mldsa65, 128));
  uint(8, e.created_at_ms);
  uint(9, e.sequence);
  bytes(10, decode(e.nonce, 24));
  bytes(11, text(e.payload_type, 128));
  bytes(12, decode(e.payload_sha256, 32));
  const combined = new Uint8Array(chunks.reduce((size, b) => size + b.length, 0));
  let offset = 0;
  for (const chunk of chunks) {
    combined.set(chunk, offset);
    offset += chunk.length;
  }
  return utf8.encode(`openclaw-push-v2-binary:${base64(combined)}`);
}

export async function verifyBrowserPush(
  payload: string,
  e: PushV2Envelope,
  keys: PushV2Keys,
  expectedRecipientId: string,
  accept: (e: PushV2Envelope) => Promise<boolean>,
  nowMs = Date.now(),
): Promise<void> {
  integer(nowMs);
  if (
    typeof payload !== "string" ||
    utf8.encode(payload).length > 65536 ||
    !e ||
    utf8.encode(JSON.stringify(e)).length > 16384 ||
    e.version !== 2 ||
    !Array.isArray(e.algorithms) ||
    e.algorithms.join(",") !== "ed25519,ml-dsa-65" ||
    e.algorithms.length !== 2 ||
    e.recipient_id !== expectedRecipientId ||
    e.sender_id !== keys.senderId ||
    e.key_id_ed25519 !== keys.keyIdEd25519 ||
    e.key_id_mldsa65 !== keys.keyIdMldsa65
  ) {
    throw new Error("push identity or protocol mismatch");
  }
  integer(e.created_at_ms);
  integer(e.sequence);
  if (e.created_at_ms > nowMs + 30000 || nowMs - e.created_at_ms > 300000) {
    throw new Error("expired push");
  }
  if (
    base64(new Uint8Array(await crypto.subtle.digest("SHA-256", utf8.encode(payload)))) !==
    e.payload_sha256
  ) {
    throw new Error("push content mismatch");
  }
  const transcript = encodeBrowserPushTranscript(e);
  if (
    !(await verifyAsync(
      decode(e.ed25519_sig, 64),
      transcript,
      decode(keys.ed25519PublicKeyBase64Url, 32),
    )) ||
    !ml_dsa65.verify(
      decode(e.mldsa65_sig, 3309),
      transcript,
      decode(keys.mldsa65PublicKeyBase64Url, 1952),
    )
  ) {
    throw new Error("push signature invalid");
  }
  if (!(await accept(e))) {
    throw new Error("replayed or reordered push");
  }
}

function openPushDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open("openclaw-pqc-push-v2", 1);
    request.addEventListener(
      "upgradeneeded",
      () => {
        request.result.createObjectStore("replay");
        request.result.createObjectStore("wakes", { keyPath: "object_id" });
      },
      { once: true },
    );
    request.addEventListener("success", () => resolve(request.result), { once: true });
    request.addEventListener("error", () => reject(new Error("push security state unavailable")), {
      once: true,
    });
  });
}
async function acceptDurably(e: PushV2Envelope): Promise<boolean> {
  const db = await openPushDatabase();
  return new Promise((resolve, reject) => {
    const tx = db.transaction("replay", "readwrite");
    const store = tx.objectStore("replay");
    const key = JSON.stringify([e.sender_id, e.recipient_id]);
    let accepted = false;
    const read = store.get(key);
    read.addEventListener(
      "success",
      () => {
        const prior = read.result as
          | { sequence: number; nonces: Array<[string, number]> }
          | undefined;
        const nonces = (prior?.nonces ?? []).filter(([, expires]) => expires > Date.now());
        if (
          (prior && prior.sequence >= e.sequence) ||
          nonces.some(([nonce]) => nonce === e.nonce) ||
          nonces.length >= 1000
        ) {
          return;
        }
        const commit = () => {
          nonces.push([e.nonce, e.created_at_ms + 330000]);
          store.put({ sequence: e.sequence, nonces }, key);
          accepted = true;
        };
        if (prior) {
          commit();
        } else {
          // Never evict a peer high-water mark: that would permit old replay.
          const count = store.count();
          count.addEventListener(
            "success",
            () => {
              if (count.result < 10000) {
                commit();
              }
            },
            { once: true },
          );
        }
      },
      { once: true },
    );
    tx.addEventListener(
      "complete",
      () => {
        db.close();
        resolve(accepted);
      },
      { once: true },
    );
    tx.addEventListener(
      "abort",
      () => {
        db.close();
        reject(new Error("push replay state unavailable"));
      },
      { once: true },
    );
  });
}

const pendingReceivers = new WeakMap<GatewayBrowserClient, Promise<void>>();
/** Invoked only after the gateway handshake; concurrent wake signals share one drain. */
export function receivePendingPqcPushes(client: GatewayBrowserClient): Promise<void> {
  const pending = pendingReceivers.get(client);
  if (pending) {
    return pending;
  }
  const drain = receivePending(client).finally(() => pendingReceivers.delete(client));
  pendingReceivers.set(client, drain);
  return drain;
}

async function receivePending(client: GatewayBrowserClient): Promise<void> {
  const db = await openPushDatabase();
  let references: Array<Record<string, unknown>>;
  try {
    references = await new Promise<Array<Record<string, unknown>>>((resolve, reject) => {
      const tx = db.transaction("wakes", "readonly");
      const r = tx.objectStore("wakes").getAll();
      r.addEventListener("success", () => resolve(r.result), { once: true });
      r.addEventListener("error", () => reject(new Error("push wake state unavailable")), {
        once: true,
      });
    });
  } finally {
    db.close();
  }
  if (references.length === 0) {
    return;
  }
  const identity = await loadOrCreateDeviceIdentity();
  const keys = (await client.request("push.pqc.keys", {})) as PushV2Keys & { recipientId: string };
  if (keys.recipientId !== identity.deviceId) {
    throw new Error("push session identity mismatch");
  }
  const values: Array<{ payload: string; envelope: PushV2Envelope }> = [];
  let rejected = false;
  for (const reference of references) {
    // Unredeemed capabilities survive connection and quota failures until expiry.
    let removeReference = true;
    try {
      const expiresAtMs = reference.expires_at_ms;
      if (!Number.isSafeInteger(expiresAtMs) || (expiresAtMs as number) <= Date.now()) {
        continue;
      }
      removeReference = false;
      const value = (await client.request("push.pqc.redeem", reference)) as {
        payload: string;
        envelope: PushV2Envelope;
      };
      removeReference = true; // Successful redemption has consumed the server object.
      // Verify before ordering; a forged sequence must not control the drain.
      await verifyBrowserPush(
        value.payload,
        value.envelope,
        keys,
        identity.deviceId,
        async () => true,
      );
      values.push(value);
    } catch {
      rejected = true;
    } finally {
      if (removeReference) {
        const cleanup = await openPushDatabase();
        try {
          await new Promise<void>((resolve, reject) => {
            const tx = cleanup.transaction("wakes", "readwrite");
            tx.objectStore("wakes").delete(reference.object_id as IDBValidKey);
            tx.addEventListener("complete", () => resolve(), { once: true });
            tx.addEventListener("abort", () => reject(new Error("push wake cleanup failed")), {
              once: true,
            });
          });
        } finally {
          cleanup.close();
        }
      }
    }
  }
  // Arrival order is relay controlled; process this authenticated batch in sequence order.
  values.sort((a, b) => a.envelope.sequence - b.envelope.sequence);
  for (const value of values) {
    try {
      const payload = JSON.parse(value.payload) as { title?: unknown; body?: unknown };
      if (
        typeof payload.title !== "string" ||
        (payload.body !== undefined && typeof payload.body !== "string")
      ) {
        throw new Error("unsupported notification content");
      }
      await verifyBrowserPush(
        value.payload,
        value.envelope,
        keys,
        identity.deviceId,
        acceptDurably,
      );
      const registration = await navigator.serviceWorker.ready;
      await registration.showNotification(payload.title, {
        body: payload.body as string | undefined,
        tag: "openclaw-verified-push",
        data: { url: registration.scope, explicitUrl: false },
      });
    } catch {
      // A bad wake cannot prevent unrelated valid notifications from being processed.
      rejected = true;
    }
  }
  if (rejected) {
    throw new Error("One or more secure notifications could not be verified.");
  }
}
