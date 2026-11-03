import { verifyAsync } from "@noble/ed25519";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { assertPushKeyPolicy, type PushKeyPolicy } from "../../../src/shared/push-key-policy.ts";
import {
  MAX_PUSH_RECOVERY_PAGE_BYTES,
  MAX_PUSH_RECOVERY_PAGE_ITEMS,
  MAX_PUSH_RECOVERY_PAGES,
} from "../../../src/shared/push-recovery.ts";
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
  keyPolicyVersion: 1;
  keyPolicy: { ed25519: PushKeyPolicy; mldsa65: PushKeyPolicy };
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

function validateBrowserPushKeys(keys: PushV2Keys, nowMs: number): void {
  integer(nowMs);
  if (!keys || keys.keyPolicyVersion !== 1) {
    throw new Error("push key policy version unavailable");
  }
  text(keys.senderId);
  text(keys.keyIdEd25519, 128);
  text(keys.keyIdMldsa65, 128);
  decode(keys.ed25519PublicKeyBase64Url, 32);
  decode(keys.mldsa65PublicKeyBase64Url, 1952);
  assertPushKeyPolicy(
    keys.keyPolicy?.ed25519,
    "ed25519",
    keys.keyIdEd25519,
    keys.senderId,
    keys.ed25519PublicKeyBase64Url,
    nowMs,
  );
  assertPushKeyPolicy(
    keys.keyPolicy?.mldsa65,
    "ml-dsa-65",
    keys.keyIdMldsa65,
    keys.senderId,
    keys.mldsa65PublicKeyBase64Url,
    nowMs,
  );
}

export async function verifyBrowserPush(
  payload: string,
  e: PushV2Envelope,
  keys: PushV2Keys,
  expectedRecipientId: string,
  accept: (e: PushV2Envelope) => Promise<boolean>,
  nowMs = Date.now(),
): Promise<void> {
  validateBrowserPushKeys(keys, nowMs);
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
type PendingPush = {
  version: 1;
  object_id: string;
  token?: string;
  recovery?: true;
  expires_at_ms: number;
  inbox?: {
    payload: string;
    envelope: PushV2Envelope;
    displayed?: true;
    leaseUntil?: number;
    leaseToken?: string;
  };
};

async function acceptDurably(
  e: PushV2Envelope,
  reference: PendingPush,
  payload: string,
): Promise<boolean> {
  const db = await openPushDatabase();
  return new Promise((resolve, reject) => {
    const tx = db.transaction(["replay", "wakes"], "readwrite");
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
          // Replay and the verified inbox share one commit. A crash before
          // presentation leaves work to drain instead of burning a valid retry.
          tx.objectStore("wakes").put({ ...reference, inbox: { payload, envelope: e } });
          accepted = true;
        };
        const commitBounded = () => {
          const wakes = tx.objectStore("wakes");
          const all = wakes.getAll();
          all.addEventListener(
            "success",
            () => {
              const live = (all.result as PendingPush[]).filter(
                (row) => row.expires_at_ms > Date.now(),
              );
              for (const row of all.result as PendingPush[]) {
                if (row.expires_at_ms <= Date.now()) {
                  wakes.delete(row.object_id);
                }
              }
              if (!live.some((row) => row.object_id === reference.object_id) && live.length >= 64) {
                // Verified work may replace an unverified relay wake, never another committed inbox.
                const disposable = live.find((row) => !row.inbox);
                if (!disposable) {
                  return;
                }
                wakes.delete(disposable.object_id);
              }
              commit();
            },
            { once: true },
          );
        };
        if (prior) {
          commitBounded();
        } else {
          // Never evict a peer high-water mark: that would permit old replay.
          const count = store.count();
          count.addEventListener(
            "success",
            () => {
              if (count.result < 10000) {
                commitBounded();
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

async function updatePendingPush(
  reference: PendingPush,
  change: (row: PendingPush) => PendingPush | undefined,
): Promise<void> {
  const db = await openPushDatabase();
  try {
    await new Promise<void>((resolve, reject) => {
      const tx = db.transaction("wakes", "readwrite");
      const store = tx.objectStore("wakes");
      const read = store.get(reference.object_id);
      read.addEventListener(
        "success",
        () => {
          const row = read.result as PendingPush | undefined;
          if (
            !row ||
            row.token !== reference.token ||
            row.expires_at_ms !== reference.expires_at_ms
          ) {
            return;
          }
          try {
            const updated = change(row);
            if (updated) {
              store.put(updated);
            } else {
              store.delete(reference.object_id);
            }
          } catch {
            tx.abort();
          }
        },
        { once: true },
      );
      tx.addEventListener("complete", () => resolve(), { once: true });
      tx.addEventListener("abort", () => reject(new Error("push inbox update failed")), {
        once: true,
      });
    });
  } finally {
    db.close();
  }
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

class PushPolicyRefreshError extends Error {}

async function discoverPendingPushes(
  client: GatewayBrowserClient,
  recipientId: string,
  known: PendingPush[],
): Promise<{
  references: PendingPush[];
  recovered: Map<string, { payload: string; envelope: PushV2Envelope }>;
}> {
  // Publish no partial discovery state: later-page failures must not advance replay or upgrade a legacy wake.
  const references = [...known];
  const recovered = new Map<string, { payload: string; envelope: PushV2Envelope }>();
  const seen = new Set<string>();
  let snapshotId: string | undefined;
  let after: { snapshotId: string; offset: number } | undefined;
  for (let pageIndex = 0; pageIndex < MAX_PUSH_RECOVERY_PAGES; pageIndex++) {
    const page = (await client.request("push.pqc.pending", after ? { after } : {})) as {
      snapshotId: string;
      items: Array<{
        object_id: string;
        expires_at_ms: number;
        value: { payload: string; envelope: PushV2Envelope; recipientId: string };
      }>;
      next?: { snapshotId: string; offset: number };
    };
    if (
      !page ||
      typeof page.snapshotId !== "string" ||
      !/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(page.snapshotId) ||
      (snapshotId !== undefined && snapshotId !== page.snapshotId) ||
      !Array.isArray(page.items) ||
      page.items.length > MAX_PUSH_RECOVERY_PAGE_ITEMS ||
      utf8.encode(JSON.stringify(page)).length > MAX_PUSH_RECOVERY_PAGE_BYTES
    ) {
      throw new Error("Invalid secure push recovery response.");
    }
    snapshotId = page.snapshotId;
    for (const item of page.items) {
      if (
        !item ||
        typeof item.object_id !== "string" ||
        !/^[0-9a-f-]{36}$/.test(item.object_id) ||
        seen.has(item.object_id) ||
        !Number.isSafeInteger(item.expires_at_ms) ||
        item.expires_at_ms <= Date.now() ||
        item.value?.recipientId !== recipientId
      ) {
        throw new Error("Invalid secure push recovery binding.");
      }
      seen.add(item.object_id);
      const existing = references.find((row) => row.object_id === item.object_id);
      if (existing && existing.expires_at_ms !== item.expires_at_ms) {
        throw new Error("Conflicting secure push recovery reference.");
      }
      if (existing) {
        // Snapshot membership selects request-time authorization for both read
        // and ACK, even when an earlier relay wake has a valid bearer token.
        // Replace this local record; a later-page failure publishes no upgrade.
        references[references.indexOf(existing)] = { ...existing, recovery: true };
      } else {
        references.push({
          version: 1,
          object_id: item.object_id,
          expires_at_ms: item.expires_at_ms,
          recovery: true,
        });
      }
      recovered.set(item.object_id, item.value);
    }
    if (!page.next) {
      break;
    }
    if (
      page.items.length === 0 ||
      page.next.snapshotId !== snapshotId ||
      !Number.isSafeInteger(page.next.offset) ||
      page.next.offset <= (after?.offset ?? 0) ||
      page.next.offset > 100 ||
      pageIndex === MAX_PUSH_RECOVERY_PAGES - 1
    ) {
      throw new Error("Invalid secure push recovery cursor.");
    }
    after = page.next;
  }
  return { references, recovered };
}

async function receivePending(client: GatewayBrowserClient): Promise<void> {
  const db = await openPushDatabase();
  let references: PendingPush[];
  try {
    references = await new Promise<PendingPush[]>((resolve, reject) => {
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
  const identity = await loadOrCreateDeviceIdentity();
  if (client.pushRecoveryRequired && !client.pushRecoveryReady) {
    throw new Error("Secure push recovery requires an approved device-authenticated reconnect.");
  }
  let recovered = new Map<string, { payload: string; envelope: PushV2Envelope }>();
  if (client.pushRecoveryReady) {
    // In negotiated strict mode the complete snapshot is required before any
    // legacy capability can advance replay state past an unseen older object.
    const discovered = await discoverPendingPushes(client, identity.deviceId, references);
    references = discovered.references;
    recovered = discovered.recovered;
  } else {
    // Servers/sessions without negotiated recovery retain their original
    // per-object path. Tokenless inboxes never degrade into that legacy path.
    references = references.filter(
      (reference) =>
        !reference.recovery &&
        typeof reference.token === "string" &&
        /^[A-Za-z0-9_-]{43}$/.test(reference.token),
    );
  }
  if (references.length === 0) {
    return;
  }
  const freshKeys = async (): Promise<PushV2Keys> => {
    try {
      const keys = (await client.request("push.pqc.keys", {})) as PushV2Keys & {
        recipientId: string;
      };
      if (keys.recipientId !== identity.deviceId) {
        throw new Error("push session identity mismatch");
      }
      // Validate the whole authenticated response inside the refresh boundary.
      // Malformed policy/key metadata must not be mistaken for a bad message.
      validateBrowserPushKeys(keys, Date.now());
      return keys;
    } catch (cause) {
      throw new PushPolicyRefreshError("Secure push key policy refresh failed.", { cause });
    }
  };
  const values: Array<{ reference: PendingPush; payload: string; envelope: PushV2Envelope }> = [];
  let rejected = false;
  for (const reference of references) {
    try {
      const expiresAtMs = reference.expires_at_ms;
      if (!Number.isSafeInteger(expiresAtMs) || (expiresAtMs as number) <= Date.now()) {
        await updatePendingPush(reference, () => undefined);
        continue;
      }
      // Send only protocol fields; the trusted local inbox is never RPC input.
      const descriptor = {
        version: reference.version,
        object_id: reference.object_id,
        token: reference.token,
        expires_at_ms: reference.expires_at_ms,
      };
      let selectedReference = reference;
      let value = reference.inbox;
      if (!value) {
        if (reference.recovery) {
          value = recovered.get(reference.object_id);
        } else {
          try {
            value = (await client.request("push.pqc.redeem", descriptor)) as {
              payload: string;
              envelope: PushV2Envelope;
            };
          } catch (error) {
            value = recovered.get(reference.object_id);
            if (!value) {
              throw error;
            }
            // A bad relay capability cannot hide a separately authorized, signed object.
            selectedReference = {
              version: 1,
              object_id: reference.object_id,
              expires_at_ms: reference.expires_at_ms,
              recovery: true,
            };
          }
        }
      }
      if (!value) {
        throw new Error("push recovery object unavailable");
      }
      // Refresh per object, including inbox recovery; a batch snapshot can outlive revocation.
      const keys = await freshKeys();
      // Verify before ordering; a forged sequence must not control the drain.
      await verifyBrowserPush(
        value.payload,
        value.envelope,
        keys,
        identity.deviceId,
        async () => true,
      );
      values.push({
        reference: selectedReference,
        payload: value.payload,
        envelope: value.envelope,
      });
    } catch (error) {
      // A policy outage is shared state, not an invalid individual wake. Do not
      // advance replay watermarks beyond work whose policy could not be refreshed.
      if (error instanceof PushPolicyRefreshError) {
        throw error;
      }
      rejected = true;
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
      if (!value.reference.inbox) {
        const keys = await freshKeys();
        await verifyBrowserPush(value.payload, value.envelope, keys, identity.deviceId, (e) =>
          acceptDurably(e, value.reference, value.payload),
        );
      }
      let claimed = false;
      let displayed = false;
      const leaseToken = crypto.randomUUID();
      await updatePendingPush(value.reference, (row) => {
        displayed = row.inbox?.displayed === true;
        if (!displayed && row.inbox && (row.inbox.leaseUntil ?? 0) <= Date.now()) {
          row.inbox.leaseUntil = Date.now() + 30_000;
          row.inbox.leaseToken = leaseToken;
          claimed = true;
        }
        return row;
      });
      if (!displayed && !claimed) {
        continue;
      }
      if (!displayed) {
        try {
          const registration = await navigator.serviceWorker.ready;
          if (Date.now() >= value.reference.expires_at_ms) {
            throw new Error("expired push reference");
          }
          // Revalidate after asynchronous worker startup and before business presentation.
          // Revocation committed after this response can still race OS notification delivery.
          const keys = await freshKeys();
          await verifyBrowserPush(
            value.payload,
            value.envelope,
            keys,
            identity.deviceId,
            async () => true,
          );
          const tagInput = JSON.stringify([
            value.envelope.sender_id,
            identity.deviceId,
            value.envelope.sequence,
            value.envelope.nonce,
          ]);
          const tag = base64(
            new Uint8Array(await crypto.subtle.digest("SHA-256", utf8.encode(tagInput))),
          );
          // Presentation is outside IndexedDB. Stable tags replace the same
          // notification if a crash precedes its local completion marker.
          await registration.showNotification(payload.title, {
            body: payload.body as string | undefined,
            tag: `openclaw-verified-push-${tag}`,
            data: { url: registration.scope, explicitUrl: false },
          });
          await updatePendingPush(value.reference, (row) => {
            if (row.inbox?.leaseToken === leaseToken) {
              row.inbox.displayed = true;
              row.inbox.leaseUntil = 0;
              delete row.inbox.leaseToken;
            } else {
              throw new Error("push presentation lease replaced");
            }
            return row;
          });
        } catch (error) {
          await updatePendingPush(value.reference, (row) => {
            if (row.inbox?.leaseToken === leaseToken) {
              row.inbox.leaseUntil = 0;
              delete row.inbox.leaseToken;
            }
            return row;
          });
          throw error;
        }
      }
      await client.request(value.reference.recovery ? "push.pqc.pending.ack" : "push.pqc.redeem", {
        version: value.reference.version,
        object_id: value.reference.object_id,
        expires_at_ms: value.reference.expires_at_ms,
        ...(value.reference.recovery ? {} : { token: value.reference.token, acknowledge: true }),
      });
      await updatePendingPush(value.reference, () => undefined);
    } catch (error) {
      if (error instanceof PushPolicyRefreshError) {
        throw error;
      }
      // A bad wake cannot prevent unrelated valid notifications from being processed.
      rejected = true;
    }
  }
  if (rejected) {
    throw new Error("One or more secure notifications could not be verified.");
  }
}
