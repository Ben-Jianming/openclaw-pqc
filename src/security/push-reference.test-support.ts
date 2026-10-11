// Transport fixtures use a bounded in-memory store; production always uses durable SQLite.
import { randomBytes, randomUUID } from "node:crypto";
import {
  DEFAULT_PUSH_REFERENCE_TTL_MS,
  matchesPushReferenceToken,
  hashPushReferenceToken,
  type PushReferenceDescriptor,
  type PushReferenceStore,
  type StoredSignedPush,
} from "./push-reference.js";

const PUSH_REFERENCE_VERSION = 1 as const;
type StoredEntry = StoredSignedPush & { tokenHash: string; expiresAtMs: number };

/**
 * Bounded, one-time reference store used by push transports. Redemption deletes
 * before returning, so a second request fails even if the first consumer later errors.
 */
export class InMemoryPushReferenceStore implements PushReferenceStore {
  readonly #entries = new Map<string, StoredEntry>();
  constructor(private readonly maxEntries = 10_000) {}

  create(
    value: StoredSignedPush,
    options: { nowMs?: number; ttlMs?: number } = {},
  ): PushReferenceDescriptor {
    const nowMs = options.nowMs ?? Date.now();
    const ttlMs = options.ttlMs ?? DEFAULT_PUSH_REFERENCE_TTL_MS;
    if (
      !Number.isSafeInteger(nowMs) ||
      !Number.isSafeInteger(nowMs + ttlMs) ||
      !Number.isSafeInteger(ttlMs) ||
      ttlMs <= 0 ||
      ttlMs > DEFAULT_PUSH_REFERENCE_TTL_MS
    ) {
      throw new Error("push reference TTL must be within five minutes");
    }
    this.prune(nowMs);
    if (this.#entries.size >= this.maxEntries) {
      throw new Error("push reference store capacity exceeded");
    }
    const objectId = randomUUID();
    const token = randomBytes(32).toString("base64url");
    const expiresAtMs = nowMs + ttlMs;
    this.#entries.set(objectId, {
      ...value,
      tokenHash: hashPushReferenceToken(token),
      expiresAtMs,
    });
    return {
      version: PUSH_REFERENCE_VERSION,
      object_id: objectId,
      token,
      expires_at_ms: expiresAtMs,
    };
  }

  redeem(
    descriptor: PushReferenceDescriptor,
    recipientId: string,
    nowMs = Date.now(),
  ): StoredSignedPush {
    if (descriptor.version !== PUSH_REFERENCE_VERSION) {
      throw new Error("unsupported push reference version");
    }
    const entry = this.#entries.get(descriptor.object_id);
    if (!entry) {
      throw new Error("push reference is unknown or already consumed");
    }
    if (entry.expiresAtMs !== descriptor.expires_at_ms) {
      throw new Error("push reference expiry binding failed");
    }
    if (nowMs >= entry.expiresAtMs) {
      this.#entries.delete(descriptor.object_id);
      throw new Error("push reference has expired");
    }
    if (entry.recipientId !== recipientId) {
      throw new Error("push reference recipient binding failed");
    }
    if (!matchesPushReferenceToken(entry.tokenHash, descriptor.token)) {
      throw new Error("push reference token is invalid");
    }
    this.#entries.delete(descriptor.object_id);
    return { payload: entry.payload, envelope: entry.envelope, recipientId: entry.recipientId };
  }

  discard(descriptor: PushReferenceDescriptor): void {
    this.#entries.delete(descriptor.object_id);
  }

  prune(nowMs = Date.now()): void {
    for (const [id, entry] of this.#entries) {
      if (nowMs >= entry.expiresAtMs) {
        this.#entries.delete(id);
      }
    }
  }

  get size(): number {
    return this.#entries.size;
  }
}
