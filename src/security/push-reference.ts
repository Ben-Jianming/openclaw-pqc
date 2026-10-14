import { createHash, timingSafeEqual } from "node:crypto";
import type { PushDualEnvelope } from "./push-dual-signature.js";

export const DEFAULT_PUSH_REFERENCE_TTL_MS = 5 * 60_000;

export interface PushReferenceDescriptor {
  version: 1;
  object_id: string;
  token: string;
  expires_at_ms: number;
}

export interface StoredSignedPush {
  payload: string;
  envelope: PushDualEnvelope;
  recipientId: string;
}

export interface PushReferenceStore {
  create(
    value: StoredSignedPush,
    options?: { nowMs?: number; ttlMs?: number },
  ): PushReferenceDescriptor;
  redeem(
    descriptor: PushReferenceDescriptor,
    recipientId: string,
    nowMs?: number,
  ): StoredSignedPush;
  /** Delete only after the receiver has durably retained or completed the work. */
  acknowledge(descriptor: PushReferenceDescriptor, recipientId: string, nowMs?: number): void;
  discard(descriptor: PushReferenceDescriptor): void;
}

export function hashPushReferenceToken(token: string): string {
  if (
    typeof token !== "string" ||
    !/^[A-Za-z0-9_-]{43}$/.test(token) ||
    Buffer.from(token, "base64url").toString("base64url") !== token
  ) {
    throw new Error("push reference token is not canonical base64url");
  }
  return createHash("sha256").update(token, "utf8").digest("hex");
}

export function matchesPushReferenceToken(expectedHash: string, token: string): boolean {
  const actual = Buffer.from(hashPushReferenceToken(token), "hex");
  const expected = Buffer.from(expectedHash, "hex");
  return expected.length === actual.length && timingSafeEqual(expected, actual);
}
