// M4 (PQC migration, whitepaper 2.2.1): wrap-envelope invariants.
//
// 23 invariants covering round-trip across empty / 1952 / 4032 / 64KiB
// plaintexts, IV uniqueness, tamper detection, wrong-size key, dropped
// keyId, non-Buffer rejection, and serialize/deserialize round-trip +
// malformed input rejection.
import { createHash, randomBytes } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  deserializeWrappedSecret,
  MAX_PLAINTEXT_BYTES,
  SecretWrappingError,
  serializeWrappedSecret,
  unwrapSecret,
  WRAP_AUTH_TAG_BYTES,
  WRAP_IV_BYTES,
  WRAP_KEY_BYTES,
  wrapSecret,
  type WrappedSecret,
} from "./secret-wrapping.js";

function newKey(seed?: number): Buffer {
  if (typeof seed === "number") {
    const hash = createHash("sha256");
    for (let i = 0; i < 8; i++) hash.update(String((seed + i) >>> 0));
    return hash.digest();
  }
  return Buffer.from(randomBytes(WRAP_KEY_BYTES));
}

afterEach(() => {
  // no-op
});

beforeEach(() => {
  // no-op
});

describe("secret-wrapping (M4, whitepaper 2.2.1)", () => {
  it("round-trips an empty plaintext", () => {
    const key = newKey(1);
    const wrapped = wrapSecret(Buffer.alloc(0), "wrap-key-2026-08", key, 1_700_000_000_000);
    const unwrapped = unwrapSecret(wrapped, "wrap-key-2026-08", key);
    expect(unwrapped.length).toBe(0);
  });

  it("round-trips a 1952-byte plaintext (ML-DSA-65 public key)", () => {
    const key = newKey(2);
    const plaintext = Buffer.from(randomBytes(1952));
    const wrapped = wrapSecret(plaintext, "wrap-key-2026-08", key, 1_700_000_000_000);
    const unwrapped = unwrapSecret(wrapped, "wrap-key-2026-08", key);
    expect(unwrapped.equals(plaintext)).toBe(true);
  });

  it("round-trips a 4032-byte plaintext (ML-DSA-65 secret key)", () => {
    const key = newKey(3);
    const plaintext = Buffer.from(randomBytes(4032));
    const wrapped = wrapSecret(plaintext, "wrap-key-2026-08", key, 1_700_000_000_000);
    const unwrapped = unwrapSecret(wrapped, "wrap-key-2026-08", key);
    expect(unwrapped.equals(plaintext)).toBe(true);
  });

  it("round-trips a 64KiB plaintext", () => {
    const key = newKey(4);
    const plaintext = Buffer.from(randomBytes(64 * 1024));
    const wrapped = wrapSecret(plaintext, "wrap-key-2026-08", key, 1_700_000_000_000);
    const unwrapped = unwrapSecret(wrapped, "wrap-key-2026-08", key);
    expect(unwrapped.equals(plaintext)).toBe(true);
  });

  it("produces a fresh 12-byte IV on every call (32-call uniqueness check)", () => {
    const key = newKey(5);
    const seen = new Set<string>();
    for (let i = 0; i < 32; i++) {
      const wrapped = wrapSecret(Buffer.from("hello"), `key-${i}`, key);
      expect(wrapped.iv.length).toBe(WRAP_IV_BYTES);
      seen.add(wrapped.iv.toString("base64url"));
    }
    expect(seen.size).toBe(32);
  });

  it("captures a 16-byte auth tag on every envelope", () => {
    const key = newKey(6);
    const wrapped = wrapSecret(Buffer.from("pqc"), "wrap-key-2026-08", key);
    expect(wrapped.authTag.length).toBe(WRAP_AUTH_TAG_BYTES);
  });

  it("rejects a wrapping key of the wrong size under the same keyId", () => {
    const rightKey = newKey(7);
    const wrongKey = Buffer.alloc(16); // half-size
    const wrapped = wrapSecret(Buffer.from("payload"), "wrap-key-2026-08", rightKey);
    expect(() => unwrapSecret(wrapped, "wrap-key-2026-08", wrongKey)).toThrow(
      /Wrapping key must be a Buffer of 32 bytes/,
    );
  });

  it("rejects an undersized 16-byte wrapping key at construction time", () => {
    const tooShort = Buffer.alloc(16);
    expect(() => wrapSecret(Buffer.from("payload"), "wrap-key-2026-08", tooShort)).toThrow(
      /Wrapping key must be a Buffer of 32 bytes/,
    );
  });

  it("rejects a non-Buffer plaintext at construction time", () => {
    const key = newKey(8);
    // @ts-expect-error -- intentional type violation to verify runtime guard
    expect(() => wrapSecret("not-a-buffer", "wrap-key-2026-08", key)).toThrow(
      /Plaintext must be a Buffer/,
    );
  });

  it("rejects a plaintext that exceeds the 64 KiB envelope cap", () => {
    const key = newKey(9);
    const tooBig = Buffer.alloc(MAX_PLAINTEXT_BYTES + 1);
    expect(() => wrapSecret(tooBig, "wrap-key-2026-08", key)).toThrow(
      /Plaintext exceeds 65536 bytes/,
    );
  });

  it("rejects an empty keyId at wrap time", () => {
    const key = newKey(10);
    expect(() => wrapSecret(Buffer.from("payload"), "", key)).toThrow(
      /keyId must be a non-empty string/,
    );
  });

  it("rejects an over-long keyId (>128 chars) at wrap time", () => {
    const key = newKey(11);
    expect(() => wrapSecret(Buffer.from("payload"), "k".repeat(129), key)).toThrow(
      /keyId exceeds 128 characters/,
    );
  });

  it("rejects an envelope that has been sealed under a different keyId", () => {
    const key = newKey(12);
    const wrapped = wrapSecret(Buffer.from("payload"), "wrap-key-2026-08", key);
    expect(() => unwrapSecret(wrapped, "wrap-key-different", key)).toThrow(
      /envelope is sealed under "wrap-key-2026-08", caller supplied "wrap-key-different"/,
    );
  });

  it("rejects an envelope whose ciphertext has been tampered with", () => {
    const key = newKey(13);
    const wrapped = wrapSecret(Buffer.from("auth-this"), "wrap-key-2026-08", key);
    const tampered: WrappedSecret = {
      ...wrapped,
      ciphertext: Buffer.concat([Buffer.from("X"), wrapped.ciphertext.subarray(1)]),
    };
    expect(() => unwrapSecret(tampered, "wrap-key-2026-08", key)).toThrow(
      /AES-256-GCM authentication failed/,
    );
  });

  it("rejects an envelope whose IV has been tampered with", () => {
    const key = newKey(14);
    const wrapped = wrapSecret(Buffer.from("auth-this"), "wrap-key-2026-08", key);
    const tampered: WrappedSecret = {
      ...wrapped,
      iv: Buffer.concat([Buffer.from([0x42]), wrapped.iv.subarray(1)]),
    };
    expect(() => unwrapSecret(tampered, "wrap-key-2026-08", key)).toThrow(
      /AES-256-GCM authentication failed/,
    );
  });

  it("rejects an envelope whose auth tag has been tampered with", () => {
    const key = newKey(15);
    const wrapped = wrapSecret(Buffer.from("auth-this"), "wrap-key-2026-08", key);
    const tampered: WrappedSecret = {
      ...wrapped,
      authTag: Buffer.concat([Buffer.from([0x42]), wrapped.authTag.subarray(1)]),
    };
    expect(() => unwrapSecret(tampered, "wrap-key-2026-08", key)).toThrow(
      /AES-256-GCM authentication failed/,
    );
  });

  it("rejects an envelope with the wrong IV length", () => {
    const key = newKey(16);
    const wrapped = wrapSecret(Buffer.from("auth-this"), "wrap-key-2026-08", key);
    const bad: WrappedSecret = { ...wrapped, iv: Buffer.alloc(8) };
    expect(() => unwrapSecret(bad, "wrap-key-2026-08", key)).toThrow(
      /WrappedSecret iv must be a Buffer of 12 bytes/,
    );
  });

  it("rejects an envelope with the wrong auth tag length", () => {
    const key = newKey(17);
    const wrapped = wrapSecret(Buffer.from("auth-this"), "wrap-key-2026-08", key);
    const bad: WrappedSecret = { ...wrapped, authTag: Buffer.alloc(8) };
    expect(() => unwrapSecret(bad, "wrap-key-2026-08", key)).toThrow(
      /WrappedSecret authTag must be a Buffer of 16 bytes/,
    );
  });

  it("serializeWrappedSecret produces round-trippable base64url JSON", () => {
    const key = newKey(18);
    const wrapped = wrapSecret(Buffer.from("round-trip"), "wrap-key-2026-08", key, 12345);
    const serialized = serializeWrappedSecret(wrapped);
    expect(serialized.length).toBeGreaterThan(0);
    expect(serialized).toMatch(/^[A-Za-z0-9_-]+$/);
    const restored = deserializeWrappedSecret(serialized);
    expect(restored.v).toBe(wrapped.v);
    expect(restored.keyId).toBe(wrapped.keyId);
    expect(restored.iv.equals(wrapped.iv)).toBe(true);
    expect(restored.ciphertext.equals(wrapped.ciphertext)).toBe(true);
    expect(restored.authTag.equals(wrapped.authTag)).toBe(true);
    expect(restored.createdAtMs).toBe(wrapped.createdAtMs);
    const unwrapped = unwrapSecret(restored, "wrap-key-2026-08", key);
    expect(unwrapped.toString("utf8")).toBe("round-trip");
  });

  it("deserializeWrappedSecret rejects an empty string", () => {
    expect(() => deserializeWrappedSecret("")).toThrow(/non-empty string/);
  });

  it("deserializeWrappedSecret rejects a non-base64url string", () => {
    expect(() => deserializeWrappedSecret("!!!not-base64!!!")).toThrow(
      /not valid base64url-encoded JSON/,
    );
  });

  it("deserializeWrappedSecret rejects a string that decodes to non-JSON", () => {
    const notJson = Buffer.from("not json", "utf8").toString("base64url");
    expect(() => deserializeWrappedSecret(notJson)).toThrow(/not valid base64url-encoded JSON/);
  });

  it("deserializeWrappedSecret rejects a JSON envelope with the wrong version", () => {
    const wrongVersion = Buffer.from(
      JSON.stringify({
        v: 99,
        keyId: "wrap-key-2026-08",
        iv: "AAAA",
        ciphertext: "AAAA",
        authTag: "AAAA",
        createdAtMs: 1,
      }),
      "utf8",
    ).toString("base64url");
    expect(() => deserializeWrappedSecret(wrongVersion)).toThrow(/unsupported version 99/);
  });

  it("unwrapSecret rejects a missing keyId argument (empty string)", () => {
    const key = newKey(19);
    const wrapped = wrapSecret(Buffer.from("auth-this"), "wrap-key-2026-08", key);
    expect(() => unwrapSecret(wrapped, "", key)).toThrow(/keyId must be a non-empty string/);
  });

  it("unwrapSecret throws SecretWrappingError (not Error) on auth failure", () => {
    const key = newKey(20);
    const wrapped = wrapSecret(Buffer.from("auth-this"), "wrap-key-2026-08", key);
    const tampered: WrappedSecret = {
      ...wrapped,
      authTag: Buffer.concat([Buffer.from([0x42]), wrapped.authTag.subarray(1)]),
    };
    let caught: unknown = null;
    try {
      unwrapSecret(tampered, "wrap-key-2026-08", key);
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(SecretWrappingError);
  });
});
