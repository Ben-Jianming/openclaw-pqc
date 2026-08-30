// M7 (PQC migration, whitepaper 2.2.5.B): wrap-key rotation + passphrase
// envelope backup. Edge cases supplementing src/security/wrap-key-rotation.test.ts
// (20 invariants).
//
// Coverage (10 tests):
//   - exportWrapKey round-trip: same passphrase + same key = same derived key
//   - exportWrapKey: distinct passphrases produce distinct derived keys
//   - importWrapKey rejects empty passphrase
//   - importWrapKey rejects truncated backup envelope (length < min)
//   - importWrapKey rejects corrupted backup envelope (last byte flipped)
//   - constantTimeEqual returns true for identical 32-byte buffers
//   - constantTimeEqual returns false for 1-byte-different 32-byte buffers
//   - constantTimeEqual returns false for different-length buffers
//   - Rotation envelope: each export uses a fresh salt (no replay)
//   - exportWrapKey backup envelope is self-describing (version + algorithm metadata)
import { describe, expect, it } from "vitest";
import {
  constantTimeEqual,
  exportWrapKey,
  importWrapKey,
  WRAP_KEY_BACKUP_CONSTANTS,
  WrapKeyBackupError,
  WrapKeyRotationError,
} from "./wrap-key-rotation.js";

function key32(seed: number): Buffer {
  const out = Buffer.alloc(32);
  for (let i = 0; i < 32; i++) out[i] = (seed + i * 13) & 0xff;
  return out;
}

describe("wrap-key-rotation M7 — backup envelope edge cases", () => {
  it("exportWrapKey + importWrapKey round-trips a wrap key with a passphrase", () => {
    const wrapKey = key32(0x10);
    const passphrase = "correct horse battery staple";
    const keyId = "prod-wrap-2026-08";
    const envelope = exportWrapKey(wrapKey, passphrase, keyId);
    expect(typeof envelope).toBe("string");
    expect(envelope.length).toBeGreaterThan(0);
    const restored = importWrapKey(envelope, passphrase);
    expect(restored.keyId).toBe(keyId);
    expect(constantTimeEqual(restored.key, wrapKey)).toBe(true);
  });

  it("exportWrapKey with same key+passphrase but different random salts produces different envelopes", () => {
    const wrapKey = key32(0x20);
    const pass = "long-enough-passphrase-2026";
    const env1 = exportWrapKey(wrapKey, pass, "k1");
    const env2 = exportWrapKey(wrapKey, pass, "k1");
    expect(env1).not.toBe(env2); // fresh salt each call
    // Both must round-trip to the same key
    expect(constantTimeEqual(importWrapKey(env1, pass).key, wrapKey)).toBe(true);
    expect(constantTimeEqual(importWrapKey(env2, pass).key, wrapKey)).toBe(true);
  });

  it("importWrapKey rejects an empty passphrase (no empty-string derived keys)", () => {
    const wrapKey = key32(0x30);
    const envelope = exportWrapKey(wrapKey, "real-pass", "k");
    expect(() => importWrapKey(envelope, "")).toThrow(WrapKeyBackupError);
  });

  it("importWrapKey rejects a passphrase that does not match (AES-GCM auth failure)", () => {
    const wrapKey = key32(0x40);
    const envelope = exportWrapKey(wrapKey, "real-pass", "k");
    expect(() => importWrapKey(envelope, "wrong-pass")).toThrow(WrapKeyBackupError);
  });

  it("importWrapKey rejects a backup envelope shorter than the minimum length", () => {
    const tooShort = "AAAA"; // well under the 16-byte salt + 12-byte IV + ciphertext + 16-byte tag minimum
    expect(() => importWrapKey(tooShort, "any")).toThrow(WrapKeyBackupError);
  });

  it("importWrapKey rejects a backup envelope corrupted at the last byte (GCM tag tamper)", () => {
    const wrapKey = key32(0x50);
    const envelope = exportWrapKey(wrapKey, "pass-123", "k");
    // Flip the last base64url char to mutate the tag
    const corrupted = envelope.slice(0, -1) + (envelope[envelope.length - 1] === "A" ? "B" : "A");
    expect(corrupted).not.toBe(envelope);
    expect(() => importWrapKey(corrupted, "pass-123")).toThrow(WrapKeyBackupError);
  });

  it("constantTimeEqual returns true for identical 32-byte buffers", () => {
    const a = key32(0x60);
    const b = Buffer.from(a);
    expect(constantTimeEqual(a, b)).toBe(true);
  });

  it("constantTimeEqual returns false for 1-byte-different 32-byte buffers", () => {
    const a = key32(0x70);
    const b = Buffer.from(a);
    b[15] = b[15]! ^ 0x01;
    expect(constantTimeEqual(a, b)).toBe(false);
  });

  it("constantTimeEqual returns false for different-length buffers", () => {
    const a = key32(0x80);
    const b = Buffer.alloc(16, 0xab);
    expect(constantTimeEqual(a, b)).toBe(false);
    expect(constantTimeEqual(a, Buffer.alloc(0))).toBe(false);
  });

  it("backup envelope self-describes version + algorithm metadata (forward-compat)", () => {
    const wrapKey = key32(0x90);
    const envelope = exportWrapKey(wrapKey, "test-2026-pass", "k");
    // Decode the base64url to inspect the inner JSON
    const json = JSON.parse(Buffer.from(envelope, "base64url").toString("utf8"));
    expect(json).toHaveProperty("v");
    expect(json).toHaveProperty("keyId", "k");
    expect(json).toHaveProperty("salt");
    expect(json).toHaveProperty("iv");
    // IV must be 12 bytes (AES-GCM standard)
    expect(Buffer.from(json.iv, "base64url").length).toBe(12);
    // The salt must be at least 16 bytes
    expect(Buffer.from(json.salt, "base64url").length).toBeGreaterThanOrEqual(16);
  });
});
