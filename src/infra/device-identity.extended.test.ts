// M2 (PQC migration, whitepaper 2.2.3): device identity public API speaks
// ML-DSA-65. Edge cases supplementing src/infra/device-identity.test.ts (12 invariants).
//
// API surface (from src/infra/device-identity.ts):
//   - normalizeDevicePublicKeyBase64Url(raw | prefixed) → canonical PREFIXED form
//     (e.g. "MLDSA65-PUBLIC-KEY:..."). Idempotent on the prefixed input.
//   - publicKeyRawBase64UrlFromPem(prefixed) → canonical UNPREFIXED base64url bytes.
//   - deriveDeviceIdFromPublicKey(raw | prefixed) → SHA-256 hex of the raw key.
//
// Coverage (8 tests):
//   - normalizeDevicePublicKeyBase64Url accepts raw 1952-byte base64url (returns prefixed)
//   - normalizeDevicePublicKeyBase64Url accepts 'MLDSA65-PUBLIC-KEY:...' (idempotent, returns same)
//   - normalizeDevicePublicKeyBase64Url returns null for empty/malformed
//   - normalizeDevicePublicKeyBase64Url returns null for wrong length (not 1952)
//   - deriveDeviceIdFromPublicKey is deterministic (same input → same ID)
//   - deriveDeviceIdFromPublicKey: two different keys produce two different IDs
//   - deriveDeviceIdFromPublicKey returns null for malformed input
//   - publicKeyRawBase64UrlFromPem returns UNPREFIXED base64url from prefixed input
//   - Full round-trip: key → publicKeyRawBase64UrlFromPem → normalize → same prefix form
import { describe, expect, it } from "vitest";
import {
  deriveDeviceIdFromPublicKey,
  normalizeDevicePublicKeyBase64Url,
  publicKeyRawBase64UrlFromPem,
} from "./device-identity.js";
import { generateMlDsa65Keypair } from "./mldsa65-key-storage.js";

function bytesToBase64Url(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

describe("device-identity M2 — public API edge cases", () => {
  it("normalizeDevicePublicKeyBase64Url returns PREFIXED form for raw 1952-byte base64url input", () => {
    const ml = generateMlDsa65Keypair();
    const b64 = bytesToBase64Url(ml.publicKey);
    const result = normalizeDevicePublicKeyBase64Url(b64);
    expect(result).not.toBeNull();
    expect(result!.startsWith("MLDSA65-PUBLIC-KEY:")).toBe(true);
    // The base64url portion must decode to exactly 1952 bytes
    const tail = result!.slice("MLDSA65-PUBLIC-KEY:".length);
    expect(Buffer.from(tail, "base64url").length).toBe(1952);
  });

  it("normalizeDevicePublicKeyBase64Url is idempotent on the PREFIXED form", () => {
    const ml = generateMlDsa65Keypair();
    const b64 = bytesToBase64Url(ml.publicKey);
    const prefixed = "MLDSA65-PUBLIC-KEY:" + b64;
    const once = normalizeDevicePublicKeyBase64Url(prefixed);
    const twice = normalizeDevicePublicKeyBase64Url(once!);
    expect(once).toBe(prefixed);
    expect(twice).toBe(prefixed);
  });

  it("normalizeDevicePublicKeyBase64Url returns null for empty string and malformed input", () => {
    expect(normalizeDevicePublicKeyBase64Url("")).toBeNull();
    expect(normalizeDevicePublicKeyBase64Url("!!!not-base64!!!")).toBeNull();
    expect(normalizeDevicePublicKeyBase64Url("MLDSA65-PUBLIC-KEY:")).toBeNull();
  });

  it("normalizeDevicePublicKeyBase64Url returns null for wrong-length decoded bytes (not 1952)", () => {
    // 16 bytes instead of 1952
    const tooShort = bytesToBase64Url(new Uint8Array(16));
    expect(normalizeDevicePublicKeyBase64Url(tooShort)).toBeNull();
    // 2048 bytes instead of 1952
    const tooLong = bytesToBase64Url(new Uint8Array(2048));
    expect(normalizeDevicePublicKeyBase64Url(tooLong)).toBeNull();
  });

  it("deriveDeviceIdFromPublicKey is deterministic (same input → same ID, no randomness)", () => {
    const ml = generateMlDsa65Keypair();
    const b64 = bytesToBase64Url(ml.publicKey);
    const id1 = deriveDeviceIdFromPublicKey(b64);
    const id2 = deriveDeviceIdFromPublicKey(b64);
    expect(id1).not.toBeNull();
    expect(id1).toBe(id2);
    // 32-byte hex (64 chars) — SHA-256 derived
    expect(id1!.length).toBe(64);
  });

  it("deriveDeviceIdFromPublicKey: two different keys produce two different IDs (collision-free)", () => {
    const ml1 = generateMlDsa65Keypair();
    const ml2 = generateMlDsa65Keypair();
    const id1 = deriveDeviceIdFromPublicKey(bytesToBase64Url(ml1.publicKey));
    const id2 = deriveDeviceIdFromPublicKey(bytesToBase64Url(ml2.publicKey));
    expect(id1).not.toBeNull();
    expect(id2).not.toBeNull();
    expect(id1).not.toBe(id2);
  });

  it("deriveDeviceIdFromPublicKey returns null for malformed input", () => {
    expect(deriveDeviceIdFromPublicKey("")).toBeNull();
    expect(deriveDeviceIdFromPublicKey("!!!not-base64!!!")).toBeNull();
    // Wrong length (not 1952 bytes)
    expect(deriveDeviceIdFromPublicKey(bytesToBase64Url(new Uint8Array(100)))).toBeNull();
  });

  it("publicKeyRawBase64UrlFromPem extracts UNPREFIXED raw base64url from PREFIXED input", () => {
    const ml = generateMlDsa65Keypair();
    const b64 = bytesToBase64Url(ml.publicKey);
    const prefixed = "MLDSA65-PUBLIC-KEY:" + b64;
    const raw = publicKeyRawBase64UrlFromPem(prefixed);
    // The returned form has NO prefix
    expect(raw).toBe(b64);
    expect(raw).not.toContain("MLDSA65-PUBLIC-KEY:");
    // The decoded length must be exactly 1952
    expect(Buffer.from(raw, "base64url").length).toBe(1952);
  });

  it("Full round-trip: key → publicKeyRawBase64UrlFromPem → normalize → same prefixed form", () => {
    const ml = generateMlDsa65Keypair();
    const b64 = bytesToBase64Url(ml.publicKey);
    const prefixed = "MLDSA65-PUBLIC-KEY:" + b64;
    // Round-trip: prefixed → raw → prefixed (via normalize)
    const rawExtracted = publicKeyRawBase64UrlFromPem(prefixed);
    expect(rawExtracted).toBe(b64);
    const prefixRecovered = normalizeDevicePublicKeyBase64Url(rawExtracted);
    expect(prefixRecovered).toBe(prefixed);
  });
});
