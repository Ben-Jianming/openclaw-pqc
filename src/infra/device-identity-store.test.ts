// M2 (PQC migration, whitepaper 2.1): direct store invariants for the
// ML-DSA-65 (FIPS 204) device identity path.
//
// These tests exercise the SQLite store end-to-end without spawning a
// coordinator or touching the on-disk Ed25519 paths; the upstream test file
// `device-identity.test.ts` covers the higher-level loadOrCreateDeviceIdentity
// invariants and is the source of truth for that surface.
import fs from "node:fs";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { closeOpenClawStateDatabaseForTest } from "../state/openclaw-state-db.js";
import { withTempDir } from "../test-utils/temp-dir.js";
import {
  generateStoredDeviceIdentity,
  insertStoredDeviceIdentityIfAbsent,
  PRIMARY_DEVICE_IDENTITY_KEY,
  readStoredDeviceIdentity,
  readStoredDeviceIdentityReadOnly,
  repairInvalidStoredDeviceIdentity,
  validateStoredDeviceIdentity,
  type DeviceIdentityStoreOptions,
  type StoredDeviceIdentity,
} from "./device-identity-store.js";
import {
  decodeMlDsa65PublicKey,
  decodeMlDsa65SecretKey,
  MLDSA65_PUBLIC_KEY_BYTES,
  MLDSA65_PUBLIC_KEY_PREFIX,
  MLDSA65_SECRET_KEY_BYTES,
  MLDSA65_SECRET_KEY_PREFIX,
  signMlDsa65Payload,
  verifyMlDsa65Signature,
} from "./mldsa65-key-storage.js";

afterEach(() => {
  closeOpenClawStateDatabaseForTest();
});

function storeOptions(rootDir: string, identityKey?: string): DeviceIdentityStoreOptions {
  return {
    env: { ...process.env, OPENCLAW_STATE_DIR: rootDir },
    path: path.join(rootDir, "state", "openclaw.sqlite"),
    ...(identityKey ? { identityKey } : {}),
  };
}

describe("device-identity-store ML-DSA-65 invariants", () => {
  it("generateStoredDeviceIdentity produces a prefixed ML-DSA-65 keypair", () => {
    const stored = generateStoredDeviceIdentity(1_700_000_000_000);
    expect(stored.publicKeyPem.startsWith(MLDSA65_PUBLIC_KEY_PREFIX)).toBe(true);
    expect(stored.privateKeyPem.startsWith(MLDSA65_SECRET_KEY_PREFIX)).toBe(true);
    expect(decodeMlDsa65PublicKey(stored.publicKeyPem).length).toBe(MLDSA65_PUBLIC_KEY_BYTES);
    expect(decodeMlDsa65SecretKey(stored.privateKeyPem).length).toBe(MLDSA65_SECRET_KEY_BYTES);
    expect(stored.deviceId).toMatch(/^[a-f0-9]{64}$/);
    expect(stored.createdAtMs).toBe(1_700_000_000_000);
  });

  it("validateStoredDeviceIdentity round-trips sign/verify on the same keypair", () => {
    const stored = generateStoredDeviceIdentity();
    const validated = validateStoredDeviceIdentity(stored);
    expect(validated.deviceId).toBe(stored.deviceId);
    expect(validated.publicKeyPem).toBe(stored.publicKeyPem);
    expect(validated.privateKeyPem).toBe(stored.privateKeyPem);
    const sig = signMlDsa65Payload(stored.privateKeyPem, "roundtrip");
    expect(
      verifyMlDsa65Signature({
        publicKey: stored.publicKeyPem,
        payload: "roundtrip",
        sigBase64Url: sig,
      }),
    ).toBe(true);
  });

  it("validateStoredDeviceIdentity rejects a tampered deviceId", () => {
    const stored = generateStoredDeviceIdentity();
    expect(() => validateStoredDeviceIdentity({ ...stored, deviceId: "deadbeef" })).toThrow(
      /invalid persisted device identity/,
    );
  });

  it("validateStoredDeviceIdentity rejects a mismatched public/private pair", () => {
    const first = generateStoredDeviceIdentity();
    const second = generateStoredDeviceIdentity();
    expect(() =>
      validateStoredDeviceIdentity({
        ...first,
        publicKeyPem: second.publicKeyPem,
      }),
    ).toThrow(/invalid persisted device identity/);
  });

  it("readStoredDeviceIdentityReadOnly returns null on a missing database without creating files", async () => {
    await withTempDir("openclaw-device-store-readonly-", async (rootDir) => {
      const options = storeOptions(rootDir);
      expect(readStoredDeviceIdentityReadOnly(options)).toBeNull();
      expect(fs.existsSync(options.path!)).toBe(false);
      expect(fs.existsSync(path.dirname(options.path!))).toBe(false);
    });
  });

  it("insertStoredDeviceIdentityIfAbsent stores and re-reads the same key", async () => {
    await withTempDir("openclaw-device-store-insert-", async (rootDir) => {
      const options = storeOptions(rootDir);
      const stored = generateStoredDeviceIdentity();
      const inserted = insertStoredDeviceIdentityIfAbsent(stored, options);
      expect(inserted).toMatchObject({
        deviceId: stored.deviceId,
        publicKeyPem: stored.publicKeyPem,
        privateKeyPem: stored.privateKeyPem,
      });
      const reloaded = readStoredDeviceIdentity(options);
      expect(reloaded).toEqual(inserted);
    });
  });

  it("insertStoredDeviceIdentityIfAbsent keeps the original row on conflict", async () => {
    await withTempDir("openclaw-device-store-conflict-", async (rootDir) => {
      const options = storeOptions(rootDir);
      const first = generateStoredDeviceIdentity();
      const inserted = insertStoredDeviceIdentityIfAbsent(first, options);
      const second = generateStoredDeviceIdentity();
      const winner = insertStoredDeviceIdentityIfAbsent(second, options);
      expect(winner.deviceId).toBe(inserted.deviceId);
      expect(winner.publicKeyPem).toBe(inserted.publicKeyPem);
    });
  });

  it("repairInvalidStoredDeviceIdentity replaces an Ed25519 PEM row with an ML-DSA-65 row", async () => {
    await withTempDir("openclaw-device-store-repair-", async (rootDir) => {
      const options = storeOptions(rootDir);
      // Seed the row with a valid ML-DSA-65 identity so the table exists.
      const original = insertStoredDeviceIdentityIfAbsent(generateStoredDeviceIdentity(), options);
      closeOpenClawStateDatabaseForTest();

      // Inject a legacy Ed25519 PEM row directly into SQLite.
      const sqlite = await import("node:sqlite");
      const database = new sqlite.DatabaseSync(options.path!);
      database
        .prepare(
          "UPDATE device_identities SET public_key_pem = ?, private_key_pem = ?, device_id = ? WHERE identity_key = ?",
        )
        .run(
          "-----BEGIN PUBLIC KEY-----\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfakefakefakefakefakefakefakefakefakefakefakefake=\n-----END PUBLIC KEY-----\n",
          "-----BEGIN PRIVATE KEY-----\nMC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY1tIYUDDXK1OmU3bml0u8c9b3u5jk\n-----END PRIVATE KEY-----\n",
          "1111111111111111111111111111111111111111111111111111111111111111",
          PRIMARY_DEVICE_IDENTITY_KEY,
        );
      database.close();
      closeOpenClawStateDatabaseForTest();

      // Reading without repair should fail.
      expect(() => readStoredDeviceIdentity(options)).toThrow(/invalid persisted device identity/);

      // Repair should drop the Ed25519 row and insert the ML-DSA-65 replacement.
      const candidate = generateStoredDeviceIdentity();
      const result = repairInvalidStoredDeviceIdentity(candidate, options);
      expect(result.repaired).toBe(true);
      expect(result.rotated).toBe(true);
      expect(result.identity.deviceId).toBe(candidate.deviceId);

      const reloaded = readStoredDeviceIdentity(options);
      expect(reloaded?.publicKeyPem).toBe(candidate.publicKeyPem);
      // Sanity: the original ML-DSA-65 row is gone (it was overwritten by the
      // tampered Ed25519 row, then dropped by salvage).
      expect(reloaded?.publicKeyPem).not.toBe(original.publicKeyPem);
    });
  });

  it("validateStoredDeviceIdentity rejects a key that decodes but does not sign", () => {
    const valid = generateStoredDeviceIdentity();
    // Truncate the secret key so it is well-formed but unusable.
    const truncatedBody = valid.privateKeyPem.slice(0, valid.privateKeyPem.length - 8);
    expect(() =>
      validateStoredDeviceIdentity({
        ...valid,
        privateKeyPem: truncatedBody,
      } as StoredDeviceIdentity),
    ).toThrow(/invalid persisted device identity/);
  });
});
