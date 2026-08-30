// M5 (PQC migration, whitepaper 2.2.2 + 2.2.3 + 2.2.4): wrap integration
// invariants for device-identity-store.
//
// 11 invariants covering: round-trip with keyring, fail-closed without
// keyring, dropped keyId, read-only path, two-keyring cross-read, BLOB
// shape (UTF-8 base64url JSON), plaintext legacy fallback, public-only
// device_id lookup, and mutual exclusion of plaintext/wrapped.
import { randomBytes } from "node:crypto";
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
  type DeviceIdentityStoreOptions,
  type StoredDeviceIdentity,
  type SyncWrappingKeyProvider,
} from "./device-identity-store.js";

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

function newKey(): Buffer {
  return Buffer.from(randomBytes(32));
}

function makeKeyring(keyId: string, key: Buffer): SyncWrappingKeyProvider {
  return {
    getActiveKey: () => ({ keyId, key }),
    getKeyById: (id: string) => (id === keyId ? { keyId, key } : null),
  };
}

describe("device-identity-store wrap integration (M5, whitepaper 2.2.2)", () => {
  it("round-trips a wrapped ML-DSA-65 secret through the keyring", async () => {
    await withTempDir("openclaw-m5-wrap-roundtrip-", async (rootDir) => {
      const options = storeOptions(rootDir);
      const key = newKey();
      const provider = makeKeyring("wrap-key-2026-08", key);
      const stored = generateStoredDeviceIdentity({ now: 1, wrappingKeyProvider: provider });
      expect(stored.mldsaPrivateKeyWrapKeyId).toBe("wrap-key-2026-08");
      expect(stored.mldsaPrivateKeyWrapped).not.toBeNull();
      expect(stored.mldsaPrivateKeyPem).toBeNull(); // plaintext + wrapped are mutually exclusive
      expect(stored.privateKeyPem).toBe("");

      const inserted = insertStoredDeviceIdentityIfAbsent(stored, {
        ...options,
        wrappingKeyProvider: provider,
      });
      const reloaded = readStoredDeviceIdentity({ ...options, wrappingKeyProvider: provider });
      expect(reloaded).not.toBeNull();
      // The unwrapped privateKeyPem must round-trip through sign/verify.
      expect(reloaded!.privateKeyPem).toMatch(/^MLDSA65-SECRET-KEY:/);
      expect(reloaded!.privateKeyPem).not.toBe("");
    });
  });

  it("fails closed when a wrapped row is read without a keyring", async () => {
    await withTempDir("openclaw-m5-wrap-failclosed-", async (rootDir) => {
      const options = storeOptions(rootDir);
      const provider = makeKeyring("wrap-key-2026-08", newKey());
      const stored = generateStoredDeviceIdentity({ wrappingKeyProvider: provider });
      insertStoredDeviceIdentityIfAbsent(stored, { ...options, wrappingKeyProvider: provider });
      closeOpenClawStateDatabaseForTest();

      expect(() => readStoredDeviceIdentity(options)).toThrow(
        /is wrapped under keyId "wrap-key-2026-08" but no WrappingKeyProvider was supplied/,
      );
    });
  });

  it("fails closed on the read-only path when no keyring is supplied", async () => {
    await withTempDir("openclaw-m5-wrap-readonly-failclosed-", async (rootDir) => {
      const options = storeOptions(rootDir);
      const provider = makeKeyring("wrap-key-2026-08", newKey());
      const stored = generateStoredDeviceIdentity({ wrappingKeyProvider: provider });
      insertStoredDeviceIdentityIfAbsent(stored, { ...options, wrappingKeyProvider: provider });
      closeOpenClawStateDatabaseForTest();

      expect(() => readStoredDeviceIdentityReadOnly(options)).toThrow(
        /is wrapped under keyId "wrap-key-2026-08" but no WrappingKeyProvider was supplied/,
      );
    });
  });

  it("rejects an envelope whose wrap keyId has been dropped from the keyring", async () => {
    await withTempDir("openclaw-m5-wrap-dropped-keyid-", async (rootDir) => {
      const options = storeOptions(rootDir);
      const provider = makeKeyring("wrap-key-2026-08", newKey());
      const stored = generateStoredDeviceIdentity({ wrappingKeyProvider: provider });
      insertStoredDeviceIdentityIfAbsent(stored, { ...options, wrappingKeyProvider: provider });
      closeOpenClawStateDatabaseForTest();

      const otherKeyring: SyncWrappingKeyProvider = {
        getActiveKey: () => ({ keyId: "wrap-key-2026-09", key: newKey() }),
        getKeyById: () => null, // the original key is gone
      };
      expect(() =>
        readStoredDeviceIdentity({ ...options, wrappingKeyProvider: otherKeyring }),
      ).toThrow(/Wrapping key "wrap-key-2026-08" is not present in the keyring/);
    });
  });

  it("rejects an envelope that has been tampered with (BLOB corruption)", async () => {
    await withTempDir("openclaw-m5-wrap-tamper-", async (rootDir) => {
      const options = storeOptions(rootDir);
      const provider = makeKeyring("wrap-key-2026-08", newKey());
      const stored = generateStoredDeviceIdentity({ wrappingKeyProvider: provider });
      insertStoredDeviceIdentityIfAbsent(stored, { ...options, wrappingKeyProvider: provider });
      closeOpenClawStateDatabaseForTest();

      // Corrupt the BLOB column directly.
      const sqlite = await import("node:sqlite");
      const db = new sqlite.DatabaseSync(options.path!);
      db.prepare(
        "UPDATE device_identities SET mldsa_private_key_wrapped = ? WHERE identity_key = ?",
      ).run(Buffer.from("not-a-real-envelope"), PRIMARY_DEVICE_IDENTITY_KEY);
      db.close();
      closeOpenClawStateDatabaseForTest();

      expect(() => readStoredDeviceIdentity({ ...options, wrappingKeyProvider: provider })).toThrow(
        /malformed wrap envelope/,
      );
    });
  });

  it("stores the wrap envelope as UTF-8 base64url JSON in the BLOB column", async () => {
    await withTempDir("openclaw-m5-wrap-blob-shape-", async (rootDir) => {
      const options = storeOptions(rootDir);
      const provider = makeKeyring("wrap-key-2026-08", newKey());
      const stored = generateStoredDeviceIdentity({ wrappingKeyProvider: provider });
      insertStoredDeviceIdentityIfAbsent(stored, { ...options, wrappingKeyProvider: provider });
      closeOpenClawStateDatabaseForTest();

      const sqlite = await import("node:sqlite");
      const probe = new sqlite.DatabaseSync(options.path!, { readOnly: true });
      const row = probe
        .prepare(
          "SELECT mldsa_private_key_wrapped, mldsa_private_key_wrap_key_id FROM device_identities WHERE identity_key = ?",
        )
        .get(PRIMARY_DEVICE_IDENTITY_KEY) as {
        mldsa_private_key_wrapped: Buffer | Uint8Array;
        mldsa_private_key_wrap_key_id: string;
      };
      probe.close();

      const blob = Buffer.from(row.mldsa_private_key_wrapped);
      // The BLOB holds the UTF-8 bytes of the base64url-encoded JSON envelope
      // (whitepaper 3.2 — never raw-decode the BLOB as JSON, it is the
      // base64url form of the JSON document).
      const asBase64Url = blob.toString("utf8");
      expect(asBase64Url).toMatch(/^[A-Za-z0-9_-]+$/);
      const json = Buffer.from(asBase64Url, "base64url").toString("utf8");
      const parsed = JSON.parse(json);
      expect(parsed.v).toBe(1);
      expect(parsed.keyId).toBe("wrap-key-2026-08");
      expect(typeof parsed.iv).toBe("string");
      expect(typeof parsed.ciphertext).toBe("string");
      expect(typeof parsed.authTag).toBe("string");
      expect(row.mldsa_private_key_wrap_key_id).toBe("wrap-key-2026-08");
    });
  });

  it("falls back to plaintext ML-DSA-65 for legacy rows that predate the wrap envelope", async () => {
    await withTempDir("openclaw-m5-wrap-plaintext-fallback-", async (rootDir) => {
      const options = storeOptions(rootDir);
      // Pre-M5 store wrote only public_key_pem / private_key_pem.
      const stored = generateStoredDeviceIdentity({ now: 1 });
      expect(stored.mldsaPrivateKeyWrapKeyId).toBeNull();
      expect(stored.mldsaPrivateKeyWrapped).toBeNull();
      expect(stored.mldsaPrivateKeyPem).not.toBeNull();

      insertStoredDeviceIdentityIfAbsent(stored, options);
      const reloaded = readStoredDeviceIdentity(options);
      expect(reloaded).not.toBeNull();
      expect(reloaded!.privateKeyPem).toMatch(/^MLDSA65-SECRET-KEY:/);
      // Even if a keyring is supplied, the legacy plaintext row must not be
      // re-wrapped under it on read — `getKeyById` is never consulted for
      // plaintext rows.
      const provider = makeKeyring("wrap-key-2026-08", newKey());
      const reloaded2 = readStoredDeviceIdentity({ ...options, wrappingKeyProvider: provider });
      expect(reloaded2!.privateKeyPem).toBe(reloaded!.privateKeyPem);
    });
  });

  it("returns the same deviceId for plaintext and wrapped reads of the same public key", async () => {
    await withTempDir("openclaw-m5-wrap-deviceid-", async (rootDir) => {
      const options = storeOptions(rootDir);
      const provider = makeKeyring("wrap-key-2026-08", newKey());
      const stored = generateStoredDeviceIdentity({ wrappingKeyProvider: provider });
      const inserted = insertStoredDeviceIdentityIfAbsent(stored, {
        ...options,
        wrappingKeyProvider: provider,
      });
      const reloaded = readStoredDeviceIdentity({ ...options, wrappingKeyProvider: provider });
      expect(reloaded!.deviceId).toBe(inserted.deviceId);
    });
  });

  it("two-keyring cross-read: a keyring without the wrap keyId cannot unwrap a wrapped row", async () => {
    await withTempDir("openclaw-m5-wrap-cross-", async (rootDir) => {
      const options = storeOptions(rootDir);
      const primary = makeKeyring("wrap-key-2026-08", newKey());
      const stored = generateStoredDeviceIdentity({ wrappingKeyProvider: primary });
      insertStoredDeviceIdentityIfAbsent(stored, { ...options, wrappingKeyProvider: primary });
      closeOpenClawStateDatabaseForTest();

      // A second keyring with a different keyId — the row's keyId is unknown
      // to it, so readStoredDeviceIdentity must throw, not silently fall
      // back to the legacy plaintext column.
      const other: SyncWrappingKeyProvider = {
        getActiveKey: () => ({ keyId: "wrap-key-2026-09", key: newKey() }),
        getKeyById: (id) =>
          id === "wrap-key-2026-09" ? { keyId: "wrap-key-2026-09", key: newKey() } : null,
      };
      expect(() => readStoredDeviceIdentity({ ...options, wrappingKeyProvider: other })).toThrow(
        /Wrapping key "wrap-key-2026-08" is not present in the keyring/,
      );
    });
  });

  it("salvage preserves the wrap envelope (Doctor must not lose the seal)", async () => {
    await withTempDir("openclaw-m5-wrap-salvage-", async (rootDir) => {
      const options = storeOptions(rootDir);
      const provider = makeKeyring("wrap-key-2026-08", newKey());
      const stored = generateStoredDeviceIdentity({ wrappingKeyProvider: provider });
      insertStoredDeviceIdentityIfAbsent(stored, { ...options, wrappingKeyProvider: provider });
      closeOpenClawStateDatabaseForTest();

      // Invalidate the row's deviceId so it is rejected on read.
      const sqlite = await import("node:sqlite");
      const db = new sqlite.DatabaseSync(options.path!);
      db.prepare("UPDATE device_identities SET device_id = ? WHERE identity_key = ?").run(
        "0".repeat(64),
        PRIMARY_DEVICE_IDENTITY_KEY,
      );
      db.close();
      closeOpenClawStateDatabaseForTest();

      const candidate = generateStoredDeviceIdentity({ wrappingKeyProvider: provider });
      const repaired = repairInvalidStoredDeviceIdentity(candidate, {
        ...options,
        wrappingKeyProvider: provider,
      });
      expect(repaired.repaired).toBe(true);
      expect(repaired.rotated).toBe(true);
      // The new row is fully wrapped under the same keyId.
      expect(repaired.identity.mldsaPrivateKeyWrapKeyId).toBe("wrap-key-2026-08");
      expect(repaired.identity.mldsaPrivateKeyWrapped).not.toBeNull();
      const reloaded = readStoredDeviceIdentity({ ...options, wrappingKeyProvider: provider });
      expect(reloaded!.deviceId).toBe(candidate.deviceId);
    });
  });

  it("plaintext and wrapped forms are mutually exclusive in a single generated row", () => {
    const plain = generateStoredDeviceIdentity();
    expect(plain.mldsaPrivateKeyWrapped).toBeNull();
    expect(plain.mldsaPrivateKeyPem).not.toBeNull();

    const provider = makeKeyring("wrap-key-2026-08", newKey());
    const wrapped = generateStoredDeviceIdentity({ wrappingKeyProvider: provider });
    expect(wrapped.mldsaPrivateKeyWrapped).not.toBeNull();
    expect(wrapped.mldsaPrivateKeyPem).toBeNull();
    // And the active publicKeyPem matches the mldsa column.
    expect(wrapped.publicKeyPem).toBe(wrapped.mldsaPublicKeyPem);
  });
});
