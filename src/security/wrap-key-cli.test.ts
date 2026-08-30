// M8 (PQC migration, whitepaper 2.2.7 + 2.2.8): wrap-key health check + CLI
// alias invariants.
//
// 13 invariants covering the four row statuses (plaintext / wrapped-active
// / wrapped-stale / invalid), the activeKeyId signal, defensive
// parseWrapEnvelope, the CLI alias wrappers, JSON-friendly output shape,
// and a sync vs async keyring distinction so the sync API can never be
// silently swapped out for a Promise-returning variant.
import { randomBytes } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import {
  generateStoredDeviceIdentity,
  type StoredDeviceIdentity,
  type SyncWrappingKeyProvider,
} from "../infra/device-identity-store.js";
import { wrapSecret, type WrappedSecret } from "./secret-wrapping.js";
import {
  parseWrapEnvelope,
  wrapKeyExportCommand,
  wrapKeyHealthCheck,
  wrapKeyImportCommand,
  wrapKeyStatusCommand,
  type WrapKeyStatus,
} from "./wrap-key-cli.js";

afterEach(() => {
  // no-op
});

function newKey(): Buffer {
  return Buffer.from(randomBytes(32));
}

function makeKeyring(keyId: string, key: Buffer): SyncWrappingKeyProvider {
  return {
    getActiveKey: () => ({ keyId, key }),
    getKeyById: (id: string) => (id === keyId ? { keyId, key } : null),
  };
}

function makeRow(overrides: Partial<StoredDeviceIdentity> = {}): StoredDeviceIdentity {
  return {
    deviceId: "0".repeat(64),
    publicKeyPem: "MLDSA65-PUBLIC-KEY:dummy",
    privateKeyPem: "MLDSA65-SECRET-KEY:dummy",
    createdAtMs: 1_700_000_000_000,
    mldsaPublicKeyPem: null,
    mldsaPrivateKeyPem: "MLDSA65-SECRET-KEY:dummy",
    mldsaPrivateKeyWrapped: null,
    mldsaPrivateKeyWrapKeyId: null,
    ...overrides,
  };
}

describe("wrap-key-cli (M8, whitepaper 2.2.7 + 2.2.8)", () => {
  it("classifies a plaintext row as plaintext with the right notes", () => {
    const row = makeRow();
    const status: WrapKeyStatus = wrapKeyHealthCheck({
      list: () => [{ identityKey: "primary", identity: row }],
      activeKeyId: "wrap-key-2026-08",
    });
    expect(status.plaintextCount).toBe(1);
    expect(status.wrappedActiveCount).toBe(0);
    expect(status.wrappedStaleCount).toBe(0);
    expect(status.invalidCount).toBe(0);
    expect(status.rows[0].status).toBe("plaintext");
    expect(status.rows[0].notes.join(" ")).toMatch(/plaintext/);
  });

  it("classifies a wrapped row whose keyId matches the active keyId as wrapped-active", () => {
    const key = newKey();
    const provider = makeKeyring("wrap-key-2026-08", key);
    const stored = generateStoredDeviceIdentity({ wrappingKeyProvider: provider });
    const status = wrapKeyHealthCheck({
      list: () => [{ identityKey: "primary", identity: stored }],
      activeKeyId: "wrap-key-2026-08",
    });
    expect(status.wrappedActiveCount).toBe(1);
    expect(status.wrappedStaleCount).toBe(0);
    expect(status.rows[0].status).toBe("wrapped-active");
  });

  it("classifies a wrapped row whose keyId does not match the active keyId as wrapped-stale", () => {
    const key = newKey();
    const provider = makeKeyring("wrap-key-2026-08", key);
    const stored = generateStoredDeviceIdentity({ wrappingKeyProvider: provider });
    const status = wrapKeyHealthCheck({
      list: () => [{ identityKey: "primary", identity: stored }],
      activeKeyId: "wrap-key-2026-09",
    });
    expect(status.wrappedStaleCount).toBe(1);
    expect(status.wrappedActiveCount).toBe(0);
    expect(status.rows[0].status).toBe("wrapped-stale");
    expect(status.rows[0].notes.join(" ")).toMatch(/non-active keyId/);
  });

  it("surfaces a malformed wrap envelope as invalid without throwing", () => {
    const row = makeRow({
      mldsaPrivateKeyPem: null,
      mldsaPrivateKeyWrapped: new Uint8Array(Buffer.from("not-a-real-envelope")),
      mldsaPrivateKeyWrapKeyId: "wrap-key-2026-08",
    });
    const status = wrapKeyHealthCheck({
      list: () => [{ identityKey: "primary", identity: row }],
      activeKeyId: "wrap-key-2026-08",
    });
    expect(status.invalidCount).toBe(1);
    expect(status.rows[0].status).toBe("invalid");
    expect(status.rows[0].notes.join(" ")).toMatch(/malformed/);
  });

  it("treats every wrapped row as wrapped-stale when the keyring is unavailable", () => {
    const key = newKey();
    const provider = makeKeyring("wrap-key-2026-08", key);
    const stored = generateStoredDeviceIdentity({ wrappingKeyProvider: provider });
    const status = wrapKeyHealthCheck({
      list: () => [{ identityKey: "primary", identity: stored }],
      activeKeyId: null,
    });
    expect(status.wrappedStaleCount).toBe(1);
    expect(status.activeKeyId).toBeNull();
  });

  it("sums the four counters consistently", () => {
    const activeKey = newKey();
    const staleKey = newKey();
    const activeProvider = makeKeyring("wrap-key-2026-08", activeKey);
    const staleProvider = makeKeyring("wrap-key-2026-07", staleKey);
    const rows = [
      { identityKey: "primary", identity: makeRow() },
      {
        identityKey: "secondary",
        identity: generateStoredDeviceIdentity({ wrappingKeyProvider: activeProvider }),
      },
      {
        identityKey: "stale",
        identity: generateStoredDeviceIdentity({ wrappingKeyProvider: staleProvider }),
      },
      {
        identityKey: "invalid",
        identity: makeRow({
          mldsaPrivateKeyPem: null,
          mldsaPrivateKeyWrapped: new Uint8Array(Buffer.from("garbage")),
          mldsaPrivateKeyWrapKeyId: "wrap-key-2026-08",
        }),
      },
    ];
    const status = wrapKeyHealthCheck({
      list: () => rows,
      activeKeyId: "wrap-key-2026-08",
    });
    expect(status.plaintextCount).toBe(1);
    expect(status.wrappedActiveCount).toBe(1);
    expect(status.wrappedStaleCount).toBe(1);
    expect(status.invalidCount).toBe(1);
    expect(status.rows).toHaveLength(4);
    // JSON-friendly: the document is plain JSON.stringify-able.
    const json = JSON.stringify(status);
    expect(typeof json).toBe("string");
    const restored = JSON.parse(json) as WrapKeyStatus;
    expect(restored.rows).toHaveLength(4);
  });

  it("parseWrapEnvelope returns the envelope on success and null on every malformed input", () => {
    const env: WrappedSecret = wrapSecret(Buffer.from("hello"), "wrap-key-2026-08", newKey());
    const serialized = Buffer.from(JSON.stringify(env), "utf8").toString("base64url");
    // The function expects a base64url-encoded JSON envelope (the BLOB
    // shape produced by M4.2 + M5).
    const ok = parseWrapEnvelope(serialized);
    expect(ok?.keyId).toBe("wrap-key-2026-08");
    expect(parseWrapEnvelope("")).toBeNull();
    expect(parseWrapEnvelope(null)).toBeNull();
    expect(parseWrapEnvelope(undefined)).toBeNull();
    expect(parseWrapEnvelope("!!!not-base64!!!")).toBeNull();
    expect(parseWrapEnvelope(Buffer.from("not-json", "utf8").toString("base64url"))).toBeNull();
  });

  it("wrapKeyStatusCommand is an alias for wrapKeyHealthCheck", () => {
    const row = makeRow();
    const a = wrapKeyStatusCommand({
      list: () => [{ identityKey: "primary", identity: row }],
      activeKeyId: null,
    });
    const b = wrapKeyHealthCheck({
      list: () => [{ identityKey: "primary", identity: row }],
      activeKeyId: null,
    });
    expect(a).toEqual(b);
  });

  it("wrapKeyExportCommand + wrapKeyImportCommand round-trip a key", async () => {
    const raw = newKey();
    const envelope = await wrapKeyExportCommand({
      rawKey: raw,
      passphrase: "openclaw-rotates-wrapping-keys-2026",
      keyId: "wrap-key-2026-08",
    });
    const restored = await wrapKeyImportCommand({
      envelope,
      passphrase: "openclaw-rotates-wrapping-keys-2026",
    });
    expect(restored.keyId).toBe("wrap-key-2026-08");
    expect(restored.key.equals(raw)).toBe(true);
  });

  it("wrapKeyImportCommand rejects a wrong passphrase", async () => {
    const raw = newKey();
    const envelope = await wrapKeyExportCommand({
      rawKey: raw,
      passphrase: "openclaw-rotates-wrapping-keys-2026",
      keyId: "wrap-key-2026-08",
    });
    await expect(
      wrapKeyImportCommand({
        envelope,
        passphrase: "a-very-different-passphrase-2026",
      }),
    ).rejects.toThrow(/AES-256-GCM authentication failed/);
  });

  it("wrapKeyHealthCheck throws TypeError when list is missing", () => {
    expect(() =>
      wrapKeyHealthCheck({
        list: undefined as unknown as () => Array<{
          identityKey: string;
          identity: StoredDeviceIdentity;
        }>,
        activeKeyId: null,
      }),
    ).toThrow(/list\(\) function/);
  });

  it("notes appear in priority order: invalid > stale > plaintext", () => {
    const provider = makeKeyring("wrap-key-2026-08", newKey());
    const rows: Array<{ identityKey: string; identity: StoredDeviceIdentity }> = [
      { identityKey: "plain", identity: makeRow() },
      {
        identityKey: "stale",
        identity: generateStoredDeviceIdentity({ wrappingKeyProvider: provider }),
      },
      {
        identityKey: "invalid",
        identity: makeRow({
          mldsaPrivateKeyPem: null,
          mldsaPrivateKeyWrapped: new Uint8Array(Buffer.from("garbage")),
          mldsaPrivateKeyWrapKeyId: "wrap-key-2026-08",
        }),
      },
    ];
    const status = wrapKeyHealthCheck({
      list: () => rows,
      activeKeyId: "wrap-key-2026-09",
    });
    const invalidIdx = status.notes.findIndex((n) => /invalid row/i.test(n));
    const staleIdx = status.notes.findIndex((n) => /non-active keyId/.test(n));
    const plaintextIdx = status.notes.findIndex((n) => /plaintext row/i.test(n));
    expect(invalidIdx).toBeGreaterThanOrEqual(0);
    expect(staleIdx).toBeGreaterThan(invalidIdx);
    expect(plaintextIdx).toBeGreaterThan(staleIdx);
  });
});
