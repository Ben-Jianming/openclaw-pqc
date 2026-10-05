import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
/**
 * M5 runtime fix: env-var-based wrap auto-wiring.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { resetPqcEmit, setPqcEmit, type PqcLogPayload } from "../logging/pqc-log.js";
import { decodeBase64UrlKey } from "../security/keyring-provider.js";
import { closeOpenClawStateDatabaseForTest } from "../state/openclaw-state-db.js";
import {
  readStoredDeviceIdentity,
  readStoredDeviceIdentityReadOnly,
  resolveDeviceIdentityStore,
  type DeviceIdentityReadOptions,
  type DeviceIdentityStoreOptions,
  type SyncWrappingKeyProvider,
} from "./device-identity-store.js";
import {
  loadDeviceIdentityIfPresent,
  loadOrCreateDeviceIdentity,
  resolveDeviceIdentityKeyring,
} from "./device-identity.js";

const WRAP_KEY = "XYU5RKqbBTfbrFvLrcSlgmMSyM5LnlLZk7vUUhKbEVg";
const WRAP_KEY_ID = "test-env-wrap-2026-08";

let tempDir: string;
let savedEnv: Record<string, string | undefined>;

function makeKeyring(rawKey: string, keyId: string): SyncWrappingKeyProvider {
  return {
    getActiveKey: () => ({ keyId, key: decodeBase64UrlKey(rawKey) }),
    getKeyById: (id: string) => (id === keyId ? { keyId, key: decodeBase64UrlKey(rawKey) } : null),
  };
}

beforeEach(() => {
  tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "pqc-wrap-env-test-"));
  savedEnv = {
    OPENCLAW_STATE_DIR: process.env.OPENCLAW_STATE_DIR,
    OPENCLAW_PQC_WRAP_KEY: process.env.OPENCLAW_PQC_WRAP_KEY,
    OPENCLAW_PQC_WRAP_KEY_ID: process.env.OPENCLAW_PQC_WRAP_KEY_ID,
  };
  process.env.OPENCLAW_STATE_DIR = tempDir;
  process.env.OPENCLAW_PQC_WRAP_KEY = WRAP_KEY;
  process.env.OPENCLAW_PQC_WRAP_KEY_ID = WRAP_KEY_ID;
});

afterEach(() => {
  resetPqcEmit();
  for (const [k, v] of Object.entries(savedEnv)) {
    if (v === undefined) {
      delete process.env[k];
    } else {
      process.env[k] = v;
    }
  }
  closeOpenClawStateDatabaseForTest();
  fs.rmSync(tempDir, { recursive: true, force: true });
});

function options(): DeviceIdentityStoreOptions {
  return { env: { ...process.env, OPENCLAW_STATE_DIR: tempDir } as NodeJS.ProcessEnv };
}

function readOptions(): DeviceIdentityReadOptions {
  return {
    env: { ...process.env, OPENCLAW_STATE_DIR: tempDir } as NodeJS.ProcessEnv,
    wrappingKeyProvider: makeKeyring(WRAP_KEY, WRAP_KEY_ID),
  };
}

describe("device-identity env-var wrap auto-wiring", () => {
  it("writes wrapped row with logical keyId when OPENCLAW_PQC_WRAP_KEY is set", () => {
    const identity = loadOrCreateDeviceIdentity(options());
    expect(identity.publicKeyPem.startsWith("MLDSA65-PUBLIC-KEY:")).toBe(true);

    const stored = readStoredDeviceIdentity(readOptions());
    expect(stored).not.toBeNull();
    expect(stored!.mldsaPrivateKeyWrapKeyId).toBe(WRAP_KEY_ID);
    expect(stored!.mldsaPrivateKeyWrapped).not.toBeNull();
    expect(stored!.mldsaPrivateKeyWrapped!.length).toBeGreaterThan(0);
    // When wrap succeeded, the plaintext column should NOT be populated.
    expect(stored!.mldsaPrivateKeyPem).toBeNull();
  });

  it("unwraps via env keyring on reload (round-trip)", () => {
    const identity1 = loadOrCreateDeviceIdentity(options());
    const identity2 = loadOrCreateDeviceIdentity(options());
    expect(identity1.publicKeyPem).toBe(identity2.publicKeyPem);
    expect(identity1.privateKeyPem.startsWith("MLDSA65-SECRET-KEY:")).toBe(true);
  });

  it("auto-provisions a wrapping key when env vars are absent", () => {
    delete process.env.OPENCLAW_PQC_WRAP_KEY;
    delete process.env.OPENCLAW_PQC_WRAP_KEY_ID;
    const records: PqcLogPayload[] = [];
    setPqcEmit((record) => records.push(record));
    loadOrCreateDeviceIdentity(options());
    const stored = readStoredDeviceIdentity({
      ...options(),
      wrappingKeyProvider: resolveDeviceIdentityKeyring(options().env),
    });
    expect(stored).not.toBeNull();
    expect(stored!.mldsaPrivateKeyWrapped).not.toBeNull();
    expect(stored!.mldsaPrivateKeyWrapKeyId).toBe("file-default");
    expect(stored!.mldsaPrivateKeyPem).toBeNull();
    expect(
      records.some((record) => String(record.detail).includes("created private state-dir")),
    ).toBe(true);
  });

  it("auto-provisions against a legacy state database without an identity table", () => {
    delete process.env.OPENCLAW_PQC_WRAP_KEY;
    delete process.env.OPENCLAW_PQC_WRAP_KEY_ID;
    const databasePath = resolveDeviceIdentityStore(options()).databasePath;
    fs.mkdirSync(path.dirname(databasePath), { recursive: true });
    const legacyDatabase = new DatabaseSync(databasePath);
    legacyDatabase.exec("CREATE TABLE legacy_state (id INTEGER PRIMARY KEY)");
    legacyDatabase.close();

    const identity = loadOrCreateDeviceIdentity(options());
    expect(identity.publicKeyPem.startsWith("MLDSA65-PUBLIC-KEY:")).toBe(true);
    const stored = readStoredDeviceIdentity({
      ...options(),
      wrappingKeyProvider: resolveDeviceIdentityKeyring(options().env),
    });
    expect(stored?.mldsaPrivateKeyWrapped).not.toBeNull();
    expect(stored?.mldsaPrivateKeyPem).toBeNull();
  });

  it("does not inherit an ambient wrap key when the caller supplies an isolated env", () => {
    const isolatedOptions: DeviceIdentityStoreOptions = { env: { OPENCLAW_STATE_DIR: tempDir } };
    const identity = loadOrCreateDeviceIdentity(isolatedOptions);
    const stored = readStoredDeviceIdentity({
      ...isolatedOptions,
      wrappingKeyProvider: resolveDeviceIdentityKeyring(isolatedOptions.env),
    });
    expect(stored?.mldsaPrivateKeyWrapKeyId).toBe("file-default");
    expect(loadDeviceIdentityIfPresent(isolatedOptions)?.deviceId).toBe(identity.deviceId);
  });

  it("rejects malformed OPENCLAW_PQC_WRAP_KEY (non-base64url)", () => {
    process.env.OPENCLAW_PQC_WRAP_KEY = "not-valid-base64!!!";
    expect(() => loadOrCreateDeviceIdentity(options())).toThrow(/base64url/);
    try {
      loadOrCreateDeviceIdentity(options());
    } catch (error) {
      expect(String(error)).not.toContain("not-valid-base64");
    }
  });

  it("uses 'env-default' as keyId when only OPENCLAW_PQC_WRAP_KEY is set", () => {
    delete process.env.OPENCLAW_PQC_WRAP_KEY_ID;
    loadOrCreateDeviceIdentity(options());
    const stored = readStoredDeviceIdentity({
      env: { ...process.env, OPENCLAW_STATE_DIR: tempDir } as NodeJS.ProcessEnv,
      wrappingKeyProvider: makeKeyring(WRAP_KEY, "env-default"),
    });
    expect(stored!.mldsaPrivateKeyWrapKeyId).toBe("env-default");
  });
});
