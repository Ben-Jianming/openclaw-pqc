/**
 * M5 runtime fix: env-var-based wrap auto-wiring.
 */
import {
  afterEach,
  beforeEach,
  describe,
  expect,
  it,
} from "vitest";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { loadOrCreateDeviceIdentity } from "./device-identity.js";
import {
  readStoredDeviceIdentity,
  readStoredDeviceIdentityReadOnly,
  type DeviceIdentityReadOptions,
  type DeviceIdentityStoreOptions,
  type SyncWrappingKeyProvider,
} from "./device-identity-store.js";
import { decodeBase64UrlKey } from "../security/keyring-provider.js";
import { closeOpenClawStateDatabaseForTest } from "../state/openclaw-state-db.js";

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
  for (const [k, v] of Object.entries(savedEnv)) {
    if (v === undefined) delete process.env[k];
    else process.env[k] = v;
  }
  closeOpenClawStateDatabaseForTest();
  fs.rmSync(tempDir, { recursive: true, force: true });
});

function options(): DeviceIdentityStoreOptions {
  return { env: { ...process.env, OPENCLAW_STATE_DIR: tempDir } as any };
}

function readOptions(): DeviceIdentityReadOptions {
  return {
    env: { ...process.env, OPENCLAW_STATE_DIR: tempDir } as any,
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

  it("falls back to plaintext when env vars are absent (with stderr warning)", () => {
    delete process.env.OPENCLAW_PQC_WRAP_KEY;
    delete process.env.OPENCLAW_PQC_WRAP_KEY_ID;
    const stderrBuf: string[] = [];
    const origWrite = process.stderr.write.bind(process.stderr);
    process.stderr.write = ((s: any) => { stderrBuf.push(String(s)); return true; }) as any;
    try {
      loadOrCreateDeviceIdentity(options());
    } finally {
      process.stderr.write = origWrite;
    }
    const stored = readStoredDeviceIdentityReadOnly(options());
    expect(stored).not.toBeNull();
    expect(stored!.mldsaPrivateKeyWrapped).toBeNull();
    expect(stored!.mldsaPrivateKeyWrapKeyId).toBeNull();
    expect(stored!.mldsaPrivateKeyPem).not.toBeNull();
    expect(stored!.mldsaPrivateKeyPem!.startsWith("MLDSA65-SECRET-KEY:")).toBe(true);
    expect(stderrBuf.join("")).toMatch(/PQC.*plaintext/);
  });

  it("rejects malformed OPENCLAW_PQC_WRAP_KEY (non-base64url)", () => {
    process.env.OPENCLAW_PQC_WRAP_KEY = "not-valid-base64!!!";
    expect(() => loadOrCreateDeviceIdentity(options())).toThrow(/base64url/);
  });

  it("uses 'env-default' as keyId when only OPENCLAW_PQC_WRAP_KEY is set", () => {
    delete process.env.OPENCLAW_PQC_WRAP_KEY_ID;
    loadOrCreateDeviceIdentity(options());
    const stored = readStoredDeviceIdentity({
      env: { ...process.env, OPENCLAW_STATE_DIR: tempDir } as any,
      wrappingKeyProvider: makeKeyring(WRAP_KEY, "env-default"),
    });
    expect(stored!.mldsaPrivateKeyWrapKeyId).toBe("env-default");
  });
});
