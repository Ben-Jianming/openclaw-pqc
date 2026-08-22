/**
 * M15.B: file-based wrap auto-wiring (v3-style, danteng-compatible).
 *
 * OPENCLAW_WRAP_KEY_FILE points to a chmod 0600 file containing a 32-byte
 * base64url AES-256 key on the first line. This is the v3-style delivery
 * format used by danteng's v3 fork (port 18791) and is preferred over
 * OPENCLAW_PQC_WRAP_KEY (v2-style, M5 v2) for production deployments.
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
const WRAP_KEY_ID = "test-file-wrap-2026-08";

let tempDir: string;
let wrapKeyFile: string;
let savedEnv: Record<string, string | undefined>;

function writeWrapKeyFile(filePath: string, value: string, mode: number = 0o600): void {
  fs.writeFileSync(filePath, value);
  fs.chmodSync(filePath, mode);
}

function makeKeyring(rawKey: string, keyId: string): SyncWrappingKeyProvider {
  return {
    getActiveKey: () => ({ keyId, key: decodeBase64UrlKey(rawKey) }),
    getKeyById: (id: string) => (id === keyId ? { keyId, key: decodeBase64UrlKey(rawKey) } : null),
  };
}

beforeEach(() => {
  tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "pqc-wrap-file-test-"));
  wrapKeyFile = path.join(tempDir, "wrap-key.bin");
  writeWrapKeyFile(wrapKeyFile, WRAP_KEY, 0o600);

  savedEnv = {
    OPENCLAW_STATE_DIR: process.env.OPENCLAW_STATE_DIR,
    OPENCLAW_PQC_WRAP_KEY: process.env.OPENCLAW_PQC_WRAP_KEY,
    OPENCLAW_PQC_WRAP_KEY_ID: process.env.OPENCLAW_PQC_WRAP_KEY_ID,
    OPENCLAW_WRAP_KEY_FILE: process.env.OPENCLAW_WRAP_KEY_FILE,
  };
  process.env.OPENCLAW_STATE_DIR = tempDir;
  process.env.OPENCLAW_WRAP_KEY_FILE = wrapKeyFile;
  process.env.OPENCLAW_PQC_WRAP_KEY_ID = WRAP_KEY_ID;
  // OPENCLAW_PQC_WRAP_KEY is intentionally NOT set in beforeEach;
  // tests that want to assert precedence can set it explicitly.
  delete process.env.OPENCLAW_PQC_WRAP_KEY;
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
  return {
    env: {
      ...process.env,
      OPENCLAW_STATE_DIR: tempDir,
    } as any,
  };
}

function readOptions(): DeviceIdentityReadOptions {
  return {
    env: {
      ...process.env,
      OPENCLAW_STATE_DIR: tempDir,
    } as any,
    wrappingKeyProvider: makeKeyring(WRAP_KEY, WRAP_KEY_ID),
  };
}

describe("M15.B device-identity file-based wrap (v3-style)", () => {
  it("writes wrapped row with logical keyId when OPENCLAW_WRAP_KEY_FILE is set", () => {
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

  it("round-trips (unwraps via file keyring on reload)", () => {
    const identity1 = loadOrCreateDeviceIdentity(options());
    const identity2 = loadOrCreateDeviceIdentity(options());
    expect(identity1.publicKeyPem).toBe(identity2.publicKeyPem);
    expect(identity1.privateKeyPem.startsWith("MLDSA65-SECRET-KEY:")).toBe(true);
  });

  it("OPENCLAW_WRAP_KEY_FILE takes precedence over OPENCLAW_PQC_WRAP_KEY", () => {
    // Set both: file path wins, so the wrap key is from the file (WRAP_KEY)
    // and the wrap key id is the env var (WRAP_KEY_ID).
    process.env.OPENCLAW_PQC_WRAP_KEY = "DIFFERENT_KEY_IN_ENV_SHOULD_BE_IGNORED_XYZWVUUSQQ";  // 43 chars
    loadOrCreateDeviceIdentity(options());
    const stored = readStoredDeviceIdentity(readOptions());
    expect(stored).not.toBeNull();
    // Verify the wrap succeeded with the FILE key, not the env key:
    // We use the file key (WRAP_KEY) for unwrap in readOptions() above,
    // so the test passes only if the row was wrapped with WRAP_KEY.
    expect(stored!.mldsaPrivateKeyWrapped).not.toBeNull();
    expect(stored!.mldsaPrivateKeyWrapKeyId).toBe(WRAP_KEY_ID);
  });

  it("uses 'file-default' as keyId when only OPENCLAW_WRAP_KEY_FILE is set (no ID)", () => {
    delete process.env.OPENCLAW_PQC_WRAP_KEY_ID;
    loadOrCreateDeviceIdentity(options());
    const stored = readStoredDeviceIdentity({
      env: { ...process.env, OPENCLAW_STATE_DIR: tempDir } as any,
      wrappingKeyProvider: makeKeyring(WRAP_KEY, "file-default"),
    });
    expect(stored).not.toBeNull();
    expect(stored!.mldsaPrivateKeyWrapKeyId).toBe("file-default");
    expect(stored!.mldsaPrivateKeyWrapped).not.toBeNull();
  });

  it("rejects relative OPENCLAW_WRAP_KEY_FILE path", () => {
    process.env.OPENCLAW_WRAP_KEY_FILE = "relative/wrap-key.bin";
    expect(() => loadOrCreateDeviceIdentity(options())).toThrow(/absolute/);
  });

  it("rejects OPENCLAW_WRAP_KEY_FILE with wrong mode (0644 too loose)", () => {
    writeWrapKeyFile(wrapKeyFile, WRAP_KEY, 0o644);
    expect(() => loadOrCreateDeviceIdentity(options())).toThrow(/chmod 0600/);
  });

  it("rejects OPENCLAW_WRAP_KEY_FILE with malformed base64url contents", () => {
    writeWrapKeyFile(wrapKeyFile, "not-valid-base64!!!", 0o600);
    expect(() => loadOrCreateDeviceIdentity(options())).toThrow(/base64url/);
  });

  it("falls back to plaintext when neither WRAP_KEY_FILE nor WRAP_KEY is set", () => {
    delete process.env.OPENCLAW_WRAP_KEY_FILE;
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
});
