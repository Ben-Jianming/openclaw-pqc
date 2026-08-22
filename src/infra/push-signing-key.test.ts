// Tests for push-signing-key.ts (M11 step 1 infrastructure).
//
// Covers:
// - generatePushSigningSecretRaw: returns 32 bytes, not all-zero, unique across calls
// - publicKeyRawFromSecretRaw: returns 32 bytes, deterministic for same secret
// - keyIdFromSecret (via getOrCreatePushSigningKey): stable for same secret
// - getOrCreatePushSigningKey: lazy file creation, chmod 0600
// - resolvePushSigningKeyPath: env var priority, absolute path required
// - PUSH_SIGNING_KEY_CONSTANTS: documented sizes
//
// Uses a tmp dir via os.tmpdir() so tests do not pollute the real
// /home/benjamin/pqc-fork-state.

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { existsSync, readFileSync, statSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  generatePushSigningSecretRaw,
  getOrCreatePushSigningKey,
  PUSH_SIGNING_KEY_CONSTANTS,
  publicKeyRawFromSecretRaw,
  resolvePushSigningKeyPath,
} from "./push-signing-key.js";

let tmpDir: string;
let savedEnv: Record<string, string | undefined>;

beforeEach(() => {
  tmpDir = mkdtempSync(join(tmpdir(), "pqc-push-key-test-"));
  savedEnv = {
    OPENCLAW_PUSH_SIGNING_KEY_FILE: process.env.OPENCLAW_PUSH_SIGNING_KEY_FILE,
    OPENCLAW_STATE_DIR: process.env.OPENCLAW_STATE_DIR,
  };
  process.env.OPENCLAW_STATE_DIR = tmpDir;
  delete process.env.OPENCLAW_PUSH_SIGNING_KEY_FILE;
});

afterEach(() => {
  if (savedEnv.OPENCLAW_PUSH_SIGNING_KEY_FILE === undefined) {
    delete process.env.OPENCLAW_PUSH_SIGNING_KEY_FILE;
  } else {
    process.env.OPENCLAW_PUSH_SIGNING_KEY_FILE = savedEnv.OPENCLAW_PUSH_SIGNING_KEY_FILE;
  }
  if (savedEnv.OPENCLAW_STATE_DIR === undefined) {
    delete process.env.OPENCLAW_STATE_DIR;
  } else {
    process.env.OPENCLAW_STATE_DIR = savedEnv.OPENCLAW_STATE_DIR;
  }
  rmSync(tmpDir, { recursive: true, force: true });
});

describe("push-signing-key M11 step 1 — constants", () => {
  it("documents raw key sizes (32-byte Ed25519 secret/public)", () => {
    expect(PUSH_SIGNING_KEY_CONSTANTS.ED25519_RAW_SECRET_KEY).toBe(32);
    expect(PUSH_SIGNING_KEY_CONSTANTS.ED25519_RAW_PUBLIC_KEY).toBe(32);
    expect(PUSH_SIGNING_KEY_CONSTANTS.FILE_MODE_0600).toBe(0o600);
  });
});

describe("push-signing-key M11 step 1 — generatePushSigningSecretRaw", () => {
  it("returns a 32-byte Uint8Array", () => {
    const secret = generatePushSigningSecretRaw();
    expect(secret).toBeInstanceOf(Uint8Array);
    expect(secret.length).toBe(32);
  });

  it("is not all-zero (sanity: randomBytes actually ran)", () => {
    const secret = generatePushSigningSecretRaw();
    const allZero = secret.every((b) => b === 0);
    expect(allZero).toBe(false);
  });

  it("returns unique values across calls (randomness)", () => {
    const a = generatePushSigningSecretRaw();
    const b = generatePushSigningSecretRaw();
    expect(Buffer.from(a).equals(Buffer.from(b))).toBe(false);
  });
});

describe("push-signing-key M11 step 1 — publicKeyRawFromSecretRaw", () => {
  it("returns a 32-byte Uint8Array for a valid secret", () => {
    const secret = generatePushSigningSecretRaw();
    const pub = publicKeyRawFromSecretRaw(secret);
    expect(pub).toBeInstanceOf(Uint8Array);
    expect(pub.length).toBe(32);
  });

  it("is deterministic for the same secret", () => {
    const secret = generatePushSigningSecretRaw();
    const pub1 = publicKeyRawFromSecretRaw(secret);
    const pub2 = publicKeyRawFromSecretRaw(secret);
    expect(Buffer.from(pub1).equals(Buffer.from(pub2))).toBe(true);
  });

  it("rejects wrong-length input", () => {
    expect(() => publicKeyRawFromSecretRaw(new Uint8Array(31))).toThrow(/32 bytes; got 31/);
    expect(() => publicKeyRawFromSecretRaw(new Uint8Array(33))).toThrow(/32 bytes; got 33/);
  });
});

describe("push-signing-key M11 step 1 — resolvePushSigningKeyPath", () => {
  it("returns $OPENCLAW_STATE_DIR/push-signing-key.bin by default", () => {
    process.env.OPENCLAW_STATE_DIR = "/tmp/example";
    const path = resolvePushSigningKeyPath();
    expect(path).toBe("/tmp/example/push-signing-key.bin");
  });

  it("uses $OPENCLAW_PUSH_SIGNING_KEY_FILE when set and absolute", () => {
    process.env.OPENCLAW_PUSH_SIGNING_KEY_FILE = "/etc/keys/push-signing-key.bin";
    const path = resolvePushSigningKeyPath();
    expect(path).toBe("/etc/keys/push-signing-key.bin");
  });

  it("rejects a relative $OPENCLAW_PUSH_SIGNING_KEY_FILE path", () => {
    process.env.OPENCLAW_PUSH_SIGNING_KEY_FILE = "relative/path.bin";
    expect(() => resolvePushSigningKeyPath()).toThrow(/must be an absolute path/);
  });
});

describe("push-signing-key M11 step 1 — getOrCreatePushSigningKey", () => {
  it("creates the file lazily if missing, with chmod 0600", () => {
    const path = resolvePushSigningKeyPath();
    expect(existsSync(path)).toBe(false);
    const key = getOrCreatePushSigningKey();
    expect(existsSync(path)).toBe(true);
    // Verify file content: 32 bytes
    const buf = readFileSync(path);
    expect(buf.length).toBe(32);
    // Verify chmod 0600
    const stat = statSync(path);
    // Mask out file-type bits; assert only owner rw
    const perm = stat.mode & 0o777;
    expect(perm).toBe(0o600);
    // Verify the returned key matches the file
    expect(Buffer.from(key.secretKeyRaw).equals(buf)).toBe(true);
    expect(key.secretKeyRaw.length).toBe(32);
    expect(key.publicKeyRaw.length).toBe(32);
    // keyId: 16-char hex (first 16 chars of SHA-256)
    expect(key.keyId).toMatch(/^[0-9a-f]{16}$/);
  });

  it("reuses the same key on subsequent calls (no rotation)", () => {
    const a = getOrCreatePushSigningKey();
    const b = getOrCreatePushSigningKey();
    expect(Buffer.from(a.secretKeyRaw).equals(Buffer.from(b.secretKeyRaw))).toBe(true);
    expect(a.keyId).toBe(b.keyId);
  });

  it("rejects a pre-existing file with wrong size (no silent overwrite)", () => {
    const path = resolvePushSigningKeyPath();
    // Write 16 bytes (wrong)
    require("node:fs").writeFileSync(path, Buffer.alloc(16, 0), { mode: 0o600 });
    expect(() => getOrCreatePushSigningKey()).toThrow(/wrong size/);
  });
});
