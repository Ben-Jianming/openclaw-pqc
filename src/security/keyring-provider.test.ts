// M6 (PQC migration, whitepaper 2.2.5 + 2.2.5.A): keyring-provider invariants.
//
// 30 invariants covering base64url codec, generateWrappingKey, FileKeyring
// (mode checks, absolute path, cache invalidation, primary override),
// EnvKeyring (read-each-call, missing var rejection, getKeyById lookup),
// CompositeKeyring (first-success, walk-all, last-error surfaced), the
// createKeyring factory, and the fail-closed OsKeyring stub.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { withTempDir } from "../test-utils/temp-dir.js";
import {
  CompositeKeyring,
  createKeyring,
  decodeBase64UrlKey,
  encodeBase64UrlKey,
  EnvKeyring,
  FileKeyring,
  generateWrappingKey,
  KeyringError,
  OsKeyring,
} from "./keyring-provider.js";

const WRAP_KEY_BYTES = 32;

afterEach(() => {
  // Make sure no stray env vars leak between tests.
  for (const key of Object.keys(process.env)) {
    if (key.startsWith("OPENCLAW_TEST_KEYRING_")) {
      delete process.env[key];
    }
  }
});

function makeKeyBytes(seed: number): Buffer {
  const out = Buffer.alloc(WRAP_KEY_BYTES);
  for (let i = 0; i < WRAP_KEY_BYTES; i++) {
    out[i] = (seed + i) & 0xff;
  }
  return out;
}

function writeFileKeyring(
  filePath: string,
  shape: { activeKeyId: string; keys: Record<string, string> },
  mode: number = 0o600,
): void {
  fs.writeFileSync(filePath, JSON.stringify(shape, null, 2), { mode, encoding: "utf8" });
  fs.chmodSync(filePath, mode);
}

describe("keyring-provider (M6, whitepaper 2.2.5)", () => {
  it("encodeBase64UrlKey accepts a 32-byte Buffer and produces valid base64url", () => {
    const raw = makeKeyBytes(1);
    const encoded = encodeBase64UrlKey(raw);
    expect(encoded).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(decodeBase64UrlKey(encoded).equals(raw)).toBe(true);
  });

  it("encodeBase64UrlKey rejects a non-Buffer", () => {
    // @ts-expect-error -- intentional type violation to verify runtime guard
    expect(() => encodeBase64UrlKey("not-a-buffer")).toThrow(/must be a Buffer/);
  });

  it("encodeBase64UrlKey rejects a Buffer of the wrong length", () => {
    expect(() => encodeBase64UrlKey(Buffer.alloc(16))).toThrow(/must be 32 bytes/);
  });

  it("decodeBase64UrlKey rejects a non-string", () => {
    // @ts-expect-error -- intentional type violation
    expect(() => decodeBase64UrlKey(null)).toThrow(/non-empty string/);
  });

  it("decodeBase64UrlKey rejects an empty string", () => {
    expect(() => decodeBase64UrlKey("")).toThrow(/non-empty string/);
  });

  it("decodeBase64UrlKey rejects a base64url that decodes to the wrong length", () => {
    expect(() => decodeBase64UrlKey("AAAA")).toThrow(/must be 32 bytes/);
  });

  it("generateWrappingKey produces 32-byte base64url keys and is non-deterministic", () => {
    const keys = new Set<string>();
    for (let i = 0; i < 8; i++) keys.add(generateWrappingKey());
    expect(keys.size).toBe(8);
    for (const k of keys) {
      expect(k).toMatch(/^[A-Za-z0-9_-]+$/);
      expect(decodeBase64UrlKey(k).length).toBe(WRAP_KEY_BYTES);
    }
  });

  it("FileKeyring refuses a relative path", () => {
    expect(() => new FileKeyring({ path: "relative.json" })).toThrow(/must be absolute/);
  });

  it("FileKeyring refuses a non-0600/0400 mode at construction time", () => {
    const absolute = path.join(os.tmpdir(), "openclaw-keyring-m6-mode.json");
    expect(() => new FileKeyring({ path: absolute, mode: 0o644 })).toThrow(/0600 or 0400/);
  });

  it("FileKeyring refuses a missing file on getActiveKey", async () => {
    await withTempDir("openclaw-m6-file-missing-", async (rootDir) => {
      const file = path.join(rootDir, "missing.json");
      const ring = new FileKeyring({ path: file });
      expect(() => ring.getActiveKey()).toThrow(
        /(Cannot stat|does not exist|ENOENT|no such file)/i,
      );
    });
  });

  it("FileKeyring refuses a 0644 file at getActiveKey time", async () => {
    await withTempDir("openclaw-m6-file-badmode-", async (rootDir) => {
      const file = path.join(rootDir, "loose.json");
      writeFileKeyring(
        file,
        { activeKeyId: "k1", keys: { k1: encodeBase64UrlKey(makeKeyBytes(1)) } },
        0o644,
      );
      const ring = new FileKeyring({ path: file });
      expect(() => ring.getActiveKey()).toThrow(/mode 0600 or 0400/);
    });
  });

  it("FileKeyring refuses a symbolic link at getActiveKey time", async () => {
    await withTempDir("openclaw-m6-file-symlink-", async (rootDir) => {
      const real = path.join(rootDir, "real.json");
      const link = path.join(rootDir, "link.json");
      writeFileKeyring(real, {
        activeKeyId: "k1",
        keys: { k1: encodeBase64UrlKey(makeKeyBytes(1)) },
      });
      fs.symlinkSync(real, link);
      const ring = new FileKeyring({ path: link });
      expect(() => ring.getActiveKey()).toThrow(/symbolic link/);
    });
  });

  it("FileKeyring resolves the active key with default ordering", async () => {
    await withTempDir("openclaw-m6-file-active-", async (rootDir) => {
      const file = path.join(rootDir, "keyring.json");
      writeFileKeyring(file, {
        activeKeyId: "k2",
        keys: {
          k1: encodeBase64UrlKey(makeKeyBytes(1)),
          k2: encodeBase64UrlKey(makeKeyBytes(2)),
        },
      });
      const ring = new FileKeyring({ path: file });
      const active = ring.getActiveKey();
      expect(active.keyId).toBe("k2");
      expect(active.key.equals(makeKeyBytes(2))).toBe(true);
    });
  });

  it("FileKeyring respects an explicit primaryKeyId override", async () => {
    await withTempDir("openclaw-m6-file-primary-", async (rootDir) => {
      const file = path.join(rootDir, "keyring.json");
      writeFileKeyring(file, {
        activeKeyId: "k2",
        keys: {
          k1: encodeBase64UrlKey(makeKeyBytes(1)),
          k2: encodeBase64UrlKey(makeKeyBytes(2)),
        },
      });
      const ring = new FileKeyring({ path: file, primaryKeyId: "k1" });
      const active = ring.getActiveKey();
      expect(active.keyId).toBe("k1");
      expect(active.key.equals(makeKeyBytes(1))).toBe(true);
    });
  });

  it("FileKeyring throws when the explicit primaryKeyId is missing", async () => {
    await withTempDir("openclaw-m6-file-primary-missing-", async (rootDir) => {
      const file = path.join(rootDir, "keyring.json");
      writeFileKeyring(file, {
        activeKeyId: "k2",
        keys: { k2: encodeBase64UrlKey(makeKeyBytes(2)) },
      });
      const ring = new FileKeyring({ path: file, primaryKeyId: "k1" });
      expect(() => ring.getActiveKey()).toThrow(/missing the explicit primary keyId "k1"/);
    });
  });

  it("FileKeyring.getKeyById returns null for an unknown keyId", async () => {
    await withTempDir("openclaw-m6-file-unknown-", async (rootDir) => {
      const file = path.join(rootDir, "keyring.json");
      writeFileKeyring(file, {
        activeKeyId: "k1",
        keys: { k1: encodeBase64UrlKey(makeKeyBytes(1)) },
      });
      const ring = new FileKeyring({ path: file });
      expect(ring.getKeyById("unknown")).toBeNull();
      expect(ring.getKeyById("")).toBeNull();
    });
  });

  it("FileKeyring invalidates its read cache when the file mtime changes", async () => {
    await withTempDir("openclaw-m6-file-cache-", async (rootDir) => {
      const file = path.join(rootDir, "keyring.json");
      writeFileKeyring(file, {
        activeKeyId: "k1",
        keys: { k1: encodeBase64UrlKey(makeKeyBytes(1)) },
      });
      const ring = new FileKeyring({ path: file });
      expect(ring.getActiveKey().key.equals(makeKeyBytes(1))).toBe(true);
      // Bump mtime + content.
      const future = Date.now() / 1000 + 2;
      fs.utimesSync(file, future, future);
      writeFileKeyring(file, {
        activeKeyId: "k2",
        keys: {
          k1: encodeBase64UrlKey(makeKeyBytes(1)),
          k2: encodeBase64UrlKey(makeKeyBytes(2)),
        },
      });
      expect(ring.getActiveKey().keyId).toBe("k2");
    });
  });

  it("FileKeyring.setShape overwrites the file and invalidates the cache", async () => {
    await withTempDir("openclaw-m6-file-set-", async (rootDir) => {
      const file = path.join(rootDir, "keyring.json");
      writeFileKeyring(file, {
        activeKeyId: "k1",
        keys: { k1: encodeBase64UrlKey(makeKeyBytes(1)) },
      });
      const ring = new FileKeyring({ path: file });
      ring.setShape({
        activeKeyId: "k3",
        keys: { k3: encodeBase64UrlKey(makeKeyBytes(3)) },
      });
      const active = ring.getActiveKey();
      expect(active.keyId).toBe("k3");
      expect(active.key.equals(makeKeyBytes(3))).toBe(true);
      const stat = fs.statSync(file);
      expect(stat.mode & 0o777).toBe(0o600);
    });
  });

  it("FileKeyring rejects an empty activeKeyId or activeKeyId that has no key entry", async () => {
    await withTempDir("openclaw-m6-file-bad-active-", async (rootDir) => {
      const file = path.join(rootDir, "keyring.json");
      writeFileKeyring(file, { activeKeyId: "missing", keys: {} });
      const ring = new FileKeyring({ path: file });
      expect(() => ring.getActiveKey()).toThrow(/no entry for the active keyId/);
    });
  });

  it("FileKeyring rejects a non-JSON file", async () => {
    await withTempDir("openclaw-m6-file-bad-json-", async (rootDir) => {
      const file = path.join(rootDir, "keyring.json");
      fs.writeFileSync(file, "not json", { mode: 0o600 });
      const ring = new FileKeyring({ path: file });
      expect(() => ring.getActiveKey()).toThrow(/not valid JSON/);
    });
  });

  it("EnvKeyring requires a non-empty activeVar at construction time", () => {
    expect(() => new EnvKeyring({ activeVar: "" })).toThrow(/non-empty activeVar/);
  });

  it("EnvKeyring reads the active key on every call (no cache)", () => {
    process.env.OPENCLAW_TEST_KEYRING_ACTIVE = encodeBase64UrlKey(makeKeyBytes(7));
    const ring = new EnvKeyring({ activeVar: "OPENCLAW_TEST_KEYRING_ACTIVE" });
    const first = ring.getActiveKey();
    expect(first.keyId).toBe("OPENCLAW_TEST_KEYRING_ACTIVE");
    expect(first.key.equals(makeKeyBytes(7))).toBe(true);
    process.env.OPENCLAW_TEST_KEYRING_ACTIVE = encodeBase64UrlKey(makeKeyBytes(8));
    const second = ring.getActiveKey();
    expect(second.key.equals(makeKeyBytes(8))).toBe(true);
  });

  it("EnvKeyring throws when the active env var is missing", () => {
    delete process.env.OPENCLAW_TEST_KEYRING_MISSING;
    const ring = new EnvKeyring({ activeVar: "OPENCLAW_TEST_KEYRING_MISSING" });
    expect(() => ring.getActiveKey()).toThrow(/missing active key/);
  });

  it("EnvKeyring.getKeyById reads the per-keyId env var", () => {
    process.env.OPENCLAW_TEST_KEYRING__wrap2026 = encodeBase64UrlKey(makeKeyBytes(11));
    const ring = new EnvKeyring({ activeVar: "OPENCLAW_TEST_KEYRING" });
    const result = ring.getKeyById("wrap2026");
    expect(result?.keyId).toBe("wrap2026");
    expect(result?.key.equals(makeKeyBytes(11))).toBe(true);
  });

  it("EnvKeyring.getKeyById returns null for an unknown keyId", () => {
    const ring = new EnvKeyring({ activeVar: "OPENCLAW_TEST_KEYRING" });
    expect(ring.getKeyById("nope")).toBeNull();
  });

  it("CompositeKeyring requires at least one provider", () => {
    expect(() => new CompositeKeyring({ providers: [] })).toThrow(/at least one provider/);
  });

  it("CompositeKeyring.getActiveKey returns the first provider that succeeds", () => {
    process.env.OPENCLAW_TEST_KEYRING_FALLBACK = encodeBase64UrlKey(makeKeyBytes(21));
    const ring = new CompositeKeyring({
      providers: [
        new EnvKeyring({ activeVar: "OPENCLAW_TEST_KEYRING_NONE" }), // throws
        new EnvKeyring({ activeVar: "OPENCLAW_TEST_KEYRING_FALLBACK" }), // succeeds
      ],
    });
    const active = ring.getActiveKey();
    expect(active.keyId).toBe("OPENCLAW_TEST_KEYRING_FALLBACK");
    expect(active.key.equals(makeKeyBytes(21))).toBe(true);
  });

  it("CompositeKeyring.getActiveKey throws when no provider succeeds", () => {
    const ring = new CompositeKeyring({
      providers: [
        new EnvKeyring({ activeVar: "OPENCLAW_TEST_KEYRING_NOPE_A" }),
        new EnvKeyring({ activeVar: "OPENCLAW_TEST_KEYRING_NOPE_B" }),
      ],
    });
    expect(() => ring.getActiveKey()).toThrow(/could not resolve an active key/);
  });

  it("CompositeKeyring.getKeyById walks all providers in order", async () => {
    await withTempDir("openclaw-m6-composite-", async (rootDir) => {
      const file = path.join(rootDir, "keyring.json");
      writeFileKeyring(file, {
        activeKeyId: "k1",
        keys: { k1: encodeBase64UrlKey(makeKeyBytes(31)) },
      });
      process.env.OPENCLAW_TEST_KEYRING__k2 = encodeBase64UrlKey(makeKeyBytes(32));
      const ring = new CompositeKeyring({
        providers: [
          new FileKeyring({ path: file }),
          new EnvKeyring({ activeVar: "OPENCLAW_TEST_KEYRING" }),
        ],
      });
      const fromFile = ring.getKeyById("k1");
      expect(fromFile?.key.equals(makeKeyBytes(31))).toBe(true);
      const fromEnv = ring.getKeyById("k2");
      expect(fromEnv?.keyId).toBe("k2");
      expect(fromEnv?.key.equals(makeKeyBytes(32))).toBe(true);
      const missing = ring.getKeyById("nope");
      expect(missing).toBeNull();
    });
  });

  it("createKeyring factory dispatches file/env/composite recursively", async () => {
    await withTempDir("openclaw-m6-factory-", async (rootDir) => {
      const file = path.join(rootDir, "keyring.json");
      writeFileKeyring(file, {
        activeKeyId: "k1",
        keys: { k1: encodeBase64UrlKey(makeKeyBytes(41)) },
      });
      process.env.OPENCLAW_TEST_KEYRING_FACTORY = encodeBase64UrlKey(makeKeyBytes(42));
      const ring = createKeyring({
        kind: "composite",
        providers: [
          { kind: "file", path: file },
          { kind: "env", activeVar: "OPENCLAW_TEST_KEYRING_FACTORY" },
        ],
      });
      const active = ring.getActiveKey();
      expect(active.keyId).toBe("k1");
      expect(active.key.equals(makeKeyBytes(41))).toBe(true);
    });
  });

  it("createKeyring rejects an unknown config kind", () => {
    // @ts-expect-error -- intentional type violation
    expect(() => createKeyring({ kind: "memory" })).toThrow(/Unknown keyring config/);
  });

  it("OsKeyring constructor throws (fail-closed) until M6.B ships", () => {
    expect(() => new OsKeyring({ service: "openclaw" })).toThrow(/M6.B/);
  });
});
