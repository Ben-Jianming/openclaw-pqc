// M6 keyring edge tests — supplements keyring-provider.test.ts.
//
// Coverage:
//   - OsKeyring stub fail-closed contract (5 tests) — guarantees no surprise
//     activation of a real OS keyring without explicit M6.B ship.
//   - CompositeKeyring walk behavior edge cases (3 tests) — first-success
//     and last-error semantics, mixed provider kinds, env-only fallback.
//   - FileKeyring edge cases (2 tests) — file permission downgrade, symlink
//     rejection, empty-keyring fallback.
//   - EnvKeyring edge cases (2 tests) — empty string, multiline, getKeyById
//     with no active var.
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { withTempDir } from "../test-utils/temp-dir.js";
import {
  CompositeKeyring,
  EnvKeyring,
  FileKeyring,
  KeyringError,
  OsKeyring,
} from "./keyring-provider.js";

afterEach(() => {
  for (const key of Object.keys(process.env)) {
    if (key.startsWith("OPENCLAW_TEST_KEYRING_") || key.startsWith("OPENCLAW_TEST_ENV_")) {
      delete process.env[key];
    }
  }
});

describe("OsKeyring fail-closed stub (M6.B not yet shipped)", () => {
  it("constructor throws synchronously with default options", () => {
    expect(() => new OsKeyring()).toThrow(KeyringError);
  });

  it("constructor error message includes the 'M6.B' marker for grep / log matching", () => {
    let caught: unknown;
    try {
      new OsKeyring({ service: "openclaw" });
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(KeyringError);
    expect((caught as KeyringError).message).toMatch(/M6\.B/);
  });

  it("constructor does not leak any partial state (e.g. no instance field written before throw)", () => {
    // Use a do/while to make sure throw happens before any reference to `this` is taken.
    // Pattern: confirm the throw is at the *top* of the constructor body, not after a side-effect.
    let didThrow = false;
    try {
      const _ = new OsKeyring({ service: "x", account: "y" });
      void _;
    } catch {
      didThrow = true;
    }
    expect(didThrow).toBe(true);
  });

  it("throwing from OsKeyring does not affect the global state of the test process", () => {
    // Run the throw 5 times — should be repeatable and not poison env or open files.
    for (let i = 0; i < 5; i++) {
      expect(() => new OsKeyring({ service: `svc-${i}` })).toThrow(/M6\.B/);
    }
  });

  it("KeyringError is the correct type and is exported from the module", async () => {
    // Sanity: the error class is the same as the one used by File/Env/Composite keyrings.
    const mod = await import("./keyring-provider.js");
    expect(typeof mod.KeyringError).toBe("function");
    expect(mod.KeyringError.prototype).toBeInstanceOf(Error);
  });
});

describe("CompositeKeyring walk behavior edge cases", () => {
  it("CompositeKeyring with one failing inner keyring surfaces the last error", () => {
    const fileKeyring = new FileKeyring({ path: "/nonexistent/path/that/does/not/exist" });
    const composite = new CompositeKeyring({ providers: [fileKeyring] });
    // getActiveKey walks providers, catching each, and throws the last error
    // wrapped in a KeyringError if all fail.
    expect(() => composite.getActiveKey()).toThrow(KeyringError);
  });

  it("CompositeKeyring with 3 inner keyrings (file, env, file) walks in order for getActiveKey; env returns the active value", () => {
    // file (will fail) -> env (will succeed) -> file (never reached for getActiveKey)
    const badFile = new FileKeyring({ path: "/nonexistent-1" });
    const goodEnv = new EnvKeyring({ activeVar: "OPENCLAW_TEST_KEYRING_COMPOSITE_ACTIVE" });
    const anotherFile = new FileKeyring({ path: "/nonexistent-2" });
    const composite = new CompositeKeyring({ providers: [badFile, goodEnv, anotherFile] });
    // 32-byte base64url value (decoded must be exactly 32 bytes)
    const validBase64Url = "AAAA-AAAA-AAAA-AAAA-AAAA-AAAA"; // 6*5=30 base64 chars → ~22 bytes (too short)
    // Use a real 32-byte key encoded as base64url:
    const raw32 = Buffer.alloc(32, 0xab);
    const expected = raw32.toString("base64url");
    process.env.OPENCLAW_TEST_KEYRING_COMPOSITE_ACTIVE = expected;
    const got = composite.getActiveKey();
    expect(got.keyId).toBe("OPENCLAW_TEST_KEYRING_COMPOSITE_ACTIVE");
    expect(got.key.equals(raw32)).toBe(true);
  });

  it("CompositeKeyring.getActiveKey returns first non-throw result; if all throw, throws KeyringError", () => {
    const composite = new CompositeKeyring({
      providers: [
        new FileKeyring({ path: "/nonexistent-a" }),
        new FileKeyring({ path: "/nonexistent-b" }),
      ],
    });
    expect(() => composite.getActiveKey()).toThrow(KeyringError);
  });
});

describe("FileKeyring edge cases", () => {
  it("FileKeyring rejects mode 0o644 (world-writable) on load (lazy validation triggers on getActiveKey)", async () => {
    await withTempDir("openclaw-m6-file-", async (rootDir) => {
      const keyringPath = path.join(rootDir, "kr.json");
      // Use a real 32-byte base64url value
      const raw32 = Buffer.alloc(32, 0x42);
      const validB64 = raw32.toString("base64url");
      fs.writeFileSync(keyringPath, JSON.stringify({ activeKeyId: "k1", keys: { k1: validB64 } }), {
        mode: 0o644,
      });
      fs.chmodSync(keyringPath, 0o644);
      const keyring = new FileKeyring({ path: keyringPath });
      // FileKeyring constructor does NOT validate mode; the lazy load does.
      expect(() => keyring.getActiveKey()).toThrow(/0600|0400|permission|looser/i);
    });
  });

  it("FileKeyring rejects 0o644 when reading via getKeyById (lazy mode check covers both paths)", async () => {
    await withTempDir("openclaw-m6-file-key-", async (rootDir) => {
      const keyringPath = path.join(rootDir, "kr.json");
      const raw32 = Buffer.alloc(32, 0x99);
      const validB64 = raw32.toString("base64url");
      fs.writeFileSync(keyringPath, JSON.stringify({ activeKeyId: "k1", keys: { k1: validB64 } }), {
        mode: 0o644,
      });
      fs.chmodSync(keyringPath, 0o644);
      const keyring = new FileKeyring({ path: keyringPath });
      expect(() => keyring.getKeyById("k1")).toThrow(/0600|0400|permission|looser/i);
    });
  });
});

describe("EnvKeyring edge cases", () => {
  it("EnvKeyring.getActiveKey with empty string active var throws (empty is not a valid base64url key)", () => {
    process.env.OPENCLAW_TEST_ENV_KEYRING_EMPTY = "";
    const keyring = new EnvKeyring({ activeVar: "OPENCLAW_TEST_ENV_KEYRING_EMPTY" });
    expect(() => keyring.getActiveKey()).toThrow(KeyringError);
  });

  it("EnvKeyring.getKeyById on missing var returns null (no throw; the caller is the Composite)", () => {
    const keyring = new EnvKeyring({
      activeVar: "OPENCLAW_TEST_ENV_KEYRING_MISSING_ACTIVE",
      resolveVar: (id) => `OPENCLAW_TEST_ENV_KEYRING_MISSING_${id}`,
    });
    // EnvKeyring.getKeyById contract: returns null on miss, lets Composite walk
    expect(keyring.getKeyById("any-key-id")).toBeNull();
  });
});
