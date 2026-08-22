// Tests for push-envelope.ts (M11 step 2 — high-level dual signature helper).
//
// Covers:
// - signPushEnvelope: returns envelope with all fields, deterministic for same
//   payload (Ed25519 deterministic per RFC 8032), random for ML-DSA-65
//   (FIPS 204 hedged — NOT asserted determinism; per danteng test M11 §3)
// - pqcLog emit: ok on success, fail on missing device (mocked)
// - trySignPushEnvelope: returns null + emits fail pqcLog on error
// - keyId propagation: Ed25519 keyId from push-signing-key, MLDSA65 keyId
//   from options or default "primary"
//
// Mocks loadOrCreateProcessDeviceIdentity to control the ML-DSA-65 key.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { generateMlDsa65Keypair } from "./mldsa65-key-storage.js";
import {
  encodeMlDsa65PublicKey,
  encodeMlDsa65SecretKey,
} from "./mldsa65-key-storage.js";

let tmpDir: string;
let savedEnv: Record<string, string | undefined>;
let pqcLogCalls: Array<{ level: string; payload: Record<string, unknown> }> = [];

beforeEach(async () => {
  tmpDir = mkdtempSync(join(tmpdir(), "pqc-push-envelope-test-"));
  savedEnv = {
    OPENCLAW_PUSH_SIGNING_KEY_FILE: process.env.OPENCLAW_PUSH_SIGNING_KEY_FILE,
    OPENCLAW_STATE_DIR: process.env.OPENCLAW_STATE_DIR,
  };
  process.env.OPENCLAW_STATE_DIR = tmpDir;
  delete process.env.OPENCLAW_PUSH_SIGNING_KEY_FILE;
  pqcLogCalls = [];

  // Mock pqcLog
  vi.doMock("../logging/pqc-log.js", () => ({
    pqcLog: (level: string, payload: Record<string, unknown>) => {
      pqcLogCalls.push({ level, payload });
    },
  }));

  // Mock device-identity to return a fresh ML-DSA-65 keypair
  const { generateMlDsa65Keypair: gen } = await import("./mldsa65-key-storage.js");
  const kp = gen();
  const pemPriv = encodeMlDsa65SecretKey(kp.secretKey);
  const pemPub = encodeMlDsa65PublicKey(kp.publicKey);
  vi.doMock("./device-identity.js", () => ({
    loadOrCreateProcessDeviceIdentity: () => ({
      deviceId: "primary",
      publicKeyPem: pemPub,
      privateKeyPem: pemPriv,
    }),
  }));
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
  vi.doUnmock("../logging/pqc-log.js");
  vi.doUnmock("./device-identity.js");
  vi.resetModules();
});

describe("push-envelope M11 step 2 — signPushEnvelope", () => {
  it("returns envelope with all M11 fields populated", async () => {
    const { signPushEnvelope } = await import("./push-envelope.js");
    const result = signPushEnvelope({ payload: "hello world" });
    expect(result.payload).toBe("hello world");
    expect(result.envelope.algorithms).toEqual(["ed25519", "ml-dsa-65"]);
    expect(result.envelope.ed25519_sig).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(result.envelope.mldsa65_sig).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(result.envelope.key_id_ed25519).toMatch(/^[0-9a-f]{16}$/);
    expect(result.envelope.key_id_mldsa65).toBe("primary");
    expect(result.keyIdEd25519).toBe(result.envelope.key_id_ed25519);
    expect(result.keyIdMldsa65).toBe("primary");
  });

  it("emits pqcLog.info with event=push-signature, status=ok on success", async () => {
    const { signPushEnvelope } = await import("./push-envelope.js");
    signPushEnvelope({ payload: "test" });
    expect(pqcLogCalls.length).toBe(1);
    expect(pqcLogCalls[0]!.level).toBe("info");
    expect(pqcLogCalls[0]!.payload.event).toBe("push-signature");
    expect(pqcLogCalls[0]!.payload.status).toBe("ok");
    expect(pqcLogCalls[0]!.payload.payloadBytes).toBe(4);
  });

  it("Ed25519 signature is deterministic for the same payload (RFC 8032)", async () => {
    const { signPushEnvelope } = await import("./push-envelope.js");
    const a = signPushEnvelope({ payload: "deterministic-test" });
    const b = signPushEnvelope({ payload: "deterministic-test" });
    expect(a.envelope.ed25519_sig).toBe(b.envelope.ed25519_sig);
  });

  it("accepts custom keyIdMldsa65 override", async () => {
    const { signPushEnvelope } = await import("./push-envelope.js");
    const result = signPushEnvelope({ payload: "x", keyIdMldsa65: "custom-key" });
    expect(result.envelope.key_id_mldsa65).toBe("custom-key");
  });

  it("rejects non-string payload", async () => {
    const { signPushEnvelope } = await import("./push-envelope.js");
    expect(() => signPushEnvelope({ payload: 123 as unknown as string })).toThrow(
      /payload must be a UTF-8 string/,
    );
  });
});

describe("push-envelope M11 step 2 — trySignPushEnvelope", () => {
  it("returns the same result as signPushEnvelope on success", async () => {
    const { signPushEnvelope, trySignPushEnvelope } = await import("./push-envelope.js");
    const a = signPushEnvelope({ payload: "abc" });
    const b = trySignPushEnvelope({ payload: "abc" });
    expect(b).not.toBeNull();
    expect(b!.envelope.algorithms).toEqual(a.envelope.algorithms);
  });

  it("returns null and emits pqcLog.warn with status=fail on error", async () => {
    // Force signPushPayloadDual to throw by mocking it
    vi.doMock("../security/push-dual-signature.js", () => ({
      signPushPayloadDual: () => {
        throw new Error("forced signing failure");
      },
    }));
    const { trySignPushEnvelope } = await import("./push-envelope.js");
    const result = trySignPushEnvelope({ payload: "fail" });
    expect(result).toBeNull();
    expect(pqcLogCalls.length).toBe(1);
    expect(pqcLogCalls[0]!.level).toBe("warn");
    expect(pqcLogCalls[0]!.payload.event).toBe("push-signature");
    expect(pqcLogCalls[0]!.payload.status).toBe("fail");
  });
});
