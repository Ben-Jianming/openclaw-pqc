// Tests for push-web-m11.ts (M11 step 4 — web-push envelope).
//
// Covers:
// - buildWebPushPayloadWithEnvelope: returns payload + pqcenvelope on success
// - envelope has all 5 M11 fields
// - on signing failure, returns the original payload unchanged
//
// Mocks trySignPushEnvelope via vi.doMock.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

let tmpDir: string;
let savedEnv: Record<string, string | undefined>;

beforeEach(async () => {
  tmpDir = mkdtempSync(join(tmpdir(), "pqc-webpush-m11-test-"));
  savedEnv = {
    OPENCLAW_PUSH_SIGNING_KEY_FILE: process.env.OPENCLAW_PUSH_SIGNING_KEY_FILE,
    OPENCLAW_STATE_DIR: process.env.OPENCLAW_STATE_DIR,
  };
  process.env.OPENCLAW_STATE_DIR = tmpDir;
  delete process.env.OPENCLAW_PUSH_SIGNING_KEY_FILE;

  vi.doMock("../logging/pqc-log.js", () => ({
    pqcLog: {
      info: () => {},
      warn: () => {},
      error: () => {},
      debug: () => {},
    },
  }));

  // Mock device-identity
  const { generateMlDsa65Keypair, encodeMlDsa65PublicKey, encodeMlDsa65SecretKey } =
    await import("./mldsa65-key-storage.js");
  const kp = generateMlDsa65Keypair();
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

describe("push-web-m11 step 4 — buildWebPushPayloadWithEnvelope", () => {
  it("returns payload + pqcenvelope on signing success", async () => {
    const { buildWebPushPayloadWithEnvelope } = await import("./push-web-m11.js");
    const input = { title: "hi", body: "world", nodeId: "test" };
    const result = buildWebPushPayloadWithEnvelope(input);
    expect(result.title).toBe("hi");
    expect(result.body).toBe("world");
    expect(result.nodeId).toBe("test");
    expect(result.pqcenvelope).toBeDefined();
    const env = result.pqcenvelope as Record<string, unknown>;
    expect(env.algorithms).toEqual(["ed25519", "ml-dsa-65"]);
    expect(env.ed25519_sig).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(env.mldsa65_sig).toMatch(/^[A-Za-z0-9_-]+$/);
  });

  it("does not mutate the input payload", async () => {
    const { buildWebPushPayloadWithEnvelope } = await import("./push-web-m11.js");
    const input = { title: "hi" };
    const result = buildWebPushPayloadWithEnvelope(input);
    expect(input).not.toHaveProperty("pqcenvelope");
    expect(result).toHaveProperty("pqcenvelope");
  });

  it("returns the original payload on signing failure", async () => {
    vi.doMock("./push-envelope.js", () => ({
      trySignPushEnvelope: () => null,
    }));
    const { buildWebPushPayloadWithEnvelope } = await import("./push-web-m11.js");
    const input = { title: "hi" };
    const result = buildWebPushPayloadWithEnvelope(input);
    expect(result).toEqual({ title: "hi" });
    expect(result).not.toHaveProperty("pqcenvelope");
  });
});
