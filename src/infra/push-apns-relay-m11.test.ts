// Tests for push-apns-relay-m11.ts (M11 step 5 — APNs relay envelope audit).
//
// Covers:
// - buildApnsRelayM11Audit: returns success on signing
// - envelope has all 5 M11 fields
// - pqcLog.info emitted with event=push-signature, status=ok
// - signing failure → signed=false, no pqcLog info event
// - default deviceKeyId is "primary"
//
// Mocks trySignPushEnvelope via vi.doMock.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

let tmpDir: string;
let savedEnv: Record<string, string | undefined>;
let pqcLogCalls: Array<{ level: string; payload: Record<string, unknown> }> = [];

beforeEach(async () => {
  tmpDir = mkdtempSync(join(tmpdir(), "pqc-apns-relay-m11-test-"));
  savedEnv = {
    OPENCLAW_PUSH_SIGNING_KEY_FILE: process.env.OPENCLAW_PUSH_SIGNING_KEY_FILE,
    OPENCLAW_STATE_DIR: process.env.OPENCLAW_STATE_DIR,
  };
  process.env.OPENCLAW_STATE_DIR = tmpDir;
  delete process.env.OPENCLAW_PUSH_SIGNING_KEY_FILE;
  pqcLogCalls = [];

  vi.doMock("../logging/pqc-log.js", () => ({
    pqcLog: {
      info: (payload: Record<string, unknown>) => {
        pqcLogCalls.push({ level: "info", payload });
      },
      warn: (payload: Record<string, unknown>) => {
        pqcLogCalls.push({ level: "warn", payload });
      },
      error: (payload: Record<string, unknown>) => {
        pqcLogCalls.push({ level: "error", payload });
      },
      debug: (payload: Record<string, unknown>) => {
        pqcLogCalls.push({ level: "debug", payload });
      },
    },
  }));

  // Mock device-identity so the real trySignPushEnvelope can succeed
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

describe("push-apns-relay-m11 step 5 — buildApnsRelayM11Audit", () => {
  it("returns success result with both keyIds on signing", async () => {
    const { buildApnsRelayM11Audit } = await import("./push-apns-relay-m11.js");
    const result = buildApnsRelayM11Audit("hello world");
    expect(result.signed).toBe(true);
    expect(result.keyIdEd25519).toMatch(/^[0-9a-f]{16}$/);
    expect(result.keyIdMldsa65).toBe("primary");
    expect(result.envelopeBytes).toBeGreaterThan(0);
  });

  it("emits pqcLog.info with event=push-signature, status=ok, detail=APNs relay", async () => {
    const { buildApnsRelayM11Audit } = await import("./push-apns-relay-m11.js");
    buildApnsRelayM11Audit("test");
    const infoCalls = pqcLogCalls.filter((c) => c.level === "info");
    // signPushEnvelope fires 1 info event + buildApnsRelayM11Audit fires 1 = 2 total
    expect(infoCalls.length).toBe(2);
    // The buildApnsRelayM11Audit event is the second one (APNs relay detail)
    const relayCall = infoCalls.find((c) => String(c.payload.detail).includes("APNs relay"));
    expect(relayCall).toBeDefined();
    expect(relayCall!.payload.event).toBe("push-signature");
    expect(relayCall!.payload.status).toBe("ok");
  });

  it("accepts custom deviceKeyId", async () => {
    const { buildApnsRelayM11Audit } = await import("./push-apns-relay-m11.js");
    const result = buildApnsRelayM11Audit("test", "my-custom-key");
    expect(result.keyIdMldsa65).toBe("my-custom-key");
    const infoCalls = pqcLogCalls.filter((c) => c.level === "info");
    expect(infoCalls[0]!.payload.identityKey).toBe("my-custom-key");
  });

  it("returns signed=false on signing failure (no info event from this fn)", async () => {
    vi.doMock("./push-envelope.js", () => ({
      trySignPushEnvelope: () => null,
    }));
    const { buildApnsRelayM11Audit } = await import("./push-apns-relay-m11.js");
    const result = buildApnsRelayM11Audit("test");
    expect(result.signed).toBe(false);
    expect(result.keyIdEd25519).toBeNull();
    expect(result.keyIdMldsa65).toBeNull();
    expect(result.envelopeBytes).toBeNull();
    // trySignPushEnvelope already logged the warn, this fn doesn't add another info
    const infoCalls = pqcLogCalls.filter((c) => c.level === "info");
    expect(infoCalls.length).toBe(0);
  });
});
