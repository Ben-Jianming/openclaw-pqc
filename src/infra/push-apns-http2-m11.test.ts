// Tests for push-apns-http2-m11.ts (M11 step 3 — APNs HTTP/2 envelope header).
//
// Covers:
// - buildApnsEnvelopeHeader: happy path (returns base64url JSON)
// - signing fail → header=null, reason=sign-failed
// - oversized envelope → header=null, reason=too-large (mocked to return huge envelope)
// - pqcLog emit on success / failure
// - APNS_PQC_ENVELOPE_HEADER constant
// - APNS_PQC_ENVELOPE_MAX_HEADER_BYTES constant
//
// Mocks trySignPushEnvelope via vi.doMock on push-envelope.

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

let tmpDir: string;
let savedEnv: Record<string, string | undefined>;
let pqcLogCalls: Array<{ level: string; payload: Record<string, unknown> }> = [];

beforeEach(async () => {
  tmpDir = mkdtempSync(join(tmpdir(), "pqc-apns-m11-test-"));
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

  // Mock device-identity to return a fresh ML-DSA-65 keypair (so the real
  // signPushEnvelope can succeed without a sqlite device identity)
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

describe("push-apns-http2-m11 step 3 — constants", () => {
  it("uses apns-pqc-envelope as the custom HTTP/2 header", async () => {
    const { APNS_PQC_ENVELOPE_HEADER } = await import("./push-apns-http2-m11.js");
    expect(APNS_PQC_ENVELOPE_HEADER).toBe("apns-pqc-envelope");
  });

  it("caps envelope header at 8 KB (HTTP/2 conservative)", async () => {
    const { APNS_PQC_ENVELOPE_MAX_HEADER_BYTES } = await import(
      "./push-apns-http2-m11.js"
    );
    expect(APNS_PQC_ENVELOPE_MAX_HEADER_BYTES).toBe(8 * 1024);
  });
});

describe("push-apns-http2-m11 step 3 — buildApnsEnvelopeHeader", () => {
  it("returns a base64url header on signing success", async () => {
    const { buildApnsEnvelopeHeader } = await import("./push-apns-http2-m11.js");
    const result = buildApnsEnvelopeHeader({ aps: { alert: "hi" }, nodeId: "test" });
    expect(result.reason).toBe("ok");
    expect(result.header).not.toBeNull();
    expect(result.header!).toMatch(/^[A-Za-z0-9_-]+$/);  // base64url
    expect(result.envelopeBytes).toBeGreaterThan(0);
    // Verify the header is valid base64url that decodes to a valid envelope JSON
    const decoded = Buffer.from(result.header!, "base64url").toString("utf8");
    const env = JSON.parse(decoded);
    expect(env.algorithms).toEqual(["ed25519", "ml-dsa-65"]);
    expect(env.ed25519_sig).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(env.mldsa65_sig).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(env.key_id_ed25519).toMatch(/^[0-9a-f]{16}$/);
    expect(env.key_id_mldsa65).toBe("primary");
  });

  it("emits pqcLog.info on success (already covered by signPushEnvelope, but verify call is allowed)", async () => {
    const { buildApnsEnvelopeHeader } = await import("./push-apns-http2-m11.js");
    buildApnsEnvelopeHeader({ test: true });
    // trySignPushEnvelope would have emitted info, but our buildApnsEnvelopeHeader
    // only emits warn on degraded mode. Verify no warn was emitted.
    const warnCalls = pqcLogCalls.filter((c) => c.level === "warn");
    expect(warnCalls.length).toBe(0);
  });

  it("returns header=null, reason=sign-failed when trySignPushEnvelope fails", async () => {
    vi.doMock("./push-envelope.js", () => ({
      trySignPushEnvelope: () => null,
    }));
    const { buildApnsEnvelopeHeader } = await import("./push-apns-http2-m11.js");
    const result = buildApnsEnvelopeHeader({ test: true });
    expect(result.header).toBeNull();
    expect(result.reason).toBe("sign-failed");
    expect(result.envelopeBytes).toBe(0);
    // No warn from buildApnsEnvelopeHeader itself (trySignPushEnvelope already logged)
    const warnCalls = pqcLogCalls.filter(
      (c) => c.level === "warn" && c.payload.detail?.toString().includes("header"),
    );
    expect(warnCalls.length).toBe(0);
  });

  it("returns header=null, reason=too-large when envelope exceeds 8 KB", async () => {
    // Mock trySignPushEnvelope to return a giant envelope
    const hugeEnvelope = {
      algorithms: ["ed25519", "ml-dsa-65"] as ["ed25519", "ml-dsa-65"],
      ed25519_sig: "x".repeat(100),
      mldsa65_sig: "y".repeat(20000),  // way over 8 KB after base64url
      key_id_ed25519: "k1",
      key_id_mldsa65: "k2",
    };
    vi.doMock("./push-envelope.js", () => ({
      trySignPushEnvelope: () => ({
        payload: "{}",
        envelope: hugeEnvelope,
        keyIdEd25519: "k1",
        keyIdMldsa65: "k2",
      }),
    }));
    const { buildApnsEnvelopeHeader } = await import("./push-apns-http2-m11.js");
    const result = buildApnsEnvelopeHeader({ test: true });
    expect(result.header).toBeNull();
    expect(result.reason).toBe("too-large");
    expect(result.envelopeBytes).toBeGreaterThan(8 * 1024);
    // Verify warn was emitted
    const warnCalls = pqcLogCalls.filter(
      (c) => c.level === "warn" && c.payload.event === "push-signature",
    );
    expect(warnCalls.length).toBe(1);
    expect(warnCalls[0]!.payload.detail).toMatch(/exceeds APNs custom header size cap/);
  });
});
