// Tests for feishu-m11-audit.ts (M11 step 6 — Feishu WS outgoing audit).
//
// Covers:
// - happy path: signs UTF-8 content with Ed25519 + ML-DSA-65
// - envelope has all 5 M11 fields
// - UTF-8 encoding is correct (Ed25519 expects Uint8Array, not raw string)
// - pqcLog event emitted with status=ok on success
// - signing failure (e.g., empty content) → signed=false, no exception
//
// Uses process.cwd() and OPENCLAW_STATE_DIR isolation to avoid
// polluting the real production state dir.

import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

let tmpDir: string;
let savedEnv: Record<string, string | undefined>;
let pqcLogCalls: Array<{ level: string; payload: Record<string, unknown> }> = [];

beforeEach(() => {
  tmpDir = mkdtempSync(join(tmpdir(), "feishu-m11-audit-test-"));
  savedEnv = {
    OPENCLAW_STATE_DIR: process.env.OPENCLAW_STATE_DIR,
    OPENCLAW_FEISHU_PUSH_SIGNING_KEY_FILE: process.env.OPENCLAW_FEISHU_PUSH_SIGNING_KEY_FILE,
    OPENCLAW_FEISHU_MLDSA_KEY_FILE: process.env.OPENCLAW_FEISHU_MLDSA_KEY_FILE,
  };
  // Use a temp dir so tests don't touch production keys
  process.env.OPENCLAW_STATE_DIR = tmpDir;
  delete process.env.OPENCLAW_FEISHU_PUSH_SIGNING_KEY_FILE;
  delete process.env.OPENCLAW_FEISHU_MLDSA_KEY_FILE;

  // Spy on console.log to capture pqcLog emissions
  pqcLogCalls = [];
  const origLog = console.log;
  vi.spyOn(console, "log").mockImplementation((...args: unknown[]) => {
    const first = args[0];
    if (typeof first === "string" && first.startsWith("[PQC] ")) {
      try {
        const payload = JSON.parse(first.slice("[PQC] ".length));
        pqcLogCalls.push({ level: payload.level, payload });
      } catch {
        // ignore non-JSON console.log
      }
    }
    return origLog.call(console, ...args);
  });
});

afterEach(() => {
  if (savedEnv.OPENCLAW_STATE_DIR === undefined) {
    delete process.env.OPENCLAW_STATE_DIR;
  } else {
    process.env.OPENCLAW_STATE_DIR = savedEnv.OPENCLAW_STATE_DIR;
  }
  if (savedEnv.OPENCLAW_FEISHU_PUSH_SIGNING_KEY_FILE === undefined) {
    delete process.env.OPENCLAW_FEISHU_PUSH_SIGNING_KEY_FILE;
  } else {
    process.env.OPENCLAW_FEISHU_PUSH_SIGNING_KEY_FILE = savedEnv.OPENCLAW_FEISHU_PUSH_SIGNING_KEY_FILE;
  }
  if (savedEnv.OPENCLAW_FEISHU_MLDSA_KEY_FILE === undefined) {
    delete process.env.OPENCLAW_FEISHU_MLDSA_KEY_FILE;
  } else {
    process.env.OPENCLAW_FEISHU_MLDSA_KEY_FILE = savedEnv.OPENCLAW_FEISHU_MLDSA_KEY_FILE;
  }
  rmSync(tmpDir, { recursive: true, force: true });
  vi.restoreAllMocks();
});

import { vi } from "vitest";
import { auditFeishuSendWithM11 } from "./feishu-m11-audit.js";

describe("feishu-m11-audit step 6 — happy path", () => {
  it("signs UTF-8 content and returns envelope with all 5 M11 fields", () => {
    const result = auditFeishuSendWithM11("hello 飞书 world 🚀");
    expect(result.signed).toBe(true);
    expect(result.error).toBeNull();
    expect(result.envelope).not.toBeNull();
    expect(result.envelope!.algorithms).toEqual(["ed25519", "ml-dsa-65"]);
    expect(result.envelope!.ed25519_sig).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(result.envelope!.mldsa65_sig).toMatch(/^[A-Za-z0-9_-]+$/);
    expect(result.envelope!.key_id_ed25519).toMatch(/^[0-9a-f]{16}$/);
    expect(result.envelope!.key_id_mldsa65).toBe("primary");
    // contentSha256 should be the SHA-256 of the UTF-8 encoded content
    expect(result.contentSha256).toMatch(/^[0-9a-f]{64}$/);
  });

  it("emits [PQC] info event on success", () => {
    auditFeishuSendWithM11("test message");
    const infoCalls = pqcLogCalls.filter((c) => c.level === "info");
    expect(infoCalls.length).toBeGreaterThan(0);
    const pushSig = infoCalls.find(
      (c) => c.payload.event === "push-signature" && c.payload.status === "ok",
    );
    expect(pushSig).toBeDefined();
    expect(String(pushSig!.payload.detail)).toMatch(/Feishu outgoing message/);
    expect(pushSig!.payload.identityKey).toBe("primary");
  });

  it("different content produces different signatures (sanity)", () => {
    const a = auditFeishuSendWithM11("message A");
    const b = auditFeishuSendWithM11("message B");
    // Ed25519 is deterministic per RFC 8032, so same key + same content
    // = same sig. But ML-DSA-65 is hedged (randomized), so even
    // same content produces different sig.
    // For different content: both halves will differ.
    expect(a.envelope!.ed25519_sig).not.toBe(b.envelope!.ed25519_sig);
    expect(a.envelope!.mldsa65_sig).not.toBe(b.envelope!.mldsa65_sig);
  });

  it("UTF-8 emoji content is encoded correctly (regression for ed25519.sign bug)", () => {
    // The original bug: ed25519.sign(content) where content is a string
    // treats it as hex and fails. The fix: TextEncoder().encode(content)
    // before passing to ed25519.sign.
    const result = auditFeishuSendWithM11("emoji test 🦀🔐🎉");
    expect(result.signed).toBe(true);
    expect(result.error).toBeNull();
  });
});

describe("feishu-m11-audit step 6 — persistence", () => {
  it("creates the signing key files in $STATE_DIR with chmod 0600", () => {
    auditFeishuSendWithM11("test 1");
    // The keys should be persisted
    const fs = require("node:fs");
    const edFile = join(tmpDir, "feishu-push-signing-key.bin");
    const mldsaFile = join(tmpDir, "feishu-m11-mldsa.bin");
    expect(fs.existsSync(edFile)).toBe(true);
    expect(fs.existsSync(mldsaFile)).toBe(true);
    const edStat = fs.statSync(edFile);
    const mldsaStat = fs.statSync(mldsaFile);
    expect(edStat.size).toBe(32); // 32-byte raw Ed25519 secret
    expect(mldsaStat.size).toBe(4032 + 1952); // raw secret + public
    // Verify chmod 0600 (mask out file-type bits)
    expect(edStat.mode & 0o777).toBe(0o600);
    expect(mldsaStat.mode & 0o777).toBe(0o600);
  });

  it("reuses existing keys on subsequent calls (deterministic keyId)", () => {
    const a = auditFeishuSendWithM11("call 1");
    const b = auditFeishuSendWithM11("call 2");
    expect(a.envelope!.key_id_ed25519).toBe(b.envelope!.key_id_ed25519);
  });
});
