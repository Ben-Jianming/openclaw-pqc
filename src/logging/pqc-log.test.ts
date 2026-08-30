// M9 (PQC migration, whitepaper 2.2.9): structured PQC log invariants.
//
// 9 invariants covering: redaction of undefined / Buffer / TypedArray
// values, redaction of secret-named fields (passphrase / rawkey /
// privatekey, case-insensitive), the level-routing pass through
// bindOpenClawLogger, the default-emitter console fallback, and the
// pqcLog chokepoint itself.
import { afterEach, describe, expect, it } from "vitest";
import {
  bindOpenClawLogger,
  getPqcEmit,
  pqcLog,
  PQC_EVENT,
  redactPqcLogPayload,
  resetPqcEmit,
  setPqcEmit,
  type OpenClawLogger,
  type PqcLogPayload,
} from "./pqc-log.js";

afterEach(() => {
  resetPqcEmit();
});

function captureOne(record: PqcLogPayload): PqcLogPayload {
  return record;
}

describe("pqc-log (M9, whitepaper 2.2.9)", () => {
  it("exposes the canonical PQC_EVENT vocabulary", () => {
    expect(PQC_EVENT).toContain("wrap-secret");
    expect(PQC_EVENT).toContain("unwrap-secret");
    expect(PQC_EVENT).toContain("device-identity");
    expect(PQC_EVENT).toContain("keyring");
    expect(PQC_EVENT).toContain("rotation");
    expect(PQC_EVENT).toContain("backup");
    expect(PQC_EVENT).toContain("restore");
    expect(PQC_EVENT).toContain("doctor");
    expect(PQC_EVENT.length).toBe(8);
  });

  it("redacts fields whose name matches passphrase / rawkey / privatekey (case-insensitive)", () => {
    const out = redactPqcLogPayload({
      event: "wrap-secret",
      level: "info",
      status: "ok",
      passphrase: "hunter2-very-secret",
      rawKey: Buffer.from("a-32-byte-secret-key-here-here-he"),
      privateKeyPem: "MLDSA65-SECRET-KEY:secret",
      PASSPHRASE_BACKUP: "openclaw-rotates-wrapping-keys-2026",
      keyId: "wrap-key-2026-08",
    });
    expect(out.passphrase).toBe("[REDACTED]");
    expect(out.rawKey).toBe("[REDACTED]");
    expect(out.privateKeyPem).toBe("[REDACTED]");
    expect(out.PASSPHRASE_BACKUP).toBe("[REDACTED]");
    expect(out.keyId).toBe("wrap-key-2026-08");
  });

  it("drops Buffer / TypedArray values entirely (no [REDACTED] marker)", () => {
    const out = redactPqcLogPayload({
      event: "unwrap-secret",
      level: "info",
      status: "ok",
      ciphertext: Buffer.alloc(32),
      payload: new Uint8Array(8),
      identityKey: "primary",
    });
    expect(Object.prototype.hasOwnProperty.call(out, "ciphertext")).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(out, "payload")).toBe(false);
    expect(out.identityKey).toBe("primary");
  });

  it("drops undefined values from the output", () => {
    const out = redactPqcLogPayload({
      event: "device-identity",
      level: "info",
      status: "ok",
      identityKey: undefined,
      keyId: undefined,
      detail: "fingerprint match",
    });
    expect(Object.prototype.hasOwnProperty.call(out, "identityKey")).toBe(false);
    expect(Object.prototype.hasOwnProperty.call(out, "keyId")).toBe(false);
    expect(out.detail).toBe("fingerprint match");
  });

  it("recurses into nested plain objects and arrays, redacting as it goes", () => {
    const out = redactPqcLogPayload({
      event: "rotation",
      level: "info",
      status: "ok",
      rotated: [
        { identityKey: "primary", passphrase: "should-be-redacted" },
        { identityKey: "secondary", rawKey: "should-be-redacted" },
      ],
      summary: { totalRotated: 2, secretBackup: "should-be-redacted" },
    });
    const rotated = out.rotated as Array<Record<string, unknown>>;
    expect(rotated[0].passphrase).toBe("[REDACTED]");
    expect(rotated[1].rawKey).toBe("[REDACTED]");
    const summary = out.summary as Record<string, unknown>;
    expect(summary.totalRotated).toBe(2);
    expect(summary.secretBackup).toBe("[REDACTED]");
  });

  it("setPqcEmit / getPqcEmit swap the emitter and the chokepoint routes through it", () => {
    const seen: PqcLogPayload[] = [];
    const myEmitter = (record: PqcLogPayload): void => {
      seen.push(record);
    };
    setPqcEmit(myEmitter);
    expect(getPqcEmit()).toBe(myEmitter);
    pqcLog.info({ event: "device-identity", status: "ok", detail: "rotated identity" });
    pqcLog.warn({ event: "keyring", status: "fail", detail: "active key missing" });
    pqcLog.error({ event: "doctor", status: "fail", detail: "stale wrap" });
    pqcLog.debug({ event: "wrap-secret", status: "ok", detail: "test debug" });
    expect(seen).toHaveLength(4);
    expect(seen.map((r) => r.level)).toEqual(["info", "warn", "error", "debug"]);
    expect(seen[0].event).toBe("device-identity");
  });

  it("bindOpenClawLogger routes records by level to the correct sink", () => {
    const info: Record<string, unknown>[] = [];
    const warn: Record<string, unknown>[] = [];
    const error: Record<string, unknown>[] = [];
    const debug: Record<string, unknown>[] = [];
    const logger: OpenClawLogger = {
      info: (r) => info.push(r),
      warn: (r) => warn.push(r),
      error: (r) => error.push(r),
      debug: (r) => debug.push(r),
    };
    bindOpenClawLogger(logger);
    pqcLog.info({ event: "device-identity", status: "ok" });
    pqcLog.warn({ event: "keyring", status: "fail", detail: "no active key" });
    pqcLog.error({ event: "doctor", status: "fail", detail: "needs repair" });
    pqcLog.debug({ event: "wrap-secret", status: "ok" });
    expect(info).toHaveLength(1);
    expect(warn).toHaveLength(1);
    expect(error).toHaveLength(1);
    expect(debug).toHaveLength(1);
    expect(info[0].tag).toBe("PQC");
    expect(info[0].event).toBe("device-identity");
  });

  it("captures the default emitter via console fallback when no other sink is bound", () => {
    const lines: string[] = [];
    const originalLog = console.log;
    console.log = (line: string) => lines.push(line);
    try {
      resetPqcEmit();
      pqcLog.info({ event: "device-identity", status: "ok", detail: "fallback" });
    } finally {
      console.log = originalLog;
    }
    expect(lines).toHaveLength(1);
    expect(lines[0]).toMatch(/^\[PQC\] /);
    const parsed = JSON.parse(lines[0].slice("[PQC] ".length));
    expect(parsed.event).toBe("device-identity");
  });

  it("rejects Buffer / TypedArray values inside arrays as well as top-level", () => {
    const out = redactPqcLogPayload({
      event: "backup",
      level: "info",
      status: "ok",
      backups: [{ envelope: Buffer.from("opaque-payload") }, { envelope: "valid-string-envelope" }],
    });
    const backups = out.backups as Array<Record<string, unknown>>;
    expect(backups[0].envelope).toBeUndefined();
    expect(backups[1].envelope).toBe("valid-string-envelope");
  });

  it("captures the captureOne helper and confirms emitter swap identity", () => {
    const original = getPqcEmit();
    setPqcEmit(captureOne);
    expect(getPqcEmit()).not.toBe(original);
    expect(getPqcEmit()).toBe(captureOne);
    setPqcEmit(original);
  });
});
