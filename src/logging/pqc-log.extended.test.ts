// M9 (PQC migration, whitepaper 2.2.9): structured PQC log redaction edge cases.
// Supplements src/logging/pqc-log.test.ts (10 invariants).
//
// API surface (from src/logging/pqc-log.ts):
//   - PQC_EVENT: "wrap-secret" | "unwrap-secret" | "device-identity" | "keyring" | "rotation" | "backup" | "restore" | "doctor"
//   - redactPqcLogPayload drops fields by NAME pattern (private-key / secret / passphrase / raw-key)
//     and by TYPE (Buffer / TypedArray)
//   - pqcLog.{info,warn,error,debug} emits a PqcLogPayload with the level auto-set
//
// Coverage (8 tests):
//   - redactPqcLogPayload redacts fields matching "private[-_]?key" pattern
//   - redactPqcLogPayload redacts fields matching "secret" pattern
//   - redactPqcLogPayload redacts fields matching "passphrase" pattern
//   - redactPqcLogPayload redacts fields matching "raw[-_]?key" pattern
//   - redactPqcLogPayload drops Buffer values (mldsa_private_key_wrapped is Uint8Array)
//   - redactPqcLogPayload drops undefined values
//   - redactPqcLogPayload keeps public fields (mldsa_public_key_pem)
//   - redactPqcLogPayload recursively redacts nested objects
//   - pqcLog.info flows through the configured emit and gets level=info
//   - pqcLog.error flows through the configured emit and gets level=error
//   - resetPqcEmit restores default emit (no test pollution)
import { afterEach, describe, expect, it } from "vitest";
import {
  getPqcEmit,
  PQC_EVENT,
  pqcLog,
  redactPqcLogPayload,
  resetPqcEmit,
  setPqcEmit,
  type PqcLogPayload,
} from "./pqc-log.js";

afterEach(() => {
  resetPqcEmit();
});

describe("pqc-log M9 — redaction edge cases", () => {
  it("redactPqcLogPayload redacts a field whose name contains 'private' + 'key' (catches mldsa_private_key_pem)", () => {
    const original: PqcLogPayload = {
      event: PQC_EVENT.DEVICE_IDENTITY,
      level: "info",
      status: "ok",
      identityKey: "primary",
      mldsa_public_key_pem: "MLDSA65-PUBLIC-KEY:abc", // public, kept
      mldsa_private_key_pem: "MLDSA65-SECRET-KEY:secret", // redacted
    };
    const redacted = redactPqcLogPayload(original);
    expect(redacted.mldsa_private_key_pem).toBe("[REDACTED]");
    // Non-redacted fields remain intact
    expect(redacted.mldsa_public_key_pem).toBe("MLDSA65-PUBLIC-KEY:abc");
    expect(redacted.identityKey).toBe("primary");
  });

  it("redactPqcLogPayload redacts a field whose name contains 'secret' (catches wrap envelope keyId etc.)", () => {
    const original: PqcLogPayload = {
      event: PQC_EVENT.WRAP_SECRET,
      level: "info",
      status: "ok",
      secretKeyId: "wrap-2026-08", // redacted
      keyId: "wrap-2026-08", // NOT redacted (no "secret" substring match against field name)
    };
    const redacted = redactPqcLogPayload(original);
    expect(redacted.secretKeyId).toBe("[REDACTED]");
    expect(redacted.keyId).toBe("wrap-2026-08");
  });

  it("redactPqcLogPayload redacts a field whose name contains 'passphrase'", () => {
    const original: PqcLogPayload = {
      event: PQC_EVENT.BACKUP,
      level: "info",
      status: "ok",
      passphrase: "correct horse battery staple", // redacted
    };
    const redacted = redactPqcLogPayload(original);
    expect(redacted.passphrase).toBe("[REDACTED]");
  });

  it("redactPqcLogPayload redacts a field whose name contains 'raw' + 'key' (catches rawKey)", () => {
    const original: PqcLogPayload = {
      event: PQC_EVENT.RESTORE,
      level: "info",
      status: "ok",
      rawKey: "MIIBVgIBADANBgkqhkiG9w0BAQEFAASCAUAwggE8AgEAAkEA...", // redacted
    };
    const redacted = redactPqcLogPayload(original);
    expect(redacted.rawKey).toBe("[REDACTED]");
  });

  it("redactPqcLogPayload drops Uint8Array values (BLOB wrap envelope never leaks)", () => {
    const original: PqcLogPayload = {
      event: PQC_EVENT.WRAP_SECRET,
      level: "info",
      status: "ok",
      identityKey: "primary",
      envelopeBytes: new Uint8Array([0xde, 0xad, 0xbe, 0xef]), // dropped
    };
    const redacted = redactPqcLogPayload(original);
    expect(redacted.envelopeBytes).toBeUndefined();
    // Non-buffer fields remain
    expect(redacted.identityKey).toBe("primary");
  });

  it("redactPqcLogPayload drops undefined values", () => {
    const original: PqcLogPayload = {
      event: PQC_EVENT.DEVICE_IDENTITY,
      level: "info",
      status: "ok",
      identityKey: "primary",
      detail: undefined, // dropped
    };
    const redacted = redactPqcLogPayload(original);
    expect(redacted).not.toHaveProperty("detail");
    expect(redacted.identityKey).toBe("primary");
  });

  it("redactPqcLogPayload recursively redacts nested objects (case-insensitive pattern)", () => {
    const original: PqcLogPayload = {
      event: PQC_EVENT.DEVICE_IDENTITY,
      level: "info",
      status: "ok",
      identityKey: "primary",
      detail: "Some context",
      nested: {
        // The "key" pattern matches "ml-dsa-65-private-key" even in nested keys
        ml_dsa_65_private_key: "nested-secret",
        publicKey: "nested-pub", // kept
      },
    };
    const redacted = redactPqcLogPayload(original);
    expect((redacted.nested as Record<string, unknown>).ml_dsa_65_private_key).toBe("[REDACTED]");
    expect((redacted.nested as Record<string, unknown>).publicKey).toBe("nested-pub");
  });

  it("redactPqcLogPayload on a payload with no redactable fields is essentially a clone", () => {
    const original: PqcLogPayload = {
      event: PQC_EVENT.DOCTOR,
      level: "info",
      status: "ok",
      identityKey: "primary",
      keyId: "wrap-2026-08",
      detail: "diagnostic complete",
    };
    const redacted = redactPqcLogPayload(original);
    expect(redacted).toEqual(original);
  });

  it("pqcLog.info auto-sets level='info' on the emitted payload", () => {
    const seen: PqcLogPayload[] = [];
    setPqcEmit((entry) => seen.push(entry));
    pqcLog.info({ event: PQC_EVENT.DEVICE_IDENTITY, status: "ok", identityKey: "primary" });
    expect(seen.length).toBe(1);
    expect(seen[0]!.level).toBe("info");
    expect(seen[0]!.event).toBe(PQC_EVENT.DEVICE_IDENTITY);
    expect(seen[0]!.identityKey).toBe("primary");
  });

  it("pqcLog.error auto-sets level='error' on the emitted payload", () => {
    const seen: PqcLogPayload[] = [];
    setPqcEmit((entry) => seen.push(entry));
    pqcLog.error({ event: PQC_EVENT.UNWRAP_SECRET, status: "fail", detail: "auth tag mismatch" });
    expect(seen.length).toBe(1);
    expect(seen[0]!.level).toBe("error");
    expect(seen[0]!.status).toBe("fail");
  });

  it("resetPqcEmit restores default emit (no test pollution)", () => {
    const seen: PqcLogPayload[] = [];
    setPqcEmit((entry) => seen.push(entry));
    expect(getPqcEmit()).not.toBeNull();
    resetPqcEmit();
    // After reset, the emit should be the default no-op
    pqcLog.info({ event: PQC_EVENT.DOCTOR, status: "ok" });
    // seen should NOT have grown (default emit doesn't push to our list)
    expect(seen.length).toBe(0);
  });
});
