import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { collectPushKeyPolicyHealthFindings } from "../commands/doctor-push-key-policy.js";
import {
  closeOpenClawStateDatabase,
  openOpenClawStateDatabase,
} from "../state/openclaw-state-db.js";
import {
  loadDeviceIdentityIfPresent,
  loadOrCreateProcessDeviceIdentity,
} from "./device-identity.js";
import { getPushEnvelopeVerificationKeys } from "./push-envelope.js";
import {
  enrollExistingPushKeys,
  renewExistingPushKeys,
  revokePushKeyPolicy,
} from "./push-key-policy-store.js";
import { initializePushKeySetup, inspectPushKeySetup } from "./push-key-setup.js";
import { getOrCreatePushSigningKey, resolvePushSigningKeyPath } from "./push-signing-key.js";

let directory: string;
let env: NodeJS.ProcessEnv;
let validity: { validFromMs: number; validUntilMs: number };
beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), "push-key-setup-"));
  env = { ...process.env, OPENCLAW_STATE_DIR: directory };
  delete env.OPENCLAW_PUSH_SIGNING_KEY_FILE;
  validity = { validFromMs: Date.now() - 1000, validUntilMs: Date.now() + 60000 };
});
afterEach(() => {
  vi.useRealTimers();
  closeOpenClawStateDatabase();
  rmSync(directory, { recursive: true, force: true });
});

describe("explicit first-install push key setup and Doctor", () => {
  it.each([false, true])(
    "refuses a replaced Ed25519 key rather than appending it to registered trust (revoked=%s)",
    (revoked) => {
      initializePushKeySetup(validity, env);
      if (revoked) {
        const keys = getPushEnvelopeVerificationKeys(env);
        revokePushKeyPolicy(
          { senderId: keys.senderId, algorithm: "ed25519", keyId: keys.keyIdEd25519 },
          { env },
        );
      }
      const { db } = openOpenClawStateDatabase({ env });
      const original = db.prepare("SELECT * FROM pqc_push_key_policies ORDER BY algorithm").all();
      const identity = loadDeviceIdentityIfPresent({ env });
      rmSync(resolvePushSigningKeyPath(env));
      getOrCreatePushSigningKey(env);
      expect(() => enrollExistingPushKeys(validity, { env })).toThrow(/policy set does not match/);
      expect(() =>
        renewExistingPushKeys(
          { ...validity, validUntilMs: validity.validUntilMs + 60000 },
          { env },
        ),
      ).toThrow(/policy set does not match/);
      expect(db.prepare("SELECT * FROM pqc_push_key_policies ORDER BY algorithm").all()).toEqual(
        original,
      );
      expect(loadDeviceIdentityIfPresent({ env })).toEqual(identity);
    },
  );

  it.each([false, true])(
    "does not treat missing key material as a fresh profile (revoked=%s)",
    (revoked) => {
      initializePushKeySetup(validity, env);
      const keys = getPushEnvelopeVerificationKeys(env);
      if (revoked) {
        revokePushKeyPolicy(
          { senderId: keys.senderId, algorithm: "ed25519", keyId: keys.keyIdEd25519 },
          { env },
        );
      }
      const { db } = openOpenClawStateDatabase({ env });
      const original = db.prepare("SELECT * FROM pqc_push_key_policies ORDER BY algorithm").all();
      db.exec("DELETE FROM device_identities");
      rmSync(resolvePushSigningKeyPath(env));
      expect(loadDeviceIdentityIfPresent({ env })).toBeNull();
      expect(inspectPushKeySetup(env)).toEqual({ ready: false, state: "incomplete" });
      expect(() => initializePushKeySetup(validity, env)).toThrow(/existing key material/);
      expect(existsSync(resolvePushSigningKeyPath(env))).toBe(false);
      expect(loadDeviceIdentityIfPresent({ env })).toBeNull();
      expect(db.prepare("SELECT * FROM pqc_push_key_policies ORDER BY algorithm").all()).toEqual(
        original,
      );
    },
  );

  it.each(["before expiry", "after expiry"])(
    "renews explicitly %s without replacing either identity",
    (when) => {
      initializePushKeySetup(validity, env);
      const identity = loadDeviceIdentityIfPresent({ env });
      const key = readFileSync(resolvePushSigningKeyPath(env));
      const before = getPushEnvelopeVerificationKeys(env);
      vi.useFakeTimers();
      vi.setSystemTime(when === "after expiry" ? validity.validUntilMs : validity.validUntilMs - 1);
      const renewed = { ...validity, validUntilMs: validity.validUntilMs + 60000 };
      renewExistingPushKeys(renewed, { env });
      closeOpenClawStateDatabase();
      const after = getPushEnvelopeVerificationKeys(env);
      expect(after.senderId).toBe(before.senderId);
      expect(after.keyPolicy.ed25519).toEqual({
        ...before.keyPolicy.ed25519,
        validUntilMs: renewed.validUntilMs,
        revision: 2,
      });
      expect(after.keyPolicy.mldsa65).toEqual({
        ...before.keyPolicy.mldsa65,
        validUntilMs: renewed.validUntilMs,
        revision: 2,
      });
      expect(inspectPushKeySetup(env).ready).toBe(true);
      expect(loadDeviceIdentityIfPresent({ env })).toEqual(identity);
      expect(readFileSync(resolvePushSigningKeyPath(env))).toEqual(key);
    },
  );

  it("rejects changed starts and non-extensions without changing either policy", () => {
    initializePushKeySetup(validity, env);
    const before = getPushEnvelopeVerificationKeys(env);
    for (const bounds of [
      {
        ...validity,
        validFromMs: validity.validFromMs - 1,
        validUntilMs: validity.validUntilMs + 60000,
      },
      validity,
      { ...validity, validUntilMs: validity.validUntilMs - 1 },
    ]) {
      expect(() => renewExistingPushKeys(bounds, { env })).toThrow(/renewal requires/);
      expect(getPushEnvelopeVerificationKeys(env)).toEqual(before);
    }
    vi.useFakeTimers();
    vi.setSystemTime(validity.validUntilMs + 60000);
    expect(() =>
      renewExistingPushKeys({ ...validity, validUntilMs: validity.validUntilMs + 1 }, { env }),
    ).toThrow(/renewal requires/);
    expect(getPushEnvelopeVerificationKeys(env)).toEqual(before);
  });

  it.each(["revoked", "missing", "exhausted"])(
    "rolls back the first algorithm when the second is %s",
    (fault) => {
      initializePushKeySetup(validity, env);
      const before = getPushEnvelopeVerificationKeys(env);
      if (fault === "revoked") {
        revokePushKeyPolicy(
          { senderId: before.senderId, algorithm: "ml-dsa-65", keyId: "primary" },
          { env },
        );
      } else {
        const { db } = openOpenClawStateDatabase({ env });
        // Deliberate persisted-state faults exercise the transaction's second-row failure.
        db.exec(
          fault === "missing"
            ? "DELETE FROM pqc_push_key_policies WHERE algorithm = 'ml-dsa-65'"
            : `UPDATE pqc_push_key_policies SET revision = ${Number.MAX_SAFE_INTEGER} WHERE algorithm = 'ml-dsa-65'`,
        );
      }
      expect(() =>
        renewExistingPushKeys(
          { ...validity, validUntilMs: validity.validUntilMs + 60000 },
          { env },
        ),
      ).toThrow(/renewal requires|revision exhausted|policy set does not match/);
      const { db } = openOpenClawStateDatabase({ env });
      expect(
        db
          .prepare(
            "SELECT valid_until_ms, revision FROM pqc_push_key_policies WHERE algorithm = 'ed25519'",
          )
          .get(),
      ).toMatchObject({ valid_until_ms: validity.validUntilMs, revision: 1 });
    },
  );

  it("diagnoses a new profile without provisioning identity, signing key or policy", () => {
    expect(inspectPushKeySetup(env)).toEqual({ ready: false, state: "uninitialized" });
    expect(collectPushKeyPolicyHealthFindings(env)[0]?.message).toContain("uninitialized");
    expect(existsSync(resolvePushSigningKeyPath(env))).toBe(false);
    expect(loadDeviceIdentityIfPresent({ env })).toBeNull();
  });

  it.each([
    { validFromMs: -1, validUntilMs: 1 },
    { validFromMs: 1, validUntilMs: 1 },
    { validFromMs: 0, validUntilMs: Number.MAX_SAFE_INTEGER + 1 },
  ])("rejects invalid bounds before generating keys: %j", (bounds) => {
    expect(() => initializePushKeySetup(bounds, env)).toThrow(/validity/);
    expect(existsSync(resolvePushSigningKeyPath(env))).toBe(false);
    expect(loadDeviceIdentityIfPresent({ env })).toBeNull();
  });

  it("initializes a fresh profile, persists enrollment, and refuses replacement on a second init", () => {
    initializePushKeySetup(validity, env);
    const key = readFileSync(resolvePushSigningKeyPath(env));
    const identity = loadDeviceIdentityIfPresent({ env });
    closeOpenClawStateDatabase();
    expect(inspectPushKeySetup(env)).toMatchObject({
      ready: true,
      state: "ready",
      senderId: identity?.deviceId,
    });
    expect(collectPushKeyPolicyHealthFindings(env)).toEqual([]);
    expect(() => initializePushKeySetup(validity, env)).toThrow(/existing key/);
    expect(readFileSync(resolvePushSigningKeyPath(env))).toEqual(key);
    expect(loadDeviceIdentityIfPresent({ env })).toEqual(identity);
  });

  it.each(["ed25519", "ml-dsa-65"])(
    "does not regenerate partial existing %s material",
    (algorithm) => {
      if (algorithm === "ed25519") {
        getOrCreatePushSigningKey(env);
      } else {
        loadOrCreateProcessDeviceIdentity({ env });
      }
      expect(inspectPushKeySetup(env).state).toBe("incomplete");
      expect(() => initializePushKeySetup(validity, env)).toThrow(/existing key/);
      if (algorithm === "ed25519") {
        expect(loadDeviceIdentityIfPresent({ env })).toBeNull();
      } else {
        expect(existsSync(resolvePushSigningKeyPath(env))).toBe(false);
      }
    },
  );

  it("keeps intact old identities and diagnoses missing enrollment without repairing schema", () => {
    getOrCreatePushSigningKey(env);
    const identity = loadOrCreateProcessDeviceIdentity({ env });
    const key = readFileSync(resolvePushSigningKeyPath(env));
    const { db } = openOpenClawStateDatabase({ env });
    db.exec("DROP TABLE IF EXISTS pqc_push_key_policies");
    expect(inspectPushKeySetup(env)).toMatchObject({ state: "unenrolled", ready: false });
    expect(
      db.prepare("SELECT 1 FROM sqlite_master WHERE name = 'pqc_push_key_policies'").get(),
    ).toBeUndefined();
    expect(collectPushKeyPolicyHealthFindings(env)[0]?.fixHint).toContain("enroll");
    enrollExistingPushKeys(validity, { env });
    expect(inspectPushKeySetup(env).ready).toBe(true);
    expect(loadDeviceIdentityIfPresent({ env })).toEqual(identity);
    expect(readFileSync(resolvePushSigningKeyPath(env))).toEqual(key);
  });

  it("reports the inclusive start and exclusive expiry without renewing the policy", () => {
    initializePushKeySetup(validity, env);
    vi.useFakeTimers();
    vi.setSystemTime(validity.validFromMs - 1);
    expect(inspectPushKeySetup(env).ready).toBe(false);
    vi.setSystemTime(validity.validFromMs);
    expect(inspectPushKeySetup(env).ready).toBe(true);
    vi.setSystemTime(validity.validUntilMs);
    expect(inspectPushKeySetup(env)).toMatchObject({ ready: false, state: "unavailable" });
    expect(collectPushKeyPolicyHealthFindings(env)).toHaveLength(1);
    expect(getPushEnvelopeVerificationKeys(env).keyPolicy.ed25519.validUntilMs).toBe(
      validity.validUntilMs,
    );
  });

  it("reports committed revocation and cannot repair it by init or reenrollment", () => {
    initializePushKeySetup(validity, env);
    const keys = getPushEnvelopeVerificationKeys(env);
    revokePushKeyPolicy(
      { senderId: keys.senderId, algorithm: "ed25519", keyId: keys.keyIdEd25519 },
      { env },
    );
    closeOpenClawStateDatabase();
    const result = inspectPushKeySetup(env);
    expect(result).toMatchObject({ ready: false, state: "unavailable" });
    expect(result.policies?.find((p) => p.algorithm === "ed25519")?.status).toBe("revoked");
    expect(collectPushKeyPolicyHealthFindings(env)[0]?.fixHint).toContain("do not replace");
    expect(() => initializePushKeySetup(validity, env)).toThrow(/existing key/);
    expect(() => enrollExistingPushKeys(validity, { env })).toThrow(/revoked/);
  });
});
