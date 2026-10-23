import { existsSync, mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { InMemoryPushReplayGuard } from "../security/push-dual-signature.js";
import { assertPushKeyPolicy } from "../shared/push-key-policy.js";
import {
  closeOpenClawStateDatabase,
  openOpenClawStateDatabase,
} from "../state/openclaw-state-db.js";
import {
  loadDeviceIdentityIfPresent,
  loadOrCreateProcessDeviceIdentity,
} from "./device-identity.js";
import {
  getPushEnvelopeVerificationKeys,
  signPushEnvelope,
  verifySignedPushEnvelope,
} from "./push-envelope.js";
import { enrollExistingPushKeys, revokePushKeyPolicy } from "./push-key-policy-store.js";
import { getOrCreatePushSigningKey, resolvePushSigningKeyPath } from "./push-signing-key.js";

let directory: string;
let env: NodeJS.ProcessEnv;
let nowMs: number;
beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), "push-key-policy-"));
  env = { ...process.env, OPENCLAW_STATE_DIR: directory };
  delete env.OPENCLAW_PUSH_SIGNING_KEY_FILE;
  nowMs = Date.now();
});
afterEach(() => {
  vi.useRealTimers();
  closeOpenClawStateDatabase();
  rmSync(directory, { recursive: true, force: true });
});
function provision() {
  getOrCreatePushSigningKey(env);
  loadOrCreateProcessDeviceIdentity({ env });
}
function enroll() {
  enrollExistingPushKeys({ validFromMs: nowMs - 1000, validUntilMs: nowMs + 60000 }, { env });
}

describe("explicit persistent push policy enrollment", () => {
  it("does not generate missing keys during enrollment, key RPC provisioning or signing", () => {
    expect(() => enroll()).toThrow(/missing/);
    expect(() => getPushEnvelopeVerificationKeys(env)).toThrow(/missing/);
    expect(() => signPushEnvelope({ payload: "x", env })).toThrow(/missing/);
    expect(existsSync(resolvePushSigningKeyPath(env))).toBe(false);
    expect(loadDeviceIdentityIfPresent({ env })).toBeNull();
  });
  it("refuses unregistered existing keys, and preserves both identities during idempotent enrollment", () => {
    provision();
    const secretBefore = readFileSync(resolvePushSigningKeyPath(env));
    const identityBefore = loadDeviceIdentityIfPresent({ env });
    expect(() => getPushEnvelopeVerificationKeys(env)).toThrow(/explicit enrollment/);
    expect(() => signPushEnvelope({ payload: "x", env })).toThrow(/explicit enrollment/);
    enroll();
    enroll();
    const keys = getPushEnvelopeVerificationKeys(env);
    expect(keys.keyPolicyVersion).toBe(1);
    expect(keys.keyPolicy.ed25519.revision).toBe(1);
    expect(keys.keyPolicy.mldsa65.publicKeyBase64Url).toBe(keys.mldsa65PublicKeyBase64Url);
    expect(readFileSync(resolvePushSigningKeyPath(env))).toEqual(secretBefore);
    expect(loadDeviceIdentityIfPresent({ env })).toEqual(identityBefore);
    closeOpenClawStateDatabase();
    expect(getPushEnvelopeVerificationKeys(env)).toEqual(keys);
    expect(() =>
      enrollExistingPushKeys({ validFromMs: nowMs - 1000, validUntilMs: nowMs + 120000 }, { env }),
    ).toThrow(/differs/);
  });
  it.each(["ed25519", "ml-dsa-65"] as const)(
    "persists %s revocation and refuses signing, verification and reenrollment",
    (algorithm) => {
      provision();
      enroll();
      const signed = signPushEnvelope({ payload: "verified", env });
      const keys = getPushEnvelopeVerificationKeys(env);
      expect(
        verifySignedPushEnvelope({
          ...signed,
          trustedKeys: keys,
          expectedRecipientId: keys.senderId,
          replayGuard: new InMemoryPushReplayGuard(),
        }),
      ).toBe(true);
      const key = {
        algorithm,
        senderId: keys.senderId,
        keyId: algorithm === "ed25519" ? keys.keyIdEd25519 : keys.keyIdMldsa65,
      };
      revokePushKeyPolicy(key, { env });
      revokePushKeyPolicy(key, { env });
      closeOpenClawStateDatabase();
      const revoked = getPushEnvelopeVerificationKeys(env);
      const policy =
        algorithm === "ed25519" ? revoked.keyPolicy.ed25519 : revoked.keyPolicy.mldsa65;
      expect(policy.status).toBe("revoked");
      expect(policy.revision).toBe(2);
      expect(() => signPushEnvelope({ payload: "x", env })).toThrow(/policy/);
      expect(() =>
        verifySignedPushEnvelope({
          ...signed,
          trustedKeys: revoked,
          expectedRecipientId: keys.senderId,
          replayGuard: new InMemoryPushReplayGuard(),
        }),
      ).toThrow(/policy/);
      expect(() => enroll()).toThrow(/revoked/);
    },
  );
  it("refuses expiry at the exact boundary in both signer and high-level verifier", () => {
    provision();
    enroll();
    const keys = getPushEnvelopeVerificationKeys(env);
    const signed = signPushEnvelope({ payload: "x", env });
    const until = keys.keyPolicy.ed25519.validUntilMs;
    expect(
      verifySignedPushEnvelope({
        ...signed,
        trustedKeys: keys,
        expectedRecipientId: keys.senderId,
        replayGuard: new InMemoryPushReplayGuard(),
        nowMs: until - 1,
      }),
    ).toBe(true);
    expect(() =>
      verifySignedPushEnvelope({
        ...signed,
        trustedKeys: keys,
        expectedRecipientId: keys.senderId,
        replayGuard: new InMemoryPushReplayGuard(),
        nowMs: until,
      }),
    ).toThrow(/policy/);
    vi.useFakeTimers({ toFake: ["Date"] });
    vi.setSystemTime(until);
    expect(() => signPushEnvelope({ payload: "x", env })).toThrow(/policy/);
  });
  it("rejects a changed public key under the same policy id", () => {
    provision();
    enroll();
    const keys = getPushEnvelopeVerificationKeys(env);
    expect(() =>
      assertPushKeyPolicy(
        keys.keyPolicy.ed25519,
        "ed25519",
        keys.keyIdEd25519,
        keys.senderId,
        "changed-public-key",
        nowMs,
      ),
    ).toThrow(/policy/);
  });
  it.each([
    [Number.NaN, 100],
    [1, Infinity],
    [-1, 100],
    [1.5, 100],
    [100, 100],
    [101, 100],
  ])(
    "refuses malformed enrollment bounds %s/%s before creating material",
    (validFromMs, validUntilMs) => {
      expect(() => enrollExistingPushKeys({ validFromMs, validUntilMs }, { env })).toThrow(
        /validity/,
      );
      expect(existsSync(resolvePushSigningKeyPath(env))).toBe(false);
    },
  );
  it("adds policy storage without changing the shared SQLite schema version", () => {
    provision();
    const before = openOpenClawStateDatabase({ env }).db.prepare("PRAGMA user_version").get();
    enroll();
    const after = openOpenClawStateDatabase({ env }).db.prepare("PRAGMA user_version").get();
    expect(after).toEqual(before);
  });
});
