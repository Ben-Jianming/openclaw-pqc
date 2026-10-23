import { existsSync } from "node:fs";
import { assertPushKeyPolicy } from "../shared/push-key-policy.js";
import {
  loadDeviceIdentityIfPresent,
  loadOrCreateProcessDeviceIdentity,
} from "./device-identity.js";
import { getPushEnvelopeVerificationKeys } from "./push-envelope.js";
import {
  enrollExistingPushKeys,
  hasStoredPushKeyPolicies,
  PushKeyEnrollmentRequiredError,
} from "./push-key-policy-store.js";
import { getOrCreatePushSigningKey, resolvePushSigningKeyPath } from "./push-signing-key.js";

export type PushKeySetupStatus = {
  ready: boolean;
  state: "uninitialized" | "incomplete" | "unenrolled" | "ready" | "unavailable";
  senderId?: string;
  policies?: {
    algorithm: "ed25519" | "ml-dsa-65";
    keyId: string;
    status: "active" | "revoked";
    validFromMs: number;
    validUntilMs: number;
    revision: number;
  }[];
};

/** No new identity, enrollment, lifetime, or repair is inferred by a diagnostic. */
export function inspectPushKeySetup(env: NodeJS.ProcessEnv = process.env): PushKeySetupStatus {
  const identity = loadDeviceIdentityIfPresent({ env });
  const hasEd25519 = existsSync(resolvePushSigningKeyPath(env));
  if (!identity || !hasEd25519) {
    return {
      ready: false,
      state:
        !identity && !hasEd25519 && !hasStoredPushKeyPolicies({ env })
          ? "uninitialized"
          : "incomplete",
    };
  }
  try {
    const keys = getPushEnvelopeVerificationKeys(env);
    const policies = [keys.keyPolicy.ed25519, keys.keyPolicy.mldsa65];
    const nowMs = Date.now();
    let ready = true;
    for (const policy of policies) {
      try {
        assertPushKeyPolicy(
          policy,
          policy.algorithm,
          policy.keyId,
          keys.senderId,
          policy.publicKeyBase64Url,
          nowMs,
        );
      } catch {
        ready = false;
      }
    }
    return {
      ready,
      state: ready ? "ready" : "unavailable",
      senderId: keys.senderId,
      policies: policies.map(
        ({ algorithm, keyId, status, validFromMs, validUntilMs, revision }) => ({
          algorithm,
          keyId,
          status,
          validFromMs,
          validUntilMs,
          revision,
        }),
      ),
    };
  } catch (error) {
    if (error instanceof PushKeyEnrollmentRequiredError) {
      return { ready: false, state: "unenrolled", senderId: identity.deviceId };
    }
    throw error;
  }
}

export function validatePushKeyValidity(validity: {
  validFromMs: number;
  validUntilMs: number;
}): void {
  if (
    !Number.isSafeInteger(validity.validFromMs) ||
    validity.validFromMs < 0 ||
    !Number.isSafeInteger(validity.validUntilMs) ||
    validity.validUntilMs <= validity.validFromMs
  ) {
    throw new Error("explicit safe-integer push key validity required");
  }
}

/** Provision only a new profile. Existing or partial material belongs to enrollment/recovery. */
export function initializePushKeySetup(
  validity: { validFromMs: number; validUntilMs: number },
  env: NodeJS.ProcessEnv = process.env,
): void {
  validatePushKeyValidity(validity);
  if (
    hasStoredPushKeyPolicies({ env }) ||
    loadDeviceIdentityIfPresent({ env }) ||
    existsSync(resolvePushSigningKeyPath(env))
  ) {
    throw new Error(
      "existing key material found; use enroll for intact keys or restore missing material; init refused",
    );
  }
  getOrCreatePushSigningKey(env);
  loadOrCreateProcessDeviceIdentity({ env });
  enrollExistingPushKeys(validity, { env });
}
