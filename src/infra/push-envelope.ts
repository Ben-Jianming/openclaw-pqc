// M11 (PQC migration): high-level push envelope helper.
//
// Wraps danteng's src/security/push-dual-signature.ts library with:
// 1. Lazy resolution of the Ed25519 push-signing key (Step 1 infra)
// 2. Lazy resolution of the device identity's ML-DSA-65 secret
// 3. pqcLog emit on success (matching the M17 wire-up pattern)
// 4. V2 recipient binding, durable sender sequences and strict acceptance.
//
// The same helper is used by push transports and the Feishu audit boundary so
// they all sign with one canonical pair of gateway-owned identities.

import { pqcLog } from "../logging/pqc-log.js";
import {
  type PushDualEnvelope,
  type PushReplayGuard,
  signPushPayloadDual,
  verifyPushPayloadDualStrict,
} from "../security/push-dual-signature.js";
import { loadOrCreateProcessDeviceIdentity } from "./device-identity.js";
import { decodeMlDsa65PublicKey, decodeMlDsa65SecretKey } from "./mldsa65-key-storage.js";
import { nextPushSequence, SqlitePushReplayGuard } from "./pqc-push-state.js";
import { getOrCreatePushSigningKey } from "./push-signing-key.js";

const ENVELOPE_KEY_ID_MLDSA65 = "primary";

export interface SignPushEnvelopeOptions {
  /** UTF-8 string body to sign (typically JSON.stringify(payload)). */
  payload: string;
  /** Authenticated recipient device id. Audit-only callers use their own id. */
  recipientId?: string;
  /** Optional override for the ML-DSA-65 key id (default "primary"). */
  keyIdMldsa65?: string;
  /** Optional environment override for isolated profiles and tests. */
  env?: NodeJS.ProcessEnv;
}

export interface SignPushEnvelopeResult {
  /** Original payload string (unchanged). */
  payload: string;
  /** M11 dual-signature envelope (algorithms + ed25519_sig + mldsa65_sig + key ids). */
  envelope: PushDualEnvelope;
  /** Resolved Ed25519 push-signing key id (for logging). */
  keyIdEd25519: string;
  /** Resolved ML-DSA-65 key id (for logging). */
  keyIdMldsa65: string;
}

export interface PushEnvelopeVerificationKeys {
  senderId: string;
  ed25519PublicKeyBase64Url: string;
  mldsa65PublicKeyBase64Url: string;
  keyIdEd25519: string;
  keyIdMldsa65: string;
}

export interface VerifySignedPushEnvelopeOptions {
  payload: string;
  envelope: PushDualEnvelope | string;
  trustedKeys: PushEnvelopeVerificationKeys;
  expectedRecipientId: string;
  replayGuard: PushReplayGuard;
  nowMs?: number;
}

/** Create the durable replay guard for controlled receivers in the selected profile. */
export function createPushReplayGuard(env: NodeJS.ProcessEnv = process.env): PushReplayGuard {
  return new SqlitePushReplayGuard({ env });
}

function decodeCanonicalBase64Url(value: string, label: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error(`${label} must be canonical base64url`);
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.toString("base64url") !== value) {
    throw new Error(`${label} must be canonical base64url`);
  }
  return new Uint8Array(decoded);
}

function decodeEnvelope(envelope: PushDualEnvelope | string): PushDualEnvelope {
  if (typeof envelope !== "string") {
    return envelope;
  }
  const parsed: unknown = JSON.parse(envelope);
  if (!parsed || typeof parsed !== "object") {
    throw new Error("push envelope must decode to an object");
  }
  return parsed as PushDualEnvelope;
}

/**
 * Sign a push payload with the M11 dual-signature envelope
 * (Ed25519 + ML-DSA-65). Both halves must succeed; otherwise
 * PushDualSignatureError is thrown.
 *
 * Emits a pqcLog.info event on success with the key ids and
 * payload byte length.
 */
export function signPushEnvelope(options: SignPushEnvelopeOptions): SignPushEnvelopeResult {
  if (typeof options.payload !== "string") {
    throw new Error("signPushEnvelope: payload must be a UTF-8 string");
  }
  const pushKey = getOrCreatePushSigningKey(options.env);
  const identity = loadOrCreateProcessDeviceIdentity({ env: options.env });
  const mldsaSecretRaw = decodeMlDsa65SecretKey(identity.privateKeyPem);
  const keyIdMldsa65 = options.keyIdMldsa65 ?? ENVELOPE_KEY_ID_MLDSA65;
  const recipientId = options.recipientId ?? identity.deviceId;

  const signed = signPushPayloadDual({
    payload: options.payload,
    ed25519SecretKeyRaw: pushKey.secretKeyRaw,
    mldsa65SecretKeyRaw: mldsaSecretRaw,
    keyIdEd25519: pushKey.keyId,
    keyIdMldsa65,
    senderId: identity.deviceId,
    recipientId,
    sequence: nextPushSequence(identity.deviceId, recipientId, { env: options.env }),
  });

  pqcLog.info({
    event: "push-signature",
    status: "ok",
    detail: "signed V2 dual signature envelope (Ed25519 + ML-DSA-65)",
    keyId: pushKey.keyId,
    identityKey: keyIdMldsa65,
    payloadBytes: Buffer.byteLength(options.payload, "utf8"),
  });

  return {
    payload: signed.payload,
    envelope: signed.envelope,
    keyIdEd25519: pushKey.keyId,
    keyIdMldsa65,
  };
}

/** Return non-secret key material for provisioning a controlled receiver. */
export function getPushEnvelopeVerificationKeys(
  env: NodeJS.ProcessEnv = process.env,
): PushEnvelopeVerificationKeys {
  const pushKey = getOrCreatePushSigningKey(env);
  const identity = loadOrCreateProcessDeviceIdentity({ env });
  return {
    senderId: identity.deviceId,
    ed25519PublicKeyBase64Url: Buffer.from(pushKey.publicKeyRaw).toString("base64url"),
    mldsa65PublicKeyBase64Url: Buffer.from(decodeMlDsa65PublicKey(identity.publicKeyPem)).toString(
      "base64url",
    ),
    keyIdEd25519: pushKey.keyId,
    keyIdMldsa65: ENVELOPE_KEY_ID_MLDSA65,
  };
}

/** Verify both signatures and pinned key ids before accepting content. */
export function verifySignedPushEnvelope(options: VerifySignedPushEnvelopeOptions): true {
  const envelope = decodeEnvelope(options.envelope);
  if (envelope.key_id_ed25519 !== options.trustedKeys.keyIdEd25519) {
    throw new Error("push envelope Ed25519 key id does not match the pinned key");
  }
  if (envelope.key_id_mldsa65 !== options.trustedKeys.keyIdMldsa65) {
    throw new Error("push envelope ML-DSA-65 key id does not match the pinned key");
  }
  const trustedKeys = options.trustedKeys;
  verifyPushPayloadDualStrict({
    payload: options.payload,
    envelope,
    expectedRecipientId: options.expectedRecipientId,
    replayGuard: options.replayGuard,
    nowMs: options.nowMs,
    registry: {
      resolve: (algorithm, keyId) => ({
        algorithm,
        keyId,
        senderId: trustedKeys.senderId,
        publicKeyRaw: decodeCanonicalBase64Url(
          algorithm === "ed25519"
            ? trustedKeys.ed25519PublicKeyBase64Url
            : trustedKeys.mldsa65PublicKeyBase64Url,
          "trusted push public key",
        ),
      }),
    },
  });
  return true;
}

/**
 * Fail-soft variant: try to sign, return null on any error.
 *
 * Audit-only integrations may record failure without blocking chat. Push
 * transports must use signPushEnvelope and stop before emitting on failure.
 */
export function trySignPushEnvelope(
  options: SignPushEnvelopeOptions,
): SignPushEnvelopeResult | null {
  try {
    return signPushEnvelope(options);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    pqcLog.warn({
      event: "push-signature",
      status: "fail",
      detail: "PQC audit signing failed; no authenticated-content guarantee",
      error: message,
    });
    return null;
  }
}
