// M11 (PQC migration): high-level push envelope helper.
//
// Wraps danteng's src/security/push-dual-signature.ts library with:
// 1. Lazy resolution of the Ed25519 push-signing key (Step 1 infra)
// 2. Lazy resolution of the device identity's ML-DSA-65 secret
// 3. pqcLog emit on success (matching the M17 wire-up pattern)
// 4. Fail-soft fallback: if M11 signing fails for any reason, the
//    caller can choose to send the payload unsigned rather than
//    drop the message (per danteng prompt §M11.3 — never lose a
//    push because of a PQC signing error)
//
// IMPORTANT: this module is *helper only* — no transport is wired yet.
// Steps 3-6 wire this into push-apns-http2.ts / push-apns.relay.ts /
// push-web.ts / Feishu WebSocket respectively.

import { loadOrCreateProcessDeviceIdentity } from "./device-identity.js";
import { decodeMlDsa65SecretKey } from "./mldsa65-key-storage.js";
import { pqcLog } from "../logging/pqc-log.js";
import {
  type PushDualEnvelope,
  signPushPayloadDual,
} from "../security/push-dual-signature.js";
import { getOrCreatePushSigningKey } from "./push-signing-key.js";

const ENVELOPE_KEY_ID_MLDSA65 = "primary";

export interface SignPushEnvelopeOptions {
  /** UTF-8 string body to sign (typically JSON.stringify(payload)). */
  payload: string;
  /** Optional override for the ML-DSA-65 key id (default "primary"). */
  keyIdMldsa65?: string;
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
  const pushKey = getOrCreatePushSigningKey();
  const identity = loadOrCreateProcessDeviceIdentity();
  const mldsaSecretRaw = decodeMlDsa65SecretKey(identity.privateKeyPem);
  const keyIdMldsa65 = options.keyIdMldsa65 ?? ENVELOPE_KEY_ID_MLDSA65;

  const signed = signPushPayloadDual({
    payload: options.payload,
    ed25519SecretKeyRaw: pushKey.secretKeyRaw,
    mldsa65SecretKeyRaw: mldsaSecretRaw,
    keyIdEd25519: pushKey.keyId,
    keyIdMldsa65,
  });

  pqcLog.info({
    event: "push-signature",
    status: "ok",
    detail: "signed M11 dual signature envelope (Ed25519 + ML-DSA-65)",
    keyId: pushKey.keyId,
    identityKey: keyIdMldsa65,
    payloadBytes: options.payload.length,
  });

  return {
    payload: signed.payload,
    envelope: signed.envelope,
    keyIdEd25519: pushKey.keyId,
    keyIdMldsa65,
  };
}

/**
 * Fail-soft variant: try to sign, return null on any error.
 *
 * Use this in code paths where dropping the push is worse than
 * sending it without the M11 envelope (e.g., real-time chat,
 * approval alerts). Callers should log the failure so the
 * degraded mode is visible.
 */
export function trySignPushEnvelope(options: SignPushEnvelopeOptions): SignPushEnvelopeResult | null {
  try {
    return signPushEnvelope(options);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    pqcLog.warn({
      event: "push-signature",
      status: "fail",
      detail: "M11 envelope signing failed; caller should fall back to unsigned",
      error: message,
    });
    return null;
  }
}
