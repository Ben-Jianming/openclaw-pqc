// M11 (PQC migration): APNs relay dual-signature envelope audit.
//
// Danteng's M11 dual-signature envelope (src/security/push-dual-signature.ts)
// requires BOTH an Ed25519 raw 32-byte secret AND an ML-DSA-65 raw 4032-byte
// secret. The APNs relay path (push-apns.relay.ts sendApnsRelayPush) ALREADY
// signs the body with the gateway's ML-DSA-65 device identity via
// signDevicePayload (the `signature` field in the wire body).
//
// For M11 audit-only, we ALSO compute the dual envelope locally. We do
// NOT add it to the wire body (the relay receiver protocol is fixed; any
// change requires danteng §M11.4). The envelope is emitted to pqcLog
// so the dashboard can audit M11 envelopes on every APNs relay send.
//
// Fail-soft: if M11 envelope signing throws, the relay send still goes
// out with the existing MLDSA-65-only signature (per danteng §M11.3 —
// never drop a push because of PQC error).

import { pqcLog } from "../logging/pqc-log.js";
import { trySignPushEnvelope } from "./push-envelope.js";

export interface BuildApnsRelayM11AuditResult {
  /** True if envelope was computed, false if fail-soft fallback. */
  signed: boolean;
  /** Envelope keyIds (always populated if signed). */
  keyIdEd25519: string | null;
  keyIdMldsa65: string | null;
  /** Envelope body bytes when signed, else null. */
  envelopeBytes: number | null;
}

/**
 * Compute the M11 dual-signature envelope over the APNs relay body and
 * emit a pqcLog.info event. Does NOT modify the wire body (the relay
 * receiver expects the existing MLDSA-65-only `signature` field).
 *
 * @param bodyJson The exact JSON string the relay will sign with
 *                 signDevicePayload (gateway identity, ML-DSA-65).
 *                 This same byte sequence is the input to the M11
 *                 dual envelope so the receiver (in a future danteng
 *                 §M11.4 protocol) could verify both halves.
 * @param deviceKeyId The MLDSA-65 device key id (e.g. "primary"),
 *                    for logging. The M11 envelope's MLDSA-65 half
 *                    is always signed with the gateway's ML-DSA-65
 *                    device identity.
 */
export function buildApnsRelayM11Audit(
  bodyJson: string,
  deviceKeyId: string = "primary",
): BuildApnsRelayM11AuditResult {
  const signed = trySignPushEnvelope({ payload: bodyJson, keyIdMldsa65: deviceKeyId });
  if (!signed) {
    return {
      signed: false,
      keyIdEd25519: null,
      keyIdMldsa65: null,
      envelopeBytes: null,
    };
  }
  const envelopeJson = JSON.stringify(signed.envelope);
  const envelopeBytes = Buffer.byteLength(envelopeJson, "utf8");
  pqcLog.info({
    event: "push-signature",
    status: "ok",
    detail:
      "APNs relay: M11 dual-signature envelope computed (Ed25519 + ML-DSA-65); audit-only — envelope not transmitted to relay (existing MLDSA-65 signature unchanged for backward compat)",
    identityKey: deviceKeyId,
    keyId: signed.keyIdEd25519,
    bodyBytes: bodyJson.length,
    envelopeBytes,
  });
  return {
    signed: true,
    keyIdEd25519: signed.keyIdEd25519,
    keyIdMldsa65: signed.keyIdMldsa65,
    envelopeBytes,
  };
}
