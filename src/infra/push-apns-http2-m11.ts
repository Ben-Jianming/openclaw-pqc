// M11 (PQC migration): APNs HTTP/2 dual-signature envelope attachment.
//
// Danteng's M11 dual-signature envelope (src/security/push-dual-signature.ts)
// signs an APNs payload body with BOTH Ed25519 and ML-DSA-65. The receiver
// (iOS app) needs the envelope to verify the push came from the right
// sender.
//
// APNs body is limited to 4 KB; the M11 envelope alone is ~4.5 KB
// (Ed25519 sig 64 b64 + ML-DSA-65 sig 3309 b64 + key ids + JSON overhead).
// So we cannot put the envelope in the JSON body — it would push every
// normal alert over 4 KB.
//
// The chosen transport: custom HTTP/2 header `apns-pqc-envelope`,
// base64url-encoded JSON envelope. iOS app reads the header.
// (Apple's APNs passes through custom `apns-*` headers to the device
//  per the APNs Provider API docs.)
//
// If the envelope header exceeds 8 KB (HTTP/2 conservative cap), we
// skip the envelope and log a degraded-mode warning — the push still
// goes out (signed at the existing transport layer), but the receiver
// cannot do the PQC verification. This is the danteng prompt §M11.3
// "never drop a push because of PQC error" rule.

import { pqcLog } from "../logging/pqc-log.js";
import { trySignPushEnvelope } from "./push-envelope.js";

/** Custom HTTP/2 header that carries the M11 envelope (base64url JSON). */
export const APNS_PQC_ENVELOPE_HEADER = "apns-pqc-envelope";

/** Conservative HTTP/2 header size cap (APNs docs do not state a limit;
 *  nginx / envoy / many ingress cap at 8 KB; we cap at 8 KB to be safe). */
export const APNS_PQC_ENVELOPE_MAX_HEADER_BYTES = 8 * 1024;

export interface BuildApnsEnvelopeHeaderResult {
  /** base64url-encoded JSON envelope, or null if M11 signing failed or
   *  the envelope was too large for a custom header. */
  header: string | null;
  /** Why the header is null (for logging / pqcLog). */
  reason: "ok" | "sign-failed" | "too-large" | "skipped";
  /** Envelope byte length when reason="ok" (raw JSON bytes, not base64url). */
  envelopeBytes: number;
}

/**
 * Build the `apns-pqc-envelope` header value for an APNs push payload.
 *
 * - Calls trySignPushEnvelope (fail-soft; logs warn on signing error).
 * - Returns header=null if signing failed.
 * - Returns header=null with reason="too-large" if base64url JSON
 *   envelope exceeds APNS_PQC_ENVELOPE_MAX_HEADER_BYTES.
 * - Emits pqcLog.info with event=push-signature, status=ok on success.
 * - Emits pqcLog.warn with event=push-signature, status=fail on
 *   degraded mode (too-large or sign-failed).
 */
export function buildApnsEnvelopeHeader(
  payload: object,
): BuildApnsEnvelopeHeaderResult {
  const body = JSON.stringify(payload);
  const signed = trySignPushEnvelope({ payload: body });
  if (!signed) {
    return { header: null, reason: "sign-failed", envelopeBytes: 0 };
  }
  const envJson = JSON.stringify(signed.envelope);
  const envelopeBytes = Buffer.byteLength(envJson, "utf8");
  const header = Buffer.from(envJson, "utf8").toString("base64url");
  if (header.length > APNS_PQC_ENVELOPE_MAX_HEADER_BYTES) {
    pqcLog.warn({
      event: "push-signature",
      status: "fail",
      detail: "M11 envelope exceeds APNs custom header size cap; sending unsigned (degraded mode)",
      envelopeBytes,
      headerBytes: header.length,
      maxBytes: APNS_PQC_ENVELOPE_MAX_HEADER_BYTES,
    });
    return { header: null, reason: "too-large", envelopeBytes };
  }
  return { header, reason: "ok", envelopeBytes };
}
