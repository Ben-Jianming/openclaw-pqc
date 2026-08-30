// M11 (PQC migration): web-push dual-signature envelope attachment.
//
// Web-push has no 4 KB body limit (unlike APNs), so the M11 envelope
// can go directly in the JSON body as a top-level `pqcenvelope` field.
// The browser service worker receiver would extract `pqcenvelope`,
// re-serialize the rest of the body, and verify against the envelope.
//
// Fail-soft: if M11 signing throws, the push still goes out unsigned
// (per danteng §M11.3 — never drop a push because of PQC error).

import { pqcLog } from "../logging/pqc-log.js";
import { trySignPushEnvelope } from "./push-envelope.js";

/** Top-level field name for the M11 envelope inside the web-push JSON body. */
export const WEB_PUSH_PQC_ENVELOPE_FIELD = "pqcenvelope";

/** Build the modified web-push payload (original + envelope), or the
 *  original payload if M11 signing failed. */
export function buildWebPushPayloadWithEnvelope<T extends Record<string, unknown>>(
  payload: T,
): T & { pqcenvelope?: unknown } {
  const body = JSON.stringify(payload);
  const signed = trySignPushEnvelope({ payload: body });
  if (!signed) {
    return payload;
  }
  return { ...payload, [WEB_PUSH_PQC_ENVELOPE_FIELD]: signed.envelope };
}
