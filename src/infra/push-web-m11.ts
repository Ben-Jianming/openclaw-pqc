import type { PushReferenceDescriptor, PushReferenceStore } from "../security/push-reference.js";
import { SqlitePushReferenceStore } from "./pqc-push-state.js";
import { signPushEnvelope } from "./push-envelope.js";

export const WEB_PUSH_PQC_ENVELOPE_FIELD = "pqc_ref";
// RFC 8291's minimum encrypted record leaves 3993 plaintext bytes.
export const WEB_PUSH_PLAINTEXT_LIMIT = 3993;

/** Relay sees only a generic wake; content stays at the authenticated gateway. */
export function buildWebPushPayloadWithEnvelope(
  payload: Record<string, unknown>,
  recipientId: string,
  options: { env?: NodeJS.ProcessEnv; store?: PushReferenceStore } = {},
): { kind: "openclaw.pqc.wake.v2"; pqc_ref: PushReferenceDescriptor } {
  if (!recipientId) {
    throw new Error("authenticated push recipient required");
  }
  const signed = signPushEnvelope({
    payload: JSON.stringify(payload),
    recipientId,
    env: options.env,
  });
  const store = options.store ?? new SqlitePushReferenceStore({ env: options.env });
  const reference = store.create({
    payload: signed.payload,
    envelope: signed.envelope,
    recipientId,
  });
  const wake = { kind: "openclaw.pqc.wake.v2" as const, pqc_ref: reference };
  if (Buffer.byteLength(JSON.stringify(wake), "utf8") > WEB_PUSH_PLAINTEXT_LIMIT) {
    store.discard(reference);
    throw new Error("Web Push wake exceeds plaintext payload budget");
  }
  return wake;
}
