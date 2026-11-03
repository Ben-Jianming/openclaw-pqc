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
  const store = options.store ?? new SqlitePushReferenceStore({ env: options.env });
  const buildValue = (env: NodeJS.ProcessEnv = options.env ?? process.env) => {
    const signed = signPushEnvelope({ payload: JSON.stringify(payload), recipientId, env });
    return { payload: signed.payload, envelope: signed.envelope, recipientId };
  };
  // Production Web Push and APNs use the shared SQLite store. Custom stores do
  // not participate in the SQLite recovery RPC or its publication guarantees.
  const reference =
    store instanceof SqlitePushReferenceStore
      ? store.createWithSignature(buildValue)
      : store.create(buildValue());
  const wake = { kind: "openclaw.pqc.wake.v2" as const, pqc_ref: reference };
  if (Buffer.byteLength(JSON.stringify(wake), "utf8") > WEB_PUSH_PLAINTEXT_LIMIT) {
    store.discard(reference);
    throw new Error("Web Push wake exceeds plaintext payload budget");
  }
  return wake;
}
