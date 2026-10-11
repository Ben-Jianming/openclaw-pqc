import type { PushReferenceStore } from "../security/push-reference.js";
import { buildWebPushPayloadWithEnvelope } from "./push-web-m11.js";

/** Provider HTTP headers do not reach a device: carry an opaque reference in JSON. */
export function buildApnsPqcWake(payload: object, recipientId: string, store: PushReferenceStore) {
  const wake = buildWebPushPayloadWithEnvelope(payload as Record<string, unknown>, recipientId, {
    store,
  });
  const originalAps = "aps" in payload ? payload.aps : undefined;
  const alert = originalAps && typeof originalAps === "object" && "alert" in originalAps;
  const result = {
    ...wake,
    aps: {
      "content-available": 1,
      ...(alert
        ? { alert: { title: "OpenClaw", body: "Open OpenClaw to view a secure notification." } }
        : {}),
    },
  };
  if (Buffer.byteLength(JSON.stringify(result), "utf8") > 4096) {
    store.discard(wake.pqc_ref);
    throw new Error("APNs wake exceeds payload budget");
  }
  return result;
}
