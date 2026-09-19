// Feishu's official clients cannot verify custom PQC metadata. This module
// records a canonical gateway signature for audit and for optional use by an
// operator-controlled receiver. It never claims that the official Feishu
// client performed end-to-end verification.

import { createHash } from "node:crypto";
import { pqcLog } from "openclaw/plugin-sdk/pqc-log";
import { trySignPushEnvelope, type PushDualEnvelope } from "openclaw/plugin-sdk/push-envelope";

export type FeishuM11Envelope = PushDualEnvelope;

export interface FeishuM11AuditResult {
  signed: boolean;
  envelope: FeishuM11Envelope | null;
  contentSha256: string;
  error: string | null;
}

/**
 * Sign the exact outgoing content with the canonical gateway Ed25519 and
 * ML-DSA-65 identities. The envelope is audit-only unless an independently
 * controlled receiver transports it and verifies it against pinned keys.
 */
export function auditFeishuSendWithM11(
  content: string,
  env: NodeJS.ProcessEnv = process.env,
): FeishuM11AuditResult {
  const contentSha256 = createHash("sha256").update(content, "utf8").digest("hex");
  const signed = trySignPushEnvelope({ payload: content, env });
  if (!signed) {
    const error = "canonical gateway M11 signing failed";
    pqcLog.warn({
      event: "push-signature",
      status: "fail",
      detail: "Feishu message has no receiver-verifiable PQC envelope",
      error,
      contentSha256,
      contentBytes: Buffer.byteLength(content, "utf8"),
    });
    return { signed: false, envelope: null, contentSha256, error };
  }

  pqcLog.info({
    event: "push-signature",
    status: "ok",
    detail:
      "Feishu outgoing message signed by canonical gateway identity (audit-only in official Feishu clients)",
    identityKey: signed.keyIdMldsa65,
    keyId: signed.keyIdEd25519,
    contentSha256,
    contentBytes: Buffer.byteLength(content, "utf8"),
  });
  return { signed: true, envelope: signed.envelope, contentSha256, error: null };
}
