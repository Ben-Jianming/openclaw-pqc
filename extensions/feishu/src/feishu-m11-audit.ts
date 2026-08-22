// M11 (PQC migration): Feishu WebSocket outgoing message PQC audit.
//
// Scope: AUDIT-ONLY. We compute the M11 dual-signature envelope
// (Ed25519 + ML-DSA-65) over the local outgoing Feishu message
// content for our own audit trail. We do NOT add the envelope to
// the Feishu message body — the Lark server is the receiver, not
// our code, and it does not currently verify M11 envelopes. Adding
// the envelope to the body would either:
//   (a) be silently ignored by the Lark server (extra unknown
//       field), or
//   (b) surface as visible text in the chat (corrupting the user
//       experience).
// The envelope is emitted to console as `[PQC] {...}` so the
// dashboard can audit M11 envelopes.
//
// This module is self-contained: it does NOT depend on the
// openclaw workspace's src/security/push-dual-signature.ts (that
// would require a plugin-sdk extension to expose across the
// workspace boundary). Instead, it directly uses @noble/post-quantum
// (ML-DSA-65) and @noble/curves (Ed25519) — the same libraries
// danteng's library uses — to perform the dual signature inline.
//
// Dependencies (added to extensions/feishu/package.json):
// - @noble/post-quantum: ^0.5.4 (for ml_dsa65)
// - @noble/curves: ^1.9.7 (for ed25519)

import { createHash, randomBytes } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { ed25519 } from "@noble/curves/ed25519";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";

const PUSH_SIGNING_KEY_FILE_ENV = "OPENCLAW_FEISHU_PUSH_SIGNING_KEY_FILE";
const MLDSA_KEY_FILE_ENV = "OPENCLAW_FEISHU_MLDSA_KEY_FILE";
const STATE_DIR_ENV = "OPENCLAW_STATE_DIR";
const DEFAULT_STATE_DIR = "/home/benjamin/pqc-fork-state";

const ED25519_RAW_SECRET = 32;
const MLDSA65_RAW_SECRET = 4032;
const MLDSA65_RAW_PUBLIC = 1952;
const MLDSA65_SIG_BYTES = 3309;
const FILE_MODE_0600 = 0o600;

function ensureDir(filePath: string): void {
  mkdirSync(dirname(filePath), { recursive: true });
}

function toBase64Url(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
  return Buffer.from(bin, "binary").toString("base64url");
}

function resolveKeyFile(env: NodeJS.ProcessEnv, keyEnv: string, filename: string): string {
  const fromEnv = env[keyEnv];
  if (fromEnv && fromEnv.length > 0) return fromEnv;
  const stateDir = env[STATE_DIR_ENV] || DEFAULT_STATE_DIR;
  return join(stateDir, filename);
}

function getOrCreateEd25519Key(env: NodeJS.ProcessEnv): { secretRaw: Uint8Array; keyId: string } {
  const filePath = resolveKeyFile(env, PUSH_SIGNING_KEY_FILE_ENV, "feishu-push-signing-key.bin");
  let secretRaw: Uint8Array;
  if (existsSync(filePath)) {
    const buf = readFileSync(filePath);
    if (buf.length !== ED25519_RAW_SECRET) {
      throw new Error(
        `feishu push-signing key file ${filePath} has wrong size: got ${buf.length}, expected ${ED25519_RAW_SECRET}`,
      );
    }
    secretRaw = new Uint8Array(buf);
  } else {
    ensureDir(filePath);
    secretRaw = randomBytes(ED25519_RAW_SECRET);
    writeFileSync(filePath, secretRaw, { mode: FILE_MODE_0600 });
    chmodSync(filePath, FILE_MODE_0600);
  }
  const keyId = createHash("sha256")
    .update(Buffer.from(secretRaw))
    .digest("hex")
    .slice(0, 16);
  return { secretRaw, keyId };
}

function getOrCreateMldsaKey(env: NodeJS.ProcessEnv): { secretRaw: Uint8Array; publicRaw: Uint8Array; keyId: string } {
  // For audit-only: we generate a fresh MLDSA-65 keypair per-process.
  // The two halves of the M11 envelope are different anyway:
  //   - Ed25519 half: Feishu push-signing key
  //   - ML-DSA-65 half: the gateway device identity (in production)
  // In a real openclaw-pqc deployment, this would call
  // loadOrCreateProcessDeviceIdentity from src/infra/device-identity.js.
  // The cross-package import is avoided by using a separate key.
  const filePath = resolveKeyFile(env, MLDSA_KEY_FILE_ENV, "feishu-m11-mldsa.bin");
  ensureDir(filePath);
  let secretRaw: Uint8Array;
  let publicRaw: Uint8Array;
  if (existsSync(filePath)) {
    const buf = readFileSync(filePath);
    if (buf.length !== MLDSA65_RAW_SECRET + MLDSA65_RAW_PUBLIC) {
      throw new Error(
        `feishu MLDSA-65 key file ${filePath} has wrong size: got ${buf.length}, expected ${MLDSA65_RAW_SECRET + MLDSA65_RAW_PUBLIC}`,
      );
    }
    secretRaw = new Uint8Array(buf.subarray(0, MLDSA65_RAW_SECRET));
    publicRaw = new Uint8Array(buf.subarray(MLDSA65_RAW_SECRET, MLDSA65_RAW_SECRET + MLDSA65_RAW_PUBLIC));
  } else {
    const kp = ml_dsa65.keygen();
    secretRaw = kp.secretKey;
    publicRaw = kp.publicKey;
    const combined = new Uint8Array(MLDSA65_RAW_SECRET + MLDSA65_RAW_PUBLIC);
    combined.set(secretRaw, 0);
    combined.set(publicRaw, MLDSA65_RAW_SECRET);
    writeFileSync(filePath, combined, { mode: FILE_MODE_0600 });
    chmodSync(filePath, FILE_MODE_0600);
  }
  return { secretRaw, publicRaw, keyId: "primary" };
}

export interface FeishuM11Envelope {
  algorithms: ["ed25519", "ml-dsa-65"];
  ed25519_sig: string;
  mldsa65_sig: string;
  key_id_ed25519: string;
  key_id_mldsa65: string;
}

export interface FeishuM11AuditResult {
  signed: boolean;
  envelope: FeishuM11Envelope | null;
  contentSha256: string;
  error: string | null;
}

/**
 * Compute the M11 dual-signature envelope over the outgoing Feishu
 * message content and emit a `[PQC]` console log for the audit trail.
 *
 * Returns the envelope + content hash. Never throws — failures are
 * caught and returned as `signed: false`.
 *
 * @param content The exact outgoing Feishu message content (the
 *                "content" string in the im.message.create API call).
 */
export function auditFeishuSendWithM11(
  content: string,
  env: NodeJS.ProcessEnv = process.env,
): FeishuM11AuditResult {
  const contentSha256 = createHash("sha256").update(content, "utf8").digest("hex");
  try {
    const ed = getOrCreateEd25519Key(env);
    const mldsa = getOrCreateMldsaKey(env);
    // Ed25519 sign (deterministic per RFC 8032)
    // @noble/curves ed25519.sign expects msg as Uint8Array (or hex string).
    // Our content is UTF-8 text, so encode it explicitly.
    const messageBytes = new TextEncoder().encode(content);
    const edSig = ed25519.sign(messageBytes, ed.secretRaw);
    // ML-DSA-65 sign (hedged, randomized)
    const mldsaSig = ml_dsa65.sign(messageBytes, mldsa.secretRaw);
    if (mldsaSig.length !== MLDSA65_SIG_BYTES) {
      throw new Error(
        `ML-DSA-65 signature length mismatch: got ${mldsaSig.length}, expected ${MLDSA65_SIG_BYTES}`,
      );
    }
    const envelope: FeishuM11Envelope = {
      algorithms: ["ed25519", "ml-dsa-65"],
      ed25519_sig: toBase64Url(edSig),
      mldsa65_sig: toBase64Url(mldsaSig),
      key_id_ed25519: ed.keyId,
      key_id_mldsa65: mldsa.keyId,
    };
    // Emit to console (default pqcLog emitter format)
    // The dashboard's find_all_pqc_log_paths may or may not pick this
    // up depending on where console output is captured; for the
    // primary Feishu session this is best-effort. The event is
    // structured so future plugin-sdk extensions can route it to
    // pqcLog directly.
    // eslint-disable-next-line no-console
    console.log(
      `[PQC] ${JSON.stringify({
        event: "push-signature",
        status: "ok",
        level: "info",
        detail:
          "Feishu outgoing message: M11 dual-signature envelope computed (Ed25519 + ML-DSA-65, audit-only — envelope not transmitted to Lark)",
        identityKey: mldsa.keyId,
        keyId: ed.keyId,
        contentSha256,
        contentBytes: content.length,
      })}`,
    );
    return { signed: true, envelope, contentSha256, error: null };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    // eslint-disable-next-line no-console
    console.log(
      `[PQC] ${JSON.stringify({
        event: "push-signature",
        status: "fail",
        level: "warn",
        detail: "Feishu M11 envelope signing failed; message will still send (degraded mode)",
        error: message,
        contentSha256,
        contentBytes: content.length,
      })}`,
    );
    return { signed: false, envelope: null, contentSha256, error: message };
  }
}
