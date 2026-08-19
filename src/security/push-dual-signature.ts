// M11 (PQC migration, whitepaper 1.3): APNs ML-DSA-65 fallback dual signature.
//
// Apple APNs JWT (ES256) is unchanged — the Apple protocol is not
// ours to evolve. The dual signature is an app-layer envelope attached
// to every push payload, so legacy clients can still verify the
// Ed25519 half while post-quantum clients verify the ML-DSA-65 half.
//
// Ed25519 always uses `src/infra/ed25519-signature.ts` (PKCS8 / SPKI
// framing on top of node:crypto). ML-DSA-65 uses the @noble/post-quantum
// helper from M1.

import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import {
  ed25519PrivateKeyPemFromRaw,
  ed25519PublicKeyPemFromRaw,
  signEd25519Payload,
  verifyEd25519SignatureBytes,
} from "../infra/ed25519-signature.js";
import {
  encodeMlDsa65PublicKey,
  encodeMlDsa65SecretKey,
  MLDSA65_PUBLIC_KEY_BYTES,
  MLDSA65_PUBLIC_KEY_PREFIX,
  MLDSA65_SECRET_KEY_BYTES,
  MLDSA65_SECRET_KEY_PREFIX,
  MLDSA65_SIGNATURE_BYTES,
  decodeMlDsa65PublicKey,
  decodeMlDsa65SecretKey,
  signMlDsa65Payload,
  verifyMlDsa65Signature,
} from "../infra/mldsa65-key-storage.js";

const ED25519_RAW_SECRET_KEY = 32;
const ED25519_RAW_PUBLIC_KEY = 32;
const ED25519_SIGNATURE_BYTES = 64;
const EXPECTED_ALGORITHMS: readonly ["ed25519", "ml-dsa-65"] = ["ed25519", "ml-dsa-65"] as const;
const MAX_KEY_ID_LENGTH = 128;
const MAX_ENVELOPE_BYTES = 8192;

export const PUSH_DUAL_SIG_CONSTANTS = {
  ED25519_RAW_SECRET_KEY,
  ED25519_RAW_PUBLIC_KEY,
  ED25519_SIGNATURE_BYTES,
  MLDSA65_PUBLIC_KEY_BYTES,
  MLDSA65_SECRET_KEY_BYTES,
  MLDSA65_SIGNATURE_BYTES,
  EXPECTED_ALGORITHMS,
  MAX_KEY_ID_LENGTH,
  MAX_ENVELOPE_BYTES,
} as const;

export class PushDualSignatureError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "PushDualSignatureError";
  }
}

export interface PushDualEnvelope {
  algorithms: ["ed25519", "ml-dsa-65"];
  ed25519_sig: string;
  mldsa65_sig: string;
  key_id_ed25519: string;
  key_id_mldsa65: string;
}

function assertKeyId(keyId: string, label: string): void {
  if (typeof keyId !== "string" || keyId.length === 0) {
    throw new PushDualSignatureError(`${label} must be a non-empty string`);
  }
  if (keyId.length > MAX_KEY_ID_LENGTH) {
    throw new PushDualSignatureError(
      `${label} exceeds ${MAX_KEY_ID_LENGTH} characters (got ${keyId.length})`,
    );
  }
}

function assertRawKey(raw: Uint8Array, expectedLength: number, label: string): void {
  if (!(raw instanceof Uint8Array) || raw.length !== expectedLength) {
    throw new PushDualSignatureError(
      `${label} must be a ${expectedLength}-byte Uint8Array; got ${raw instanceof Uint8Array ? raw.length : typeof raw}`,
    );
  }
}

function toBase64Url(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
  return Buffer.from(bin, "binary").toString("base64url");
}

function fromBase64Url(s: string, expectedLength: number, label: string): Buffer {
  try {
    const buf = Buffer.from(s, "base64url");
    if (buf.length !== expectedLength) {
      throw new PushDualSignatureError(
        `${label} must decode to ${expectedLength} bytes; got ${buf.length}`,
      );
    }
    return buf;
  } catch (error) {
    if (error instanceof PushDualSignatureError) throw error;
    throw new PushDualSignatureError(`${label} is not valid base64url`, { cause: error });
  }
}

function isAlgorithmsHeader(algorithms: unknown): algorithms is ["ed25519", "ml-dsa-65"] {
  return (
    Array.isArray(algorithms) &&
    algorithms.length === 2 &&
    algorithms[0] === "ed25519" &&
    algorithms[1] === "ml-dsa-65"
  );
}

export interface SignPushPayloadDualOptions {
  payload: string;
  ed25519SecretKeyRaw: Uint8Array;
  mldsa65SecretKeyRaw: Uint8Array;
  keyIdEd25519: string;
  keyIdMldsa65: string;
}

export interface SignPushPayloadDualResult {
  payload: string;
  envelope: PushDualEnvelope;
}

/**
 * Sign a UTF-8 push payload with both Ed25519 and ML-DSA-65. The
 * returned envelope is JSON-serializable; the caller embeds it
 * alongside the original payload.
 */
export function signPushPayloadDual(
  options: SignPushPayloadDualOptions,
): SignPushPayloadDualResult {
  if (typeof options.payload !== "string") {
    throw new PushDualSignatureError("payload must be a UTF-8 string");
  }
  assertRawKey(options.ed25519SecretKeyRaw, ED25519_RAW_SECRET_KEY, "ed25519SecretKeyRaw");
  assertRawKey(options.mldsa65SecretKeyRaw, MLDSA65_SECRET_KEY_BYTES, "mldsa65SecretKeyRaw");
  assertKeyId(options.keyIdEd25519, "keyIdEd25519");
  assertKeyId(options.keyIdMldsa65, "keyIdMldsa65");

  // Ed25519 path: build a PKCS8 PEM from the raw 32-byte secret and
  // sign through the canonical helper. M11 must NOT take a dependency
  // on @noble/curves/ed25519 (per danteng prompt §M11.2 — that path
  // is missing `randomPrivateKey` and breaks vitest).
  const edPrivPem = ed25519PrivateKeyPemFromRaw(Buffer.from(options.ed25519SecretKeyRaw));
  const edSigBase64Url = signEd25519Payload(edPrivPem, options.payload);
  if (Buffer.from(edSigBase64Url, "base64url").length !== ED25519_SIGNATURE_BYTES) {
    throw new PushDualSignatureError(
      `Ed25519 signature must be ${ED25519_SIGNATURE_BYTES} bytes; got ${Buffer.from(edSigBase64Url, "base64url").length}`,
    );
  }

  // ML-DSA-65 path: build the prefixed wire shape and sign through the
  // canonical M1 helper.
  const mldsaSecretPem = encodeMlDsa65SecretKey(new Uint8Array(options.mldsa65SecretKeyRaw));
  const mldsaSigBase64Url = signMlDsa65Payload(mldsaSecretPem, options.payload);
  if (Buffer.from(mldsaSigBase64Url, "base64url").length !== MLDSA65_SIGNATURE_BYTES) {
    throw new PushDualSignatureError(
      `ML-DSA-65 signature must be ${MLDSA65_SIGNATURE_BYTES} bytes; got ${Buffer.from(mldsaSigBase64Url, "base64url").length}`,
    );
  }

  const envelope: PushDualEnvelope = {
    algorithms: ["ed25519", "ml-dsa-65"],
    ed25519_sig: edSigBase64Url,
    mldsa65_sig: mldsaSigBase64Url,
    key_id_ed25519: options.keyIdEd25519,
    key_id_mldsa65: options.keyIdMldsa65,
  };
  return { payload: options.payload, envelope };
}

export interface VerifyPushPayloadDualOptions {
  payload: string;
  ed25519PublicKeyRaw: Uint8Array;
  mldsa65PublicKeyRaw: Uint8Array;
  envelope: PushDualEnvelope | string;
}

function parseEnvelope(envelope: PushPayloadDualEnvelopeLike | string): PushDualEnvelope {
  if (typeof envelope === "string") {
    if (envelope.length === 0) {
      throw new PushDualSignatureError("envelope must be a non-empty string");
    }
    if (envelope.length > MAX_ENVELOPE_BYTES) {
      throw new PushDualSignatureError(
        `envelope string exceeds ${MAX_ENVELOPE_BYTES} characters (got ${envelope.length})`,
      );
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(envelope);
    } catch (error) {
      throw new PushDualSignatureError("envelope is not valid JSON", { cause: error });
    }
    return parseEnvelopeObject(parsed);
  }
  return parseEnvelopeObject(envelope);
}

type PushPayloadDualEnvelopeLike = unknown;
function parseEnvelopeObject(obj: PushPayloadDualEnvelopeLike): PushDualEnvelope {
  if (!obj || typeof obj !== "object") {
    throw new PushDualSignatureError("envelope must decode to an object");
  }
  const o = obj as Record<string, unknown>;
  if (!isAlgorithmsHeader(o.algorithms)) {
    throw new PushDualSignatureError(
      `envelope.algorithms must be exactly ["ed25519", "ml-dsa-65"]; got ${JSON.stringify(o.algorithms)}`,
    );
  }
  if (typeof o.ed25519_sig !== "string" || o.ed25519_sig.length === 0) {
    throw new PushDualSignatureError("envelope.ed25519_sig must be a non-empty base64url string");
  }
  if (typeof o.mldsa65_sig !== "string" || o.mldsa65_sig.length === 0) {
    throw new PushDualSignatureError("envelope.mldsa65_sig must be a non-empty base64url string");
  }
  if (typeof o.key_id_ed25519 !== "string" || o.key_id_ed25519.length === 0) {
    throw new PushDualSignatureError("envelope.key_id_ed25519 must be a non-empty string");
  }
  if (typeof o.key_id_mldsa65 !== "string" || o.key_id_mldsa65.length === 0) {
    throw new PushDualSignatureError("envelope.key_id_mldsa65 must be a non-empty string");
  }
  return {
    algorithms: ["ed25519", "ml-dsa-65"],
    ed25519_sig: o.ed25519_sig,
    mldsa65_sig: o.mldsa65_sig,
    key_id_ed25519: o.key_id_ed25519,
    key_id_mldsa65: o.key_id_mldsa65,
  };
}

/**
 * Verify a push payload's dual signature. Fail-closed: ANY single
 * signature failure throws PushDualSignatureError. Both halves must
 * verify under the supplied raw public keys.
 */
export function verifyPushPayloadDual(options: VerifyPushPayloadDualOptions): boolean {
  if (typeof options.payload !== "string") {
    throw new PushDualSignatureError("payload must be a UTF-8 string");
  }
  assertRawKey(options.ed25519PublicKeyRaw, ED25519_RAW_PUBLIC_KEY, "ed25519PublicKeyRaw");
  assertRawKey(options.mldsa65PublicKeyRaw, MLDSA65_PUBLIC_KEY_BYTES, "mldsa65PublicKeyRaw");
  const envelope = parseEnvelope(options.envelope);

  // 1. Ed25519 verification.
  const edPubPem = ed25519PublicKeyPemFromRaw(Buffer.from(options.ed25519PublicKeyRaw));
  const edSigBytes = fromBase64Url(envelope.ed25519_sig, ED25519_SIGNATURE_BYTES, "ed25519_sig");
  const ed25519Ok = verifyEd25519SignatureBytes({
    publicKey: edPubPem,
    payload: Buffer.from(options.payload, "utf8"),
    signatureBase64Url: Buffer.from(edSigBytes).toString("base64url"),
  });
  if (!ed25519Ok) {
    throw new PushDualSignatureError("Ed25519 signature verification failed");
  }

  // 2. ML-DSA-65 verification.
  const mldsaPubPem = encodeMlDsa65PublicKey(new Uint8Array(options.mldsa65PublicKeyRaw));
  const mldsaSigBytes = fromBase64Url(envelope.mldsa65_sig, MLDSA65_SIGNATURE_BYTES, "mldsa65_sig");
  const mldsaOk = verifyMlDsa65Signature({
    publicKey: mldsaPubPem,
    payload: options.payload,
    sigBase64Url: Buffer.from(mldsaSigBytes).toString("base64url"),
  });
  if (!mldsaOk) {
    throw new PushDualSignatureError("ML-DSA-65 signature verification failed");
  }
  // Confirm the wire shape carries the canonical keyIds. Verification
  // does not require the keyId to match the public key (callers may
  // rotate), but the envelope must round-trip the prefix and length.
  assertKeyId(envelope.key_id_ed25519, "envelope.key_id_ed25519");
  assertKeyId(envelope.key_id_mldsa65, "envelope.key_id_mldsa65");
  return true;
}

// Re-export size constants from the @noble/post-quantum module so a
// downstream caller can build a keys table without pulling in the
// internal module.
void ml_dsa65;
void decodeMlDsa65PublicKey;
void decodeMlDsa65SecretKey;
void MLDSA65_PUBLIC_KEY_PREFIX;
void MLDSA65_SECRET_KEY_PREFIX;
