/**
 * M1: ML-DSA-65 (FIPS 204) device identity key storage
 *
 * Per docs/security/pqc-whitepaper.md section 2.1.1:
 * - ML-DSA-65 keypair generation, encoding, signing, verification
 * - Public key: 1952 bytes
 * - Private key: 4032 bytes
 * - Signature: 3309 bytes
 *
 * Storage format: "MLDSA65-{PUBLIC,SECRET}-KEY:" + base64url(raw)
 * The prefix is for storage only; sign/verify always operates on raw bytes
 * (FIPS 204 does not natively understand the prefix).
 *
 * @noble/post-quantum uses hedged mode (FIPS 204 section 5.3, NIST-recommended),
 * so each sign() automatically mixes in 32 fresh random bytes -- signatures
 * are not deterministic.
 */

import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";

const PREFIX_PUBLIC = "MLDSA65-PUBLIC-KEY:";
const PREFIX_SECRET = "MLDSA65-SECRET-KEY:";

const ML_DSA_65_PK_BYTES = 1952;
const ML_DSA_65_SK_BYTES = 4032;
const ML_DSA_65_SIG_BYTES = 3309;

export const MLDSA65_PUBLIC_KEY_BYTES = ML_DSA_65_PK_BYTES;
export const MLDSA65_SECRET_KEY_BYTES = ML_DSA_65_SK_BYTES;
export const MLDSA65_SIGNATURE_BYTES = ML_DSA_65_SIG_BYTES;
export const MLDSA65_PUBLIC_KEY_PREFIX = PREFIX_PUBLIC;
export const MLDSA65_SECRET_KEY_PREFIX = PREFIX_SECRET;

function toBase64Url(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
  const b64 = Buffer.from(bin, "binary").toString("base64");
  return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64Url(s: string): Uint8Array {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) {
    throw new Error("ML-DSA-65 base64url: invalid character set");
  }
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const b64 = (s + pad).replace(/-/g, "+").replace(/_/g, "/");
  const bin = Buffer.from(b64, "base64").toString("binary");
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

export function generateMlDsa65Keypair(): { publicKey: Uint8Array; secretKey: Uint8Array } {
  const kp = ml_dsa65.keygen();
  if (kp.publicKey.length !== ML_DSA_65_PK_BYTES) {
    throw new Error(
      `ML-DSA-65 public key length mismatch: got ${kp.publicKey.length}, expected ${ML_DSA_65_PK_BYTES}`,
    );
  }
  if (kp.secretKey.length !== ML_DSA_65_SK_BYTES) {
    throw new Error(
      `ML-DSA-65 secret key length mismatch: got ${kp.secretKey.length}, expected ${ML_DSA_65_SK_BYTES}`,
    );
  }
  return { publicKey: kp.publicKey, secretKey: kp.secretKey };
}

export function encodeMlDsa65PublicKey(raw: Uint8Array): string {
  if (!(raw instanceof Uint8Array)) {
    throw new Error("ML-DSA-65 public key must be a Uint8Array");
  }
  if (raw.length !== ML_DSA_65_PK_BYTES) {
    throw new Error(`ML-DSA-65 public key must be ${ML_DSA_65_PK_BYTES} bytes, got ${raw.length}`);
  }
  return PREFIX_PUBLIC + toBase64Url(raw);
}

export function encodeMlDsa65SecretKey(raw: Uint8Array): string {
  if (!(raw instanceof Uint8Array)) {
    throw new Error("ML-DSA-65 secret key must be a Uint8Array");
  }
  if (raw.length !== ML_DSA_65_SK_BYTES) {
    throw new Error(`ML-DSA-65 secret key must be ${ML_DSA_65_SK_BYTES} bytes, got ${raw.length}`);
  }
  return PREFIX_SECRET + toBase64Url(raw);
}

export function decodeMlDsa65PublicKey(prefixed: string): Uint8Array {
  if (typeof prefixed !== "string") {
    throw new Error("ML-DSA-65 public key must be a string");
  }
  if (!prefixed.startsWith(PREFIX_PUBLIC)) {
    throw new Error(`ML-DSA-65 public key missing prefix "${PREFIX_PUBLIC}"`);
  }
  const body = prefixed.slice(PREFIX_PUBLIC.length);
  if (body.length === 0) {
    throw new Error("ML-DSA-65 public key body is empty");
  }
  const raw = fromBase64Url(body);
  if (raw.length !== ML_DSA_65_PK_BYTES) {
    throw new Error(
      `ML-DSA-65 public key decoded length mismatch: got ${raw.length}, expected ${ML_DSA_65_PK_BYTES}`,
    );
  }
  return raw;
}

export function decodeMlDsa65SecretKey(prefixed: string): Uint8Array {
  if (typeof prefixed !== "string") {
    throw new Error("ML-DSA-65 secret key must be a string");
  }
  if (!prefixed.startsWith(PREFIX_SECRET)) {
    throw new Error(`ML-DSA-65 secret key missing prefix "${PREFIX_SECRET}"`);
  }
  const body = prefixed.slice(PREFIX_SECRET.length);
  if (body.length === 0) {
    throw new Error("ML-DSA-65 secret key body is empty");
  }
  const raw = fromBase64Url(body);
  if (raw.length !== ML_DSA_65_SK_BYTES) {
    throw new Error(
      `ML-DSA-65 secret key decoded length mismatch: got ${raw.length}, expected ${ML_DSA_65_SK_BYTES}`,
    );
  }
  return raw;
}

export function tryDecodeMlDsa65PublicKeyRaw(
  prefixed: string | null | undefined,
): Uint8Array | null {
  if (!prefixed) return null;
  try {
    return decodeMlDsa65PublicKey(prefixed);
  } catch {
    return null;
  }
}

export function tryDecodeMlDsa65SecretKeyRaw(
  prefixed: string | null | undefined,
): Uint8Array | null {
  if (!prefixed) return null;
  try {
    return decodeMlDsa65SecretKey(prefixed);
  } catch {
    return null;
  }
}

export function signMlDsa65Payload(prefixedSecret: string, payload: string): string {
  if (typeof prefixedSecret !== "string") {
    throw new Error("ML-DSA-65 secret key must be a string");
  }
  if (typeof payload !== "string") {
    throw new Error("ML-DSA-65 payload must be a string");
  }
  const rawSk = decodeMlDsa65SecretKey(prefixedSecret);
  const message = new TextEncoder().encode(payload);
  const sig = ml_dsa65.sign(message, rawSk);
  if (sig.length !== ML_DSA_65_SIG_BYTES) {
    throw new Error(
      `ML-DSA-65 signature length mismatch: got ${sig.length}, expected ${ML_DSA_65_SIG_BYTES}`,
    );
  }
  return toBase64Url(sig);
}

export function verifyMlDsa65Signature(params: {
  publicKey: string;
  payload: string;
  sigBase64Url: string;
}): boolean {
  const { publicKey, payload, sigBase64Url } = params;
  if (typeof publicKey !== "string") {
    throw new Error("ML-DSA-65 public key must be a string");
  }
  if (typeof payload !== "string") {
    throw new Error("ML-DSA-65 payload must be a string");
  }
  if (typeof sigBase64Url !== "string") {
    throw new Error("ML-DSA-65 signature must be a string");
  }
  let rawPk: Uint8Array;
  try {
    rawPk = decodeMlDsa65PublicKey(publicKey);
  } catch {
    return false;
  }
  let rawSig: Uint8Array;
  try {
    rawSig = fromBase64Url(sigBase64Url);
    if (rawSig.length !== ML_DSA_65_SIG_BYTES) return false;
  } catch {
    return false;
  }
  const message = new TextEncoder().encode(payload);
  return ml_dsa65.verify(rawSig, message, rawPk);
}

export { ml_dsa65 };
