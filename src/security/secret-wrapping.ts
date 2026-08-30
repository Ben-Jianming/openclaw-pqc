// M4 (PQC migration, whitepaper 2.2.1): AES-256-GCM secret-wrap envelope.
//
// `wrapSecret(plaintext, keyId, key)` produces a `WrappedSecret` with a fresh
// 12-byte IV and 16-byte auth tag. The envelope carries a `keyId` so a future
// keyring (M6) can rotate keys without re-encrypting every row. Plaintext and
// key are both `Buffer`s; the wire format on disk is base64url-encoded JSON
// produced by `serializeWrappedSecret` so it survives any byte-vs-utf8 ambiguity
// in the downstream BLOB column (mldsa_private_key_wrapped, see M3).
//
// `WrappingKeyProvider` is the abstract interface that M5/M6 wire into
// device-identity-store and M6 implements as File/Env/Composite keyrings.
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";

const ALGORITHM = "aes-256-gcm";
const IV_BYTES = 12;
const AUTH_TAG_BYTES = 16;
const KEY_BYTES = 32;

const WRAPPED_SECRET_VERSION = 1;
const MAX_PLAINTEXT_BYTES = 64 * 1024;
const MAX_KEY_ID_LENGTH = 128;
const MAX_SERIALIZED_LENGTH = 16 * 1024;

export {
  ALGORITHM as WRAP_ALGORITHM,
  IV_BYTES as WRAP_IV_BYTES,
  AUTH_TAG_BYTES as WRAP_AUTH_TAG_BYTES,
  KEY_BYTES as WRAP_KEY_BYTES,
  WRAPPED_SECRET_VERSION,
  MAX_PLAINTEXT_BYTES,
  MAX_PLAINTEXT_BYTES as WRAP_MAX_PLAINTEXT_BYTES,
  MAX_KEY_ID_LENGTH,
  MAX_KEY_ID_LENGTH as WRAP_MAX_KEY_ID_LENGTH,
  MAX_SERIALIZED_LENGTH,
  MAX_SERIALIZED_LENGTH as WRAP_MAX_SERIALIZED_LENGTH,
};

export interface WrappedSecret {
  readonly v: typeof WRAPPED_SECRET_VERSION;
  readonly keyId: string;
  readonly iv: Buffer;
  readonly ciphertext: Buffer;
  readonly authTag: Buffer;
  readonly createdAtMs: number;
}

export class SecretWrappingError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "SecretWrappingError";
  }
}

function assertKeyShape(key: Buffer): void {
  if (!(key instanceof Buffer) || key.length !== KEY_BYTES) {
    throw new SecretWrappingError(
      `Wrapping key must be a Buffer of ${KEY_BYTES} bytes; got ${key instanceof Buffer ? key.length : typeof key}`,
    );
  }
}

function assertPlaintextShape(plaintext: Buffer): void {
  if (!(plaintext instanceof Buffer)) {
    throw new SecretWrappingError("Plaintext must be a Buffer");
  }
  if (plaintext.length > MAX_PLAINTEXT_BYTES) {
    throw new SecretWrappingError(
      `Plaintext exceeds ${MAX_PLAINTEXT_BYTES} bytes (got ${plaintext.length})`,
    );
  }
}

function assertKeyId(keyId: string): void {
  if (typeof keyId !== "string" || keyId.length === 0) {
    throw new SecretWrappingError("keyId must be a non-empty string");
  }
  if (keyId.length > MAX_KEY_ID_LENGTH) {
    throw new SecretWrappingError(
      `keyId exceeds ${MAX_KEY_ID_LENGTH} characters (got ${keyId.length})`,
    );
  }
}

function freshIv(): Buffer {
  return Buffer.from(randomBytes(IV_BYTES));
}

function toBase64Url(buf: Buffer): string {
  return buf.toString("base64url");
}

function fromBase64Url(s: string, label: string): Buffer {
  try {
    const buf = Buffer.from(s, "base64url");
    if (buf.length === 0) {
      throw new SecretWrappingError(`${label} base64url decoded to zero bytes`);
    }
    return buf;
  } catch (error) {
    if (error instanceof SecretWrappingError) throw error;
    throw new SecretWrappingError(`${label} is not valid base64url`, { cause: error });
  }
}

/**
 * Wrap a plaintext Buffer with a 32-byte AES-256-GCM key. The IV is fresh
 * per call (NIST SP 800-38D §8.2.1) and the authTag is captured into the
 * envelope so `unwrapSecret` can authenticate the ciphertext.
 */
export function wrapSecret(
  plaintext: Buffer,
  keyId: string,
  key: Buffer,
  now: number = Date.now(),
): WrappedSecret {
  assertKeyId(keyId);
  assertKeyShape(key);
  assertPlaintextShape(plaintext);

  const iv = freshIv();
  const cipher = createCipheriv(ALGORITHM, key, iv, { authTagLength: AUTH_TAG_BYTES });
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const authTag = cipher.getAuthTag();
  if (authTag.length !== AUTH_TAG_BYTES) {
    throw new SecretWrappingError(
      `Auth tag has unexpected length ${authTag.length} (expected ${AUTH_TAG_BYTES})`,
    );
  }
  return {
    v: WRAPPED_SECRET_VERSION,
    keyId,
    iv,
    ciphertext,
    authTag,
    createdAtMs: now,
  };
}

/**
 * Unwrap a `WrappedSecret` produced by `wrapSecret`. Throws on missing
 * keyId, wrong key length, mismatched keyId, IV/auth tag shape mismatch,
 * or AES-GCM auth failure. Never returns partial plaintext.
 */
export function unwrapSecret(wrapped: WrappedSecret, keyId: string, key: Buffer): Buffer {
  assertKeyId(keyId);
  assertKeyShape(key);
  if (!wrapped || typeof wrapped !== "object") {
    throw new SecretWrappingError("WrappedSecret must be an object");
  }
  if (wrapped.v !== WRAPPED_SECRET_VERSION) {
    throw new SecretWrappingError(
      `WrappedSecret has unsupported version ${String(wrapped.v)} (expected ${WRAPPED_SECRET_VERSION})`,
    );
  }
  if (wrapped.keyId !== keyId) {
    throw new SecretWrappingError(
      `WrappedSecret keyId mismatch: envelope is sealed under "${wrapped.keyId}", caller supplied "${keyId}"`,
    );
  }
  if (!(wrapped.iv instanceof Buffer) || wrapped.iv.length !== IV_BYTES) {
    throw new SecretWrappingError(
      `WrappedSecret iv must be a Buffer of ${IV_BYTES} bytes (got ${wrapped.iv instanceof Buffer ? wrapped.iv.length : typeof wrapped.iv})`,
    );
  }
  if (!(wrapped.authTag instanceof Buffer) || wrapped.authTag.length !== AUTH_TAG_BYTES) {
    throw new SecretWrappingError(
      `WrappedSecret authTag must be a Buffer of ${AUTH_TAG_BYTES} bytes (got ${wrapped.authTag instanceof Buffer ? wrapped.authTag.length : typeof wrapped.authTag})`,
    );
  }
  if (!(wrapped.ciphertext instanceof Buffer)) {
    throw new SecretWrappingError("WrappedSecret ciphertext must be a Buffer");
  }
  const decipher = createDecipheriv(ALGORITHM, key, wrapped.iv, { authTagLength: AUTH_TAG_BYTES });
  decipher.setAuthTag(wrapped.authTag);
  try {
    return Buffer.concat([decipher.update(wrapped.ciphertext), decipher.final()]);
  } catch (error) {
    throw new SecretWrappingError(
      "AES-256-GCM authentication failed — wrong key, tampered ciphertext, or wrong IV",
      { cause: error },
    );
  }
}

function encodeJsonBase64Url(obj: unknown): string {
  const json = JSON.stringify(obj);
  if (json.length > MAX_SERIALIZED_LENGTH) {
    throw new SecretWrappingError(
      `Serialized envelope exceeds ${MAX_SERIALIZED_LENGTH} chars (got ${json.length})`,
    );
  }
  return Buffer.from(json, "utf8").toString("base64url");
}

function decodeJsonBase64Url(s: string, label: string): unknown {
  if (typeof s !== "string" || s.length === 0) {
    throw new SecretWrappingError(`${label} must be a non-empty string`);
  }
  if (s.length > MAX_SERIALIZED_LENGTH) {
    throw new SecretWrappingError(
      `${label} exceeds ${MAX_SERIALIZED_LENGTH} characters (got ${s.length})`,
    );
  }
  let parsed: unknown;
  try {
    const json = Buffer.from(s, "base64url").toString("utf8");
    parsed = JSON.parse(json);
  } catch (error) {
    throw new SecretWrappingError(`${label} is not valid base64url-encoded JSON`, { cause: error });
  }
  return parsed;
}

/** Serialize a WrappedSecret to a base64url-encoded JSON string for BLOB storage. */
export function serializeWrappedSecret(wrapped: WrappedSecret): string {
  return encodeJsonBase64Url({
    v: wrapped.v,
    keyId: wrapped.keyId,
    iv: toBase64Url(wrapped.iv),
    ciphertext: toBase64Url(wrapped.ciphertext),
    authTag: toBase64Url(wrapped.authTag),
    createdAtMs: wrapped.createdAtMs,
  });
}

/** Deserialize a base64url-encoded JSON string back into a WrappedSecret. */
export function deserializeWrappedSecret(serialized: string): WrappedSecret {
  const obj = decodeJsonBase64Url(serialized, "WrappedSecret") as Record<string, unknown>;
  if (!obj || typeof obj !== "object") {
    throw new SecretWrappingError("WrappedSecret JSON must decode to an object");
  }
  if (obj.v !== WRAPPED_SECRET_VERSION) {
    throw new SecretWrappingError(
      `WrappedSecret has unsupported version ${String(obj.v)} (expected ${WRAPPED_SECRET_VERSION})`,
    );
  }
  if (typeof obj.keyId !== "string" || obj.keyId.length === 0) {
    throw new SecretWrappingError("WrappedSecret.keyId must be a non-empty string");
  }
  if (typeof obj.createdAtMs !== "number" || !Number.isSafeInteger(obj.createdAtMs)) {
    throw new SecretWrappingError("WrappedSecret.createdAtMs must be a safe integer");
  }
  return {
    v: WRAPPED_SECRET_VERSION,
    keyId: obj.keyId,
    iv: fromBase64Url(String(obj.iv), "WrappedSecret.iv"),
    ciphertext: fromBase64Url(String(obj.ciphertext), "WrappedSecret.ciphertext"),
    authTag: fromBase64Url(String(obj.authTag), "WrappedSecret.authTag"),
    createdAtMs: obj.createdAtMs,
  };
}

/**
 * Abstract keyring provider. M5 calls `getActiveKey()` when it needs to wrap a
 * freshly generated ML-DSA-65 secret. M6 implements File/Env/Composite variants
 * and a fail-closed OsKeyring stub. The interface is intentionally narrow so a
 * future `@napi-rs/keyring` native provider can drop in.
 */
export interface WrappingKeyProvider {
  /** Identifier that will be embedded in the envelope (e.g. file basename, env var name). */
  getActiveKey(): Promise<{ keyId: string; key: Buffer }>;
  /** Resolve a specific keyId; null if the provider does not hold that key. */
  getKeyById(keyId: string): Promise<{ keyId: string; key: Buffer } | null>;
}
