// M7 (PQC migration, whitepaper 2.2.5.C + 2.2.5.D): wrap-key rotation and
// passphrase-envelope backup / restore.
//
// rotateWrappingKey walks every wrapped device-identity row, unwraps with
// the old key, and re-wraps under the new key. Plaintext rows are skipped —
// they will be re-wrapped the next time Doctor refreshes the keyring.
//
// exportWrapKey / importWrapKey produce a passphrase-protected envelope for
// off-host backup. The envelope uses PBKDF2-SHA256 (OWASP 2023 minimum:
// 210,000 iterations) to derive an AES-256-GCM key from the passphrase.

import {
  createCipheriv,
  createDecipheriv,
  pbkdf2Sync,
  randomBytes,
  timingSafeEqual,
} from "node:crypto";
import {
  readStoredDeviceIdentity,
  writeStoredDeviceIdentity,
  type StoredDeviceIdentity,
  type SyncWrappingKeyProvider,
} from "../infra/device-identity-store.js";
import {
  serializeWrappedSecret,
  unwrapSecret,
  wrapSecret,
  type WrappedSecret,
} from "./secret-wrapping.js";

const BACKUP_VERSION = 1;
const PBKDF2_ITERATIONS = 210_000; // OWASP 2023 minimum for PBKDF2-SHA256
const PBKDF2_KEY_BYTES = 32;
const SALT_BYTES = 16;
const IV_BYTES = 12;
const AUTH_TAG_BYTES = 16;
const WRAP_KEY_BYTES = 32;
const MAX_ENVELOPE_LENGTH = 4096;
const MAX_KEY_ID_LENGTH = 128;
const MAX_PASSPHRASE_LENGTH = 1024;
const MIN_PASSPHRASE_LENGTH = 8;

export const WRAP_KEY_BACKUP_CONSTANTS = {
  BACKUP_VERSION,
  PBKDF2_ITERATIONS,
  PBKDF2_KEY_BYTES,
  SALT_BYTES,
  IV_BYTES,
  AUTH_TAG_BYTES,
  WRAP_KEY_BYTES,
  MAX_ENVELOPE_LENGTH,
  MAX_KEY_ID_LENGTH,
  MAX_PASSPHRASE_LENGTH,
  MIN_PASSPHRASE_LENGTH,
} as const;

export class WrapKeyBackupError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "WrapKeyBackupError";
  }
}

export class WrapKeyRotationError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "WrapKeyRotationError";
  }
}

function toBase64Url(buf: Buffer): string {
  return buf.toString("base64url");
}

function fromBase64Url(s: string, label: string): Buffer {
  try {
    return Buffer.from(s, "base64url");
  } catch (error) {
    throw new WrapKeyBackupError(`${label} is not valid base64url`, { cause: error });
  }
}

export function constantTimeEqual(a: Buffer, b: Buffer): boolean {
  if (!(a instanceof Buffer) || !(b instanceof Buffer)) return false;
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

function assertKeyId(keyId: string): void {
  if (typeof keyId !== "string" || keyId.length === 0) {
    throw new WrapKeyBackupError("keyId must be a non-empty string");
  }
  if (keyId.length > MAX_KEY_ID_LENGTH) {
    throw new WrapKeyBackupError(
      `keyId exceeds ${MAX_KEY_ID_LENGTH} characters (got ${keyId.length})`,
    );
  }
}

function assertPassphrase(passphrase: string): void {
  if (typeof passphrase !== "string" || passphrase.length === 0) {
    throw new WrapKeyBackupError("passphrase must be a non-empty string");
  }
  if (passphrase.length < MIN_PASSPHRASE_LENGTH) {
    throw new WrapKeyBackupError(
      `passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters (got ${passphrase.length})`,
    );
  }
  if (passphrase.length > MAX_PASSPHRASE_LENGTH) {
    throw new WrapKeyBackupError(
      `passphrase exceeds ${MAX_PASSPHRASE_LENGTH} characters (got ${passphrase.length})`,
    );
  }
}

function assertKeyBytes(raw: Buffer): void {
  if (!(raw instanceof Buffer)) {
    throw new WrapKeyBackupError("key must be a Buffer");
  }
  if (raw.length !== WRAP_KEY_BYTES) {
    throw new WrapKeyBackupError(`key must be ${WRAP_KEY_BYTES} bytes (got ${raw.length})`);
  }
}

interface BackupEnvelope {
  v: typeof BACKUP_VERSION;
  keyId: string;
  iterations: number;
  salt: string; // base64url
  iv: string; // base64url
  ciphertext: string; // base64url
  authTag: string; // base64url
  createdAtMs: number;
}

/**
 * Encrypt a 32-byte wrapping key under a passphrase. The output is a
 * base64url-encoded JSON envelope; never store or print the raw key while
 * holding the JSON.
 */
export function exportWrapKey(
  rawKey: Buffer,
  passphrase: string,
  keyId: string,
  now: number = Date.now(),
): string {
  assertKeyBytes(rawKey);
  assertKeyId(keyId);
  assertPassphrase(passphrase);

  const salt = Buffer.from(randomBytes(SALT_BYTES));
  const iv = Buffer.from(randomBytes(IV_BYTES));
  const derived = pbkdf2Sync(passphrase, salt, PBKDF2_ITERATIONS, PBKDF2_KEY_BYTES, "sha256");
  const cipher = createCipheriv("aes-256-gcm", derived, iv, { authTagLength: AUTH_TAG_BYTES });
  const ciphertext = Buffer.concat([cipher.update(rawKey), cipher.final()]);
  const authTag = cipher.getAuthTag();
  if (authTag.length !== AUTH_TAG_BYTES) {
    throw new WrapKeyBackupError(
      `authTag has unexpected length ${authTag.length} (expected ${AUTH_TAG_BYTES})`,
    );
  }
  const envelope: BackupEnvelope = {
    v: BACKUP_VERSION,
    keyId,
    iterations: PBKDF2_ITERATIONS,
    salt: toBase64Url(salt),
    iv: toBase64Url(iv),
    ciphertext: toBase64Url(ciphertext),
    authTag: toBase64Url(authTag),
    createdAtMs: now,
  };
  const json = JSON.stringify(envelope);
  if (json.length > MAX_ENVELOPE_LENGTH) {
    throw new WrapKeyBackupError(
      `Envelope JSON exceeds ${MAX_ENVELOPE_LENGTH} characters (got ${json.length})`,
    );
  }
  return Buffer.from(json, "utf8").toString("base64url");
}

/**
 * Decrypt a passphrase-protected envelope. Returns the original 32-byte key
 * along with the keyId recorded in the envelope. Never returns partial key
 * material on failure.
 */
export function importWrapKey(
  envelope: string,
  passphrase: string,
): { key: Buffer; keyId: string } {
  assertPassphrase(passphrase);
  if (typeof envelope !== "string" || envelope.length === 0) {
    throw new WrapKeyBackupError("envelope must be a non-empty string");
  }
  if (envelope.length > MAX_ENVELOPE_LENGTH) {
    throw new WrapKeyBackupError(
      `envelope exceeds ${MAX_ENVELOPE_LENGTH} characters (got ${envelope.length})`,
    );
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(Buffer.from(envelope, "base64url").toString("utf8"));
  } catch (error) {
    throw new WrapKeyBackupError("envelope is not valid base64url-encoded JSON", { cause: error });
  }
  if (!parsed || typeof parsed !== "object") {
    throw new WrapKeyBackupError("Envelope JSON must decode to an object");
  }
  const obj = parsed as Record<string, unknown>;
  if (obj.v !== BACKUP_VERSION) {
    throw new WrapKeyBackupError(
      `Unsupported envelope version ${String(obj.v)} (expected ${BACKUP_VERSION})`,
    );
  }
  if (typeof obj.keyId !== "string" || obj.keyId.length === 0) {
    throw new WrapKeyBackupError("Envelope is missing a keyId string");
  }
  if (
    typeof obj.iterations !== "number" ||
    !Number.isInteger(obj.iterations) ||
    obj.iterations < 1
  ) {
    throw new WrapKeyBackupError("Envelope iterations must be a positive integer");
  }
  const salt = fromBase64Url(String(obj.salt), "envelope.salt");
  const iv = fromBase64Url(String(obj.iv), "envelope.iv");
  const ciphertext = fromBase64Url(String(obj.ciphertext), "envelope.ciphertext");
  const authTag = fromBase64Url(String(obj.authTag), "envelope.authTag");
  if (salt.length !== SALT_BYTES) {
    throw new WrapKeyBackupError(`Envelope salt must be ${SALT_BYTES} bytes`);
  }
  if (iv.length !== IV_BYTES) {
    throw new WrapKeyBackupError(`Envelope iv must be ${IV_BYTES} bytes`);
  }
  if (authTag.length !== AUTH_TAG_BYTES) {
    throw new WrapKeyBackupError(`Envelope authTag must be ${AUTH_TAG_BYTES} bytes`);
  }
  if (ciphertext.length !== WRAP_KEY_BYTES) {
    throw new WrapKeyBackupError(
      `Envelope ciphertext must be ${WRAP_KEY_BYTES} bytes (got ${ciphertext.length})`,
    );
  }
  const derived = pbkdf2Sync(passphrase, salt, obj.iterations, PBKDF2_KEY_BYTES, "sha256");
  const decipher = createDecipheriv("aes-256-gcm", derived, iv, { authTagLength: AUTH_TAG_BYTES });
  decipher.setAuthTag(authTag);
  let raw: Buffer;
  try {
    raw = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch (error) {
    throw new WrapKeyBackupError(
      "AES-256-GCM authentication failed — wrong passphrase, tampered envelope, or wrong salt",
      { cause: error },
    );
  }
  if (raw.length !== WRAP_KEY_BYTES) {
    throw new WrapKeyBackupError(
      `Decrypted key must be ${WRAP_KEY_BYTES} bytes (got ${raw.length})`,
    );
  }
  return { key: raw, keyId: obj.keyId };
}

export interface RotateWrappingKeyOptions {
  oldKeyring: SyncWrappingKeyProvider;
  newKey: { keyId: string; key: Buffer };
  /**
   * Function that re-writes a single stored device identity with the new
   * envelope. Doctor wires this to the SQLite store; tests inject an
   * in-memory implementation.
   */
  rewrite: (
    identityKey: string,
    next: StoredDeviceIdentity,
  ) => StoredDeviceIdentity | Promise<StoredDeviceIdentity>;
  /** Function that enumerates wrapped identities. */
  listWrapped: () => Array<{ identityKey: string; identity: StoredDeviceIdentity }>;
}

export interface RotateWrappingKeyResult {
  rotated: number;
  skipped: number;
}

/**
 * Re-wrap every wrapped device-identity row from the old keyring under
 * `newKey`. Plaintext rows are skipped; Doctor's next refresh will seal
 * them. The function is deliberately engine-agnostic — the caller wires
 * `listWrapped` and `rewrite` to whatever persistence layer is in use.
 */
export async function rotateWrappingKey(
  options: RotateWrappingKeyOptions,
): Promise<RotateWrappingKeyResult> {
  if (!options || typeof options !== "object") {
    throw new WrapKeyRotationError("rotateWrappingKey requires an options object");
  }
  if (!options.oldKeyring || !options.newKey || !options.rewrite || !options.listWrapped) {
    throw new WrapKeyRotationError(
      "rotateWrappingKey requires { oldKeyring, newKey, rewrite, listWrapped }",
    );
  }
  if (!options.newKey.key || options.newKey.key.length !== WRAP_KEY_BYTES) {
    throw new WrapKeyRotationError(`rotateWrappingKey newKey.key must be ${WRAP_KEY_BYTES} bytes`);
  }
  assertKeyId(options.newKey.keyId);

  let rotated = 0;
  let skipped = 0;
  const wrapped = options.listWrapped();
  for (const { identityKey, identity } of wrapped) {
    if (!identity.mldsaPrivateKeyWrapped || !identity.mldsaPrivateKeyWrapKeyId) {
      skipped += 1;
      continue;
    }
    const oldResolved = options.oldKeyring.getKeyById(identity.mldsaPrivateKeyWrapKeyId);
    if (!oldResolved) {
      throw new WrapKeyRotationError(
        `Old keyring does not hold keyId "${identity.mldsaPrivateKeyWrapKeyId}" for identity "${identityKey}"`,
      );
    }
    let raw: Buffer;
    try {
      // The BLOB is UTF-8 bytes of the base64url-encoded JSON envelope
      // (whitepaper 3.2). Use the canonical deserializer to decode it
      // before unwrapping with the old key.
      const { deserializeWrappedSecret } = await import("./secret-wrapping.js");
      const canonical = deserializeWrappedSecret(
        Buffer.from(identity.mldsaPrivateKeyWrapped).toString("utf8"),
      );
      raw = unwrapSecret(canonical, identity.mldsaPrivateKeyWrapKeyId, oldResolved.key);
    } catch (error) {
      throw new WrapKeyRotationError(
        `Failed to unwrap identity "${identityKey}" under the old keyring`,
        { cause: error },
      );
    }
    const now = Date.now();
    const rewrapped = wrapSecret(raw, options.newKey.keyId, options.newKey.key, now);
    const next: StoredDeviceIdentity = {
      ...identity,
      publicKeyPem: identity.publicKeyPem, // unchanged
      privateKeyPem: "", // wrapped; unwrap on read
      mldsaPrivateKeyPem: null,
      mldsaPrivateKeyWrapped: new Uint8Array(
        Buffer.from(serializeWrappedSecret(rewrapped), "utf8"),
      ),
      mldsaPrivateKeyWrapKeyId: options.newKey.keyId,
      createdAtMs: identity.createdAtMs,
    };
    await options.rewrite(identityKey, next);
    rotated += 1;
  }
  return { rotated, skipped };
}
