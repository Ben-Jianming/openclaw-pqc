// M11 (PQC migration): Ed25519 push-signing key infrastructure.
//
// Danteng's M11 dual-signature envelope (src/security/push-dual-signature.ts)
// requires BOTH an Ed25519 raw 32-byte secret AND an ML-DSA-65 raw 4032-byte
// secret. The user's PQC fork is "ML-DSA-65 only" — the original openclaw
// Ed25519 device identity was retired in the v2 migration. To keep M11's
// strict `algorithms: ["ed25519", "ml-dsa-65"]` envelope contract intact
// (legacy clients must still verify the Ed25519 half during the migration
// window), this module lazily generates a separate, dedicated Ed25519
// keypair for push signing only.
//
// Storage: $STATE_DIR/push-signing-key.bin (chmod 0600, 32 bytes raw).
// Pattern mirrors wrap-key.bin (M15.B OPENCLAW_WRAP_KEY_FILE).
//
// Key id: stable hash of the raw secret (so key rotation is detectable).
//
// IMPORTANT: This module is *infrastructure only* — it does not import or
// wire into any push transport (push-apns / push-web / Feishu WS). Step 2
// of the M11 rollout wires it into push-apns-http2.ts.

import { createHash, randomBytes } from "node:crypto";
import { chmodSync, existsSync, readFileSync, writeFileSync } from "node:fs";
import { isAbsolute, join } from "node:path";
import { ed25519 } from "@noble/curves/ed25519";

const ED25519_RAW_SECRET_KEY = 32;
const ED25519_RAW_PUBLIC_KEY = 32;

const PUSH_SIGNING_KEY_FILE_ENV = "OPENCLAW_PUSH_SIGNING_KEY_FILE";
const FILE_MODE_0600 = 0o600;

const STATE_DIR_ENV = "OPENCLAW_STATE_DIR";
const DEFAULT_STATE_DIR = "/home/benjamin/pqc-fork-state";
const DEFAULT_PUSH_SIGNING_KEY_FILENAME = "push-signing-key.bin";

/** Resolve the file path for the push signing key. */
export function resolvePushSigningKeyPath(env: NodeJS.ProcessEnv = process.env): string {
  const fromEnv = env[PUSH_SIGNING_KEY_FILE_ENV];
  if (fromEnv && fromEnv.length > 0) {
    if (!isAbsolute(fromEnv)) {
      throw new Error(
        `${PUSH_SIGNING_KEY_FILE_ENV} must be an absolute path; got ${fromEnv}`,
      );
    }
    return fromEnv;
  }
  const stateDir = env[STATE_DIR_ENV] || DEFAULT_STATE_DIR;
  return join(stateDir, DEFAULT_PUSH_SIGNING_KEY_FILENAME);
}

export interface PushSigningKey {
  /** Stable key id: hex-encoded SHA-256 of the raw secret. */
  keyId: string;
  /** Raw 32-byte Ed25519 secret. */
  secretKeyRaw: Uint8Array;
  /** Raw 32-byte Ed25519 public key. */
  publicKeyRaw: Uint8Array;
}

function assertValidKeyBytes(raw: Uint8Array, expectedLength: number, label: string): void {
  if (!(raw instanceof Uint8Array)) {
    throw new Error(`${label} must be a Uint8Array; got ${typeof raw}`);
  }
  if (raw.length !== expectedLength) {
    throw new Error(`${label} must be ${expectedLength} bytes; got ${raw.length}`);
  }
}

function keyIdFromSecret(secretRaw: Uint8Array): string {
  return createHash("sha256").update(secretRaw).digest("hex").slice(0, 16);
}

/** Generate a new raw 32-byte Ed25519 secret. */
export function generatePushSigningSecretRaw(): Uint8Array {
  return randomBytes(ED25519_RAW_SECRET_KEY);
}

/** Derive the Ed25519 public key from a raw 32-byte secret. */
export function publicKeyRawFromSecretRaw(secretRaw: Uint8Array): Uint8Array {
  assertValidKeyBytes(secretRaw, ED25519_RAW_SECRET_KEY, "ed25519SecretRaw");
  // @noble/curves ed25519.getPublicKey returns raw 32 bytes
  return ed25519.getPublicKey(secretRaw);
}

function readExistingKey(filePath: string): Uint8Array | null {
  if (!existsSync(filePath)) {
    return null;
  }
  const buf = readFileSync(filePath);
  if (buf.length !== ED25519_RAW_SECRET_KEY) {
    throw new Error(
      `${filePath} exists but has wrong size: got ${buf.length}, expected ${ED25519_RAW_SECRET_KEY} (raw Ed25519 secret)`,
    );
  }
  return new Uint8Array(buf);
}

function writeNewKey(filePath: string, secretRaw: Uint8Array): void {
  writeFileSync(filePath, secretRaw, { mode: FILE_MODE_0600 });
  // Belt-and-suspenders: chmod in case the umask overrode the mode option.
  chmodSync(filePath, FILE_MODE_0600);
}

/**
 * Get or create the Ed25519 push-signing key.
 *
 * Lazy: reads from $OPENCLAW_PUSH_SIGNING_KEY_FILE (or
 * $OPENCLAW_STATE_DIR/push-signing-key.bin) if it exists. Otherwise
 * generates a new 32-byte secret, writes it to the file with mode 0600,
 * and returns the derived public key.
 */
export function getOrCreatePushSigningKey(
  env: NodeJS.ProcessEnv = process.env,
): PushSigningKey {
  const filePath = resolvePushSigningKeyPath(env);
  let secretRaw = readExistingKey(filePath);
  if (secretRaw === null) {
    secretRaw = generatePushSigningSecretRaw();
    writeNewKey(filePath, secretRaw);
  }
  const publicRaw = publicKeyRawFromSecretRaw(secretRaw);
  return {
    keyId: keyIdFromSecret(secretRaw),
    secretKeyRaw: secretRaw,
    publicKeyRaw: publicRaw,
  };
}

export const PUSH_SIGNING_KEY_CONSTANTS = {
  ED25519_RAW_SECRET_KEY,
  ED25519_RAW_PUBLIC_KEY,
  PUSH_SIGNING_KEY_FILE_ENV,
  FILE_MODE_0600,
} as const;
