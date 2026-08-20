// Gateway/device ML-DSA-65 (FIPS 204) identity API backed by canonical shared SQLite state.
//
// M2 (PQC migration, whitepaper 2.1): Ed25519 device identity has been removed.
// All public functions in this module now speak ML-DSA-65 (FIPS 204) only.
//
// Wire format used for stored PEM-shaped fields:
//   publicKeyPem  = "MLDSA65-PUBLIC-KEY:" + base64url(raw 1952 bytes)
//   privateKeyPem = "MLDSA65-SECRET-KEY:" + base64url(raw 4032 bytes)
//
// Sign/verify always operates on the raw 1952/4032 bytes; the prefix is for
// storage disambiguation only (FIPS 204 does not natively understand prefixes).
//
// @noble/post-quantum uses hedged mode (FIPS 204 §5.3, NIST-recommended), so each
// sign() call automatically mixes in 32 fresh random bytes — signatures are
// non-deterministic by design.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { resolveStateDir } from "../config/paths.js";
import { acquireDeviceIdentityCoordinator } from "./device-identity-coordinator.js";
import {
  generateStoredDeviceIdentity,
  insertStoredDeviceIdentityIfAbsent,
  PRIMARY_DEVICE_IDENTITY_KEY,
  readStoredDeviceIdentity,
  readStoredDeviceIdentityReadOnly,
  resolveDeviceIdentityStore,
  type DeviceIdentity,
  type DeviceIdentityStoreOptions,
  type StoredDeviceIdentity,
} from "./device-identity-store.js";
import {
  decodeBase64UrlKey,
  type SyncWrappingKeyProvider,
} from "../security/keyring-provider.js";
import {
  decodeMlDsa65PublicKey,
  decodeMlDsa65SecretKey,
  encodeMlDsa65PublicKey,
  MLDSA65_PUBLIC_KEY_BYTES,
  MLDSA65_PUBLIC_KEY_PREFIX,
  MLDSA65_SECRET_KEY_BYTES,
  MLDSA65_SECRET_KEY_PREFIX,
  MLDSA65_SIGNATURE_BYTES,
  signMlDsa65Payload as signMlDsa65PayloadImpl,
  verifyMlDsa65Signature as verifyMlDsa65SignatureImpl,
} from "./mldsa65-key-storage.js";

export type { DeviceIdentity } from "./device-identity-store.js";

const LEGACY_DEVICE_IDENTITY_RELATIVE_PATH = path.join("identity", "device.json");
const DOCTOR_CLAIM_SUFFIX = ".doctor-importing";
const NATIVE_CLAIM_SUFFIX = ".native-importing";

class DeviceIdentityMigrationRequiredError extends Error {
  constructor(filePath: string) {
    super(
      `Legacy device identity exists at ${filePath}. Run "openclaw doctor --fix" before starting the gateway or connecting this client.`,
    );
    this.name = "DeviceIdentityMigrationRequiredError";
  }
}

function toDeviceIdentity(stored: StoredDeviceIdentity): DeviceIdentity {
  return {
    deviceId: stored.deviceId,
    publicKeyPem: stored.publicKeyPem,
    privateKeyPem: stored.privateKeyPem,
  };
}

function pathMayExist(filePath: string): boolean {
  try {
    fs.lstatSync(filePath);
    return true;
  } catch (error) {
    return (error as NodeJS.ErrnoException).code !== "ENOENT";
  }
}

function resolveLegacyStateDir(options: DeviceIdentityStoreOptions): string {
  if (options.env?.OPENCLAW_STATE_DIR?.trim()) {
    return resolveStateDir(options.env);
  }
  if (options.path) {
    const databaseDir = path.dirname(path.resolve(options.path));
    return path.basename(databaseDir) === "state" ? path.dirname(databaseDir) : databaseDir;
  }
  return resolveStateDir(options.env ?? process.env);
}

/** Exact retired file owned by Doctor migration code. */
function resolveLegacyDeviceIdentityPath(options: DeviceIdentityStoreOptions = {}): string {
  return path.join(resolveLegacyStateDir(options), LEGACY_DEVICE_IDENTITY_RELATIVE_PATH);
}

function assertNoPendingLegacyIdentity(options: DeviceIdentityStoreOptions): void {
  const { identityKey } = resolveDeviceIdentityStore(options);
  if (identityKey !== PRIMARY_DEVICE_IDENTITY_KEY) {
    return;
  }
  const legacyPath = resolveLegacyDeviceIdentityPath(options);
  if (
    // Claims first, source last: both migration owners restore claim -> source atomically.
    pathMayExist(`${legacyPath}${DOCTOR_CLAIM_SUFFIX}`) ||
    pathMayExist(`${legacyPath}${NATIVE_CLAIM_SUFFIX}`) ||
    pathMayExist(legacyPath)
  ) {
    throw new DeviceIdentityMigrationRequiredError(legacyPath);
  }
}

function withDeviceIdentityCoordinator<T>(
  options: DeviceIdentityStoreOptions,
  operation: (
    resolved: ReturnType<typeof resolveDeviceIdentityStore>,
    resolvedOptions: DeviceIdentityStoreOptions,
  ) => T,
): T {
  const resolved = resolveDeviceIdentityStore(options);
  const resolvedOptions: DeviceIdentityStoreOptions = {
    ...options,
    path: resolved.databasePath,
    identityKey: resolved.identityKey,
  };
  const coordinator = acquireDeviceIdentityCoordinator({ databasePath: resolved.databasePath });
  let result: T;
  try {
    result = operation(resolved, resolvedOptions);
  } catch (operationError) {
    try {
      coordinator.release();
    } catch (releaseError) {
      const aggregateError = new AggregateError(
        [operationError, releaseError],
        "device identity operation and coordinator release both failed",
        { cause: releaseError },
      );
      throw aggregateError;
    }
    throw operationError;
  }
  coordinator.release();
  return result;
}

/**
 * Build a SyncWrappingKeyProvider from OPENCLAW_PQC_WRAP_KEY[_ID] env vars.
 * Returns undefined if neither var is set, which triggers the plaintext path
 * (a startup warning is logged in that case).
 *
 * We use a custom inline provider rather than EnvKeyring because EnvKeyring
 * hardcodes the env var name as the keyId, which would force the user to
 * set OPENCLAW_PQC_WRAP_KEY_ID = "OPENCLAW_PQC_WRAP_KEY". The env var name
 * is an implementation detail; users set a logical keyId via
 * OPENCLAW_PQC_WRAP_KEY_ID.
 */
function resolveDeviceIdentityKeyring(
  env: NodeJS.ProcessEnv = process.env,
): SyncWrappingKeyProvider | undefined {
  const raw = env.OPENCLAW_PQC_WRAP_KEY?.trim();
  if (!raw) {
    return undefined;
  }
  if (!/^[A-Za-z0-9_-]+$/.test(raw)) {
    throw new Error(
      "OPENCLAW_PQC_WRAP_KEY must be base64url (A-Z a-z 0-9 _ -); got: " + raw.slice(0, 16) + "...",
    );
  }
  const keyId = env.OPENCLAW_PQC_WRAP_KEY_ID?.trim() || "env-default";
  const decode = () => decodeBase64UrlKey(raw);
  return {
    getActiveKey: () => ({ keyId, key: decode() }),
    getKeyById: (id: string) => (id === keyId ? { keyId, key: decode() } : null),
  };
}

function loadOrCreateDeviceIdentityOwned(options: DeviceIdentityStoreOptions): DeviceIdentity {
  assertNoPendingLegacyIdentity(options);
  // Resolve wrap keyring from env. If absent, the device identity will be
  // stored with the ML-DSA-65 private key in plaintext (M5 fallback path).
  // Operators must set OPENCLAW_PQC_WRAP_KEY in production deployments.
  const wrappingKeyProvider = resolveDeviceIdentityKeyring(options.env ?? process.env);
  if (!wrappingKeyProvider) {
    process.stderr.write(
      "[openclaw][PQC] WARNING: device identity will be stored with ML-DSA-65 private key in plaintext. " +
      "Set OPENCLAW_PQC_WRAP_KEY (32-byte base64url) and OPENCLAW_PQC_WRAP_KEY_ID env vars to enable wrap. " +
      "See docs/security/pqc-whitepaper.md §2.2.1.\n",
    );
  }
  const readOptions = { ...options, wrappingKeyProvider };

  const existing = readStoredDeviceIdentity(readOptions);
  if (existing) {
    return toDeviceIdentity(existing);
  }

  // Generate outside the write transaction. The transaction rereads the row
  // before inserting so concurrent runtimes converge on one authoritative key.
  const candidate = generateStoredDeviceIdentity({ wrappingKeyProvider });
  return toDeviceIdentity(insertStoredDeviceIdentityIfAbsent(candidate, readOptions));
}

/** Load a valid canonical identity or atomically create its SQLite row. */
export function loadOrCreateDeviceIdentity(
  options: DeviceIdentityStoreOptions = {},
): DeviceIdentity {
  return withDeviceIdentityCoordinator(options, (_resolved, resolvedOptions) =>
    loadOrCreateDeviceIdentityOwned(resolvedOptions),
  );
}

const processDeviceIdentities = new Map<string, DeviceIdentity>();
const MAX_PROCESS_DEVICE_IDENTITIES = 32;

/** Keep one authoritative identity stable for the lifetime of a state-dir process. */
export function loadOrCreateProcessDeviceIdentity(
  options: DeviceIdentityStoreOptions = {},
): DeviceIdentity {
  return withDeviceIdentityCoordinator(options, (resolved, resolvedOptions) => {
    assertNoPendingLegacyIdentity(resolvedOptions);
    const cacheKey = `${resolved.databasePath}\0${resolved.identityKey}`;
    const cached = processDeviceIdentities.get(cacheKey);
    if (cached) {
      return cached;
    }
    const identity = loadOrCreateDeviceIdentityOwned(resolvedOptions);
    if (processDeviceIdentities.size >= MAX_PROCESS_DEVICE_IDENTITIES) {
      const oldestKey = processDeviceIdentities.keys().next().value;
      if (oldestKey !== undefined) {
        processDeviceIdentities.delete(oldestKey);
      }
    }
    processDeviceIdentities.set(cacheKey, identity);
    return identity;
  });
}

/** Load a valid persisted identity without creating or mutating SQLite state. */
export function loadDeviceIdentityIfPresent(
  options: DeviceIdentityStoreOptions = {},
): DeviceIdentity | null {
  return withDeviceIdentityCoordinator(options, (_resolved, resolvedOptions) => {
    assertNoPendingLegacyIdentity(resolvedOptions);
    const stored = readStoredDeviceIdentityReadOnly(resolvedOptions);
    return stored ? toDeviceIdentity(stored) : null;
  });
}

/** Sign a UTF-8 payload with an ML-DSA-65 secret key (MLDSA65-SECRET-KEY prefixed). */
export function signDevicePayload(privateKeyPem: string, payload: string): string {
  if (typeof privateKeyPem !== "string") {
    throw new Error("ML-DSA-65 secret key must be a string");
  }
  if (!privateKeyPem.startsWith(MLDSA65_SECRET_KEY_PREFIX)) {
    throw new Error(
      `Device secret key must be prefixed with "${MLDSA65_SECRET_KEY_PREFIX}" (ML-DSA-65, FIPS 204).`,
    );
  }
  // Defensive: confirm the prefix payload actually decodes before signing.
  decodeMlDsa65SecretKey(privateKeyPem);
  return signMlDsa65PayloadImpl(privateKeyPem, payload);
}

/**
 * Try to interpret `base64Url` as a raw base64url-encoded ML-DSA-65 public
 * key (no prefix, exactly 1952 decoded bytes). Returns null on any decode or
 * length mismatch.
 */
function tryDecodeRawMlDsa65PublicKey(base64Url: string): Uint8Array | null {
  try {
    const raw = Buffer.from(base64Url, "base64url");
    if (raw.length !== MLDSA65_PUBLIC_KEY_BYTES) {
      return null;
    }
    return new Uint8Array(raw);
  } catch {
    return null;
  }
}

/** Normalize ML-DSA-65 public key (PEM-prefixed or raw base64url) to canonical prefixed form. */
export function normalizeDevicePublicKeyBase64Url(publicKey: string): string | null {
  if (typeof publicKey !== "string" || publicKey.length === 0) {
    return null;
  }
  if (publicKey.startsWith(MLDSA65_PUBLIC_KEY_PREFIX)) {
    try {
      const raw = decodeMlDsa65PublicKey(publicKey);
      return encodeMlDsa65PublicKey(raw);
    } catch {
      return null;
    }
  }
  // Try raw base64url ML-DSA-65 public key (1952 bytes after decode).
  const raw = tryDecodeRawMlDsa65PublicKey(publicKey);
  if (!raw) {
    return null;
  }
  return encodeMlDsa65PublicKey(raw);
}

/** Derive the stable device id from an ML-DSA-65 public key (PEM-prefixed or raw base64url). */
export function deriveDeviceIdFromPublicKey(publicKey: string): string | null {
  try {
    const normalized = normalizeDevicePublicKeyBase64Url(publicKey);
    if (!normalized) {
      return null;
    }
    const raw = decodeMlDsa65PublicKey(normalized);
    if (raw.length !== MLDSA65_PUBLIC_KEY_BYTES) {
      return null;
    }
    return crypto.createHash("sha256").update(raw).digest("hex");
  } catch {
    return null;
  }
}

/** Export an ML-DSA-65 prefixed public key as canonical raw base64url bytes (no prefix). */
export function publicKeyRawBase64UrlFromPem(publicKeyPem: string): string {
  if (typeof publicKeyPem !== "string") {
    throw new Error("ML-DSA-65 public key must be a string");
  }
  if (!publicKeyPem.startsWith(MLDSA65_PUBLIC_KEY_PREFIX)) {
    throw new Error(
      `Device public key must be prefixed with "${MLDSA65_PUBLIC_KEY_PREFIX}" (ML-DSA-65, FIPS 204).`,
    );
  }
  const raw = decodeMlDsa65PublicKey(publicKeyPem);
  if (raw.length !== MLDSA65_PUBLIC_KEY_BYTES) {
    throw new Error(
      `ML-DSA-65 public key must be ${MLDSA65_PUBLIC_KEY_BYTES} bytes, got ${raw.length}`,
    );
  }
  return mldsaRawToBase64Url(raw);
}

function mldsaRawToBase64Url(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
  return Buffer.from(bin, "binary").toString("base64url");
}

/** Verify a UTF-8 payload signature against an ML-DSA-65 public key. */
export function verifyDeviceSignature(
  publicKey: string,
  payload: string,
  signatureBase64Url: string,
): boolean {
  if (typeof publicKey !== "string" || publicKey.length === 0) {
    return false;
  }
  let prefixed: string;
  if (publicKey.startsWith(MLDSA65_PUBLIC_KEY_PREFIX)) {
    prefixed = publicKey;
  } else {
    const raw = tryDecodeRawMlDsa65PublicKey(publicKey);
    if (!raw) {
      return false;
    }
    prefixed = encodeMlDsa65PublicKey(raw);
  }
  return verifyMlDsa65SignatureImpl({
    publicKey: prefixed,
    payload,
    sigBase64Url: signatureBase64Url,
  });
}

// Re-export MLDSA-65 size constants and prefixes for downstream consumers
// that need to validate wire shapes without taking a hard dependency on the
// mldsa65-key-storage module.
export {
  MLDSA65_PUBLIC_KEY_BYTES,
  MLDSA65_PUBLIC_KEY_PREFIX,
  MLDSA65_SECRET_KEY_BYTES,
  MLDSA65_SECRET_KEY_PREFIX,
  MLDSA65_SIGNATURE_BYTES,
};

// Silence "imported but unused" for symbols that exist for documentation only.
void decodeMlDsa65SecretKey;
