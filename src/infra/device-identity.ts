// Gateway/device ML-DSA-65 (FIPS 204) identity API backed by canonical shared SQLite state.
//
// Locally generated Node/CLI identities use ML-DSA-65 (FIPS 204). Gateway
// verification also accepts explicitly versioned Ed25519 proofs from native
// clients while their on-device key stores migrate to ML-DSA-65.
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
import { ed25519 } from "@noble/curves/ed25519.js";
import { resolveStateDir } from "../config/paths.js";
import { pqcLog } from "../logging/pqc-log.js";
import { decodeBase64UrlKey } from "../security/keyring-provider.js";
import { acquireDeviceIdentityCoordinator } from "./device-identity-coordinator.js";
import {
  generateStoredDeviceIdentity,
  insertStoredDeviceIdentityIfAbsent,
  PRIMARY_DEVICE_IDENTITY_KEY,
  readStoredDeviceIdentity,
  readStoredDeviceIdentityReadOnly,
  resolveDeviceIdentityStore,
  wrapStoredDeviceIdentityIfPlaintext,
  type DeviceIdentity,
  type DeviceIdentityStoreOptions,
  type SyncWrappingKeyProvider,
  type StoredDeviceIdentity,
} from "./device-identity-store.js";
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
export type DeviceIdentityAlgorithm = "ed25519" | "ml-dsa-65";

const ED25519_PUBLIC_KEY_BYTES = 32;
const ED25519_SIGNATURE_BYTES = 64;

function decodeCanonicalBase64Url(value: string): Buffer | null {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) {
    return null;
  }
  try {
    const raw = Buffer.from(value, "base64url");
    return raw.toString("base64url") === value ? raw : null;
  } catch {
    return null;
  }
}

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
 * Build a SyncWrappingKeyProvider from wrap env vars. Returns undefined if
 * neither var is set, which triggers the plaintext path (a startup warning
 * is logged in that case).
 *
 * Resolution order (first wins):
 *   1. OPENCLAW_WRAP_KEY_FILE (M15.B, v3-style) - absolute path to a chmod 0600
 *      file containing a 32-byte base64url AES-256 key on the first line.
 *      Read at provider construction time, not cached.
 *   2. OPENCLAW_PQC_WRAP_KEY (M5 v2, v2-style) - raw 32-byte base64url value
 *      in env. Backward compatible with all existing deployments.
 *
 * The file path is preferred because:
 *   - It survives shell history (raw env values have been leaked 3 times)
 *   - It enables chmod 0600 enforcement as a security gate (not stat-guard)
 *   - It is the format used by danteng v3 fork and by FileKeyring class in src
 *
 * We use a custom inline provider (read-once + closure decode) rather than
 * the FileKeyring class because FileKeyring expects a JSON shape
 * (keys + activeKeyId); for the single-key v3 use case we only need a
 * raw base64url string.
 */
export function resolveDeviceIdentityKeyring(
  env: NodeJS.ProcessEnv = process.env,
): SyncWrappingKeyProvider | undefined {
  // M15.B: v3-style file-based wrap takes precedence.
  const wrapKeyFile = env.OPENCLAW_WRAP_KEY_FILE?.trim();
  if (wrapKeyFile) {
    if (!path.isAbsolute(wrapKeyFile)) {
      throw new Error(`OPENCLAW_WRAP_KEY_FILE must be absolute; got: ${wrapKeyFile}`);
    }
    const stat = fs.statSync(wrapKeyFile);
    if (process.platform !== "win32" && (stat.mode & 0o777) !== 0o600) {
      throw new Error(
        `OPENCLAW_WRAP_KEY_FILE ${wrapKeyFile} must be chmod 0600; got 0o${(stat.mode & 0o777).toString(8)}`,
      );
    }
    const raw = fs.readFileSync(wrapKeyFile, "utf8").trim();
    if (!/^[A-Za-z0-9_-]+$/.test(raw)) {
      throw new Error(
        "OPENCLAW_WRAP_KEY_FILE contents must be base64url (A-Z a-z 0-9 _ -); got: " +
          raw.slice(0, 16) +
          "...",
      );
    }
    const keyId = env.OPENCLAW_PQC_WRAP_KEY_ID?.trim() || "file-default";
    const decode = () => decodeBase64UrlKey(raw);
    return {
      getActiveKey: () => ({ keyId, key: decode() }),
      getKeyById: (id: string) => (id === keyId ? { keyId, key: decode() } : null),
    };
  }
  // M5 v2: v2-style inline env value path (backward compatible).
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
  const wrapEnvEnabled = wrappingKeyProvider !== undefined;
  if (!wrapEnvEnabled) {
    // M17: emit pqcLog so dashboard can see wrap-disabled state at startup
    pqcLog.warn({
      event: "device-identity",
      status: "fail",
      identityKey: PRIMARY_DEVICE_IDENTITY_KEY,
      detail:
        "wrap env unavailable, falling back to plaintext storage (set OPENCLAW_PQC_WRAP_KEY to enable)",
    });
  }
  const readOptions = { ...options, wrappingKeyProvider };

  let existing = readStoredDeviceIdentity(readOptions);
  if (existing) {
    if (wrapEnvEnabled && existing.mldsaPrivateKeyWrapped == null) {
      const migration = wrapStoredDeviceIdentityIfPlaintext({
        ...readOptions,
        wrappingKeyProvider: wrappingKeyProvider!,
      });
      existing = migration.identity ?? existing;
      if (migration.migrated) {
        pqcLog.info({
          event: "device-identity",
          status: "ok",
          identityKey: PRIMARY_DEVICE_IDENTITY_KEY,
          detail: "migrated existing plaintext identity to wrapped storage",
        });
      }
    }
    // M17: emit pqcLog so dashboard can see device-identity activity.
    // Distinguish: row state (actual wrap) vs env state (config intent).
    const rowIsWrapped = existing.mldsaPrivateKeyWrapped != null;
    let detail: string;
    let status: "ok" | "fail";
    if (rowIsWrapped && wrapEnvEnabled) {
      detail = "loaded existing wrapped identity (M2+M4 active)";
      status = "ok";
    } else if (rowIsWrapped && !wrapEnvEnabled) {
      detail =
        "loaded existing wrapped identity, env has no wrap (M5 fallback would kick in on next generate)";
      status = "ok";
    } else if (!rowIsWrapped && wrapEnvEnabled) {
      detail = "loaded plaintext identity while wrap migration was unavailable";
      status = "fail";
    } else {
      detail = "loaded existing legacy plaintext identity (no wrap, M5 fallback)";
      status = "ok";
    }
    pqcLog.info({
      event: "device-identity",
      status,
      identityKey: PRIMARY_DEVICE_IDENTITY_KEY,
      detail,
    });
    return toDeviceIdentity(existing);
  }

  // Generate outside the write transaction. The transaction rereads the row
  // before inserting so concurrent runtimes converge on one authoritative key.
  const candidate = generateStoredDeviceIdentity({ wrappingKeyProvider });
  const created = insertStoredDeviceIdentityIfAbsent(candidate, readOptions);
  // M17: emit pqcLog on first-time generation
  pqcLog.info({
    event: "device-identity",
    status: "ok",
    identityKey: PRIMARY_DEVICE_IDENTITY_KEY,
    detail: wrapEnvEnabled
      ? "generated and wrapped new identity (M2+M4+M5 v2 active)"
      : "generated new identity in plaintext (M5 fallback)",
  });
  return toDeviceIdentity(created);
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
  const raw = decodeCanonicalBase64Url(base64Url);
  if (!raw || raw.length !== MLDSA65_PUBLIC_KEY_BYTES) {
    return null;
  }
  return new Uint8Array(raw);
}

function tryDecodeRawEd25519PublicKey(base64Url: string): Uint8Array | null {
  const raw = decodeCanonicalBase64Url(base64Url);
  return raw?.length === ED25519_PUBLIC_KEY_BYTES ? new Uint8Array(raw) : null;
}

export function resolveDeviceIdentityAlgorithm(
  publicKey: string,
  declared?: string,
): DeviceIdentityAlgorithm | null {
  const inferred = publicKey.startsWith(MLDSA65_PUBLIC_KEY_PREFIX)
    ? "ml-dsa-65"
    : tryDecodeRawMlDsa65PublicKey(publicKey)
      ? "ml-dsa-65"
      : tryDecodeRawEd25519PublicKey(publicKey)
        ? "ed25519"
        : null;
  if (!inferred || (declared !== undefined && declared !== inferred)) {
    return null;
  }
  return inferred;
}

/** Normalize ML-DSA-65 public key (PEM-prefixed or raw base64url) to canonical prefixed form. */
export function normalizeDevicePublicKeyBase64Url(
  publicKey: string,
  algorithm?: string,
): string | null {
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
  if (algorithm === "ed25519") {
    const edRaw = tryDecodeRawEd25519PublicKey(publicKey);
    return edRaw ? Buffer.from(edRaw).toString("base64url") : null;
  }
  // Try raw base64url ML-DSA-65 public key (1952 bytes after decode).
  const raw = tryDecodeRawMlDsa65PublicKey(publicKey);
  if (raw) {
    return algorithm && algorithm !== "ml-dsa-65" ? null : encodeMlDsa65PublicKey(raw);
  }
  const edRaw = tryDecodeRawEd25519PublicKey(publicKey);
  return !algorithm || algorithm === "ed25519"
    ? edRaw
      ? Buffer.from(edRaw).toString("base64url")
      : null
    : null;
}

/** Derive the stable device id from an ML-DSA-65 public key (PEM-prefixed or raw base64url). */
export function deriveDeviceIdFromPublicKey(publicKey: string, algorithm?: string): string | null {
  try {
    const resolvedAlgorithm = resolveDeviceIdentityAlgorithm(publicKey, algorithm);
    if (!resolvedAlgorithm) {
      return null;
    }
    const normalized = normalizeDevicePublicKeyBase64Url(publicKey, resolvedAlgorithm);
    if (!normalized) {
      return null;
    }
    const raw =
      resolvedAlgorithm === "ml-dsa-65"
        ? decodeMlDsa65PublicKey(normalized)
        : Buffer.from(normalized, "base64url");
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
  for (const byte of bytes) {
    bin += String.fromCharCode(byte);
  }
  return Buffer.from(bin, "binary").toString("base64url");
}

/** Verify a UTF-8 payload signature against an ML-DSA-65 public key. */
export function verifyDeviceSignature(
  publicKey: string,
  payload: string,
  signatureBase64Url: string,
  algorithm?: string,
): boolean {
  if (typeof publicKey !== "string" || publicKey.length === 0) {
    return false;
  }
  const resolvedAlgorithm = resolveDeviceIdentityAlgorithm(publicKey, algorithm);
  if (resolvedAlgorithm === "ed25519") {
    try {
      const raw = tryDecodeRawEd25519PublicKey(publicKey);
      const signature = Buffer.from(signatureBase64Url, "base64url");
      return Boolean(
        raw &&
        signature.length === ED25519_SIGNATURE_BYTES &&
        ed25519.verify(signature, new TextEncoder().encode(payload), raw),
      );
    } catch {
      return false;
    }
  }
  if (resolvedAlgorithm !== "ml-dsa-65") {
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
