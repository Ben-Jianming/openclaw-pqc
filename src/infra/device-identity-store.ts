// Canonical SQLite storage for gateway/device ML-DSA-65 (FIPS 204) identities.
//
// M2 (PQC migration, whitepaper 2.1): the device identity is now ML-DSA-65.
// M3 (whitepaper 2.1.3 + 2.2.1): the `device_identities` table gains four
//   additive ML-DSA-65 / wrap-envelope columns.
// M5 (whitepaper 2.2.2 + 2.2.3 + 2.2.4): this module now writes through the
//   wrap envelope when a `SyncWrappingKeyProvider` is supplied, and reads
//   back the unwrapped secret synchronously. Wrapped rows are fail-closed:
//   if no keyring is supplied the read throws — there is no silent
//   plaintext fallback. Legacy Ed25519 PEM rows fall through to the
//   doctor-repair path which deletes them and writes a fresh ML-DSA-65
//   identity.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type { Insertable, Selectable } from "kysely";
import {
  deserializeWrappedSecret,
  serializeWrappedSecret,
  unwrapSecret,
  wrapSecret,
  type WrappedSecret,
} from "../security/secret-wrapping.js";
import { withOpenClawStateDatabaseReadOnly } from "../state/openclaw-state-db-readonly.js";
import type { DB as OpenClawStateKyselyDatabase } from "../state/openclaw-state-db.generated.js";
import {
  openOpenClawStateDatabase,
  runOpenClawStateWriteTransaction,
  type OpenClawStateDatabaseOptions,
} from "../state/openclaw-state-db.js";
import { resolveOpenClawStateSqlitePath } from "../state/openclaw-state-db.paths.js";
import {
  executeSqliteQuerySync,
  executeSqliteQueryTakeFirstSync,
  getNodeSqliteKysely,
} from "./kysely-sync.js";
import {
  decodeMlDsa65PublicKey,
  decodeMlDsa65SecretKey,
  encodeMlDsa65PublicKey,
  encodeMlDsa65SecretKey,
  generateMlDsa65Keypair,
  MLDSA65_PUBLIC_KEY_BYTES,
  MLDSA65_PUBLIC_KEY_PREFIX,
  MLDSA65_SECRET_KEY_BYTES,
  MLDSA65_SECRET_KEY_PREFIX,
  signMlDsa65Payload,
  verifyMlDsa65Signature,
} from "./mldsa65-key-storage.js";

export const PRIMARY_DEVICE_IDENTITY_KEY = "primary";

export type DeviceIdentity = {
  deviceId: string;
  publicKeyPem: string;
  privateKeyPem: string;
};

/**
 * Runtime shape carrying the persisted ML-DSA-65 material. `mldsaPrivateKeyPem`
 * is the unwrapped secret (only populated when no wrap envelope is present).
 * `mldsaPrivateKeyWrapped` / `mldsaPrivateKeyWrapKeyId` are the diagnostic
 * envelope fields Doctor may need to repair or rotate without losing the
 * wrap provenance.
 */
export type StoredDeviceIdentity = DeviceIdentity & {
  createdAtMs: number;
  mldsaPublicKeyPem: string | null;
  mldsaPrivateKeyPem: string | null;
  mldsaPrivateKeyWrapped: Uint8Array | null;
  mldsaPrivateKeyWrapKeyId: string | null;
};

export type DeviceIdentityStoreOptions = OpenClawStateDatabaseOptions & {
  identityKey?: string;
};

export interface DeviceIdentityReadOptions extends DeviceIdentityStoreOptions {
  /** When set, wrapped rows are unwrapped through this keyring synchronously. */
  wrappingKeyProvider?: SyncWrappingKeyProvider | null;
}

export interface GenerateStoredDeviceIdentityOptions {
  now?: number;
  /** When set, the secret key is wrapped before being persisted. */
  wrappingKeyProvider?: SyncWrappingKeyProvider | null;
}

/**
 * Synchronous keyring interface used by the device-identity-store. M6
 * implements this with File / Env / Composite providers. The async surface
 * in `secret-wrapping.ts` is kept for future native keyrings that cannot
 * offer sync resolution.
 */
export interface SyncWrappingKeyProvider {
  getActiveKey(): { keyId: string; key: Buffer };
  getKeyById(keyId: string): { keyId: string; key: Buffer } | null;
}

type DeviceIdentityDatabase = Pick<OpenClawStateKyselyDatabase, "device_identities">;
type DeviceIdentityRow = Selectable<DeviceIdentityDatabase["device_identities"]>;
type DeviceIdentityInsert = Insertable<DeviceIdentityDatabase["device_identities"]>;

export class DeviceIdentityStorageError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "DeviceIdentityStorageError";
  }
}

function normalizeIdentityKey(key: string | undefined): string {
  const normalized = key ?? PRIMARY_DEVICE_IDENTITY_KEY;
  if (normalized.length === 0 || normalized !== normalized.trim()) {
    throw new DeviceIdentityStorageError(
      "Device identity key must be a non-empty string without surrounding whitespace.",
    );
  }
  if (normalized.length > 128) {
    throw new DeviceIdentityStorageError("Device identity key exceeds 128 characters.");
  }
  return normalized;
}

function invalidStoredIdentityError(
  identityKey: string,
  cause?: unknown,
): DeviceIdentityStorageError {
  return new DeviceIdentityStorageError(
    `SQLite contains an invalid persisted device identity "${identityKey}". Run "openclaw doctor --fix" before starting the gateway or connecting this client.`,
    cause === undefined ? undefined : { cause },
  );
}

/** Fingerprint = SHA-256 over the raw 1952-byte ML-DSA-65 public key. */
function fingerprintPublicKey(publicKey: string): string {
  const raw = decodeMlDsa65PublicKey(publicKey);
  return crypto.createHash("sha256").update(raw).digest("hex");
}

/**
 * Build a stored identity by generating a fresh ML-DSA-65 keypair. When a
 * `wrappingKeyProvider` is supplied the secret key is sealed under the
 * active key; otherwise the secret key is stored in plaintext
 * MLDSA65-SECRET-KEY form. Plaintext and wrapped are mutually exclusive.
 */
export function generateStoredDeviceIdentity(
  options: GenerateStoredDeviceIdentityOptions = {},
): StoredDeviceIdentity {
  const now = options.now ?? Date.now();
  const { publicKey, secretKey } = generateMlDsa65Keypair();
  const publicKeyPem = encodeMlDsa65PublicKey(publicKey);
  const deviceId = fingerprintPublicKey(publicKeyPem);
  if (options.wrappingKeyProvider) {
    const { keyId, key } = options.wrappingKeyProvider.getActiveKey();
    const wrapped = wrapSecret(Buffer.from(secretKey), keyId, key, now);
    return {
      deviceId,
      publicKeyPem,
      // plaintext form intentionally absent on a wrapped row
      privateKeyPem: "",
      createdAtMs: now,
      mldsaPublicKeyPem: publicKeyPem,
      mldsaPrivateKeyPem: null,
      mldsaPrivateKeyWrapped: new Uint8Array(Buffer.from(serializeWrappedSecret(wrapped), "utf8")),
      mldsaPrivateKeyWrapKeyId: keyId,
    };
  }
  const privateKeyPem = encodeMlDsa65SecretKey(secretKey);
  return {
    deviceId,
    publicKeyPem,
    privateKeyPem,
    createdAtMs: now,
    mldsaPublicKeyPem: publicKeyPem,
    mldsaPrivateKeyPem: privateKeyPem,
    mldsaPrivateKeyWrapped: null,
    mldsaPrivateKeyWrapKeyId: null,
  };
}

/**
 * Verify the prefixed ML-DSA-65 public/secret pair is well-formed and
 * round-trips through sign/verify. ML-DSA-65 uses hedged signing, so we
 * pick a fresh probe payload per call to avoid signature reuse.
 */
function keyPairMatches(publicKeyPem: string, privateKeyPem: string): boolean {
  try {
    if (typeof publicKeyPem !== "string" || typeof privateKeyPem !== "string") return false;
    if (!publicKeyPem.startsWith(MLDSA65_PUBLIC_KEY_PREFIX)) return false;
    if (!privateKeyPem.startsWith(MLDSA65_SECRET_KEY_PREFIX)) return false;
    const rawPk = decodeMlDsa65PublicKey(publicKeyPem);
    const rawSk = decodeMlDsa65SecretKey(privateKeyPem);
    if (rawPk.length !== MLDSA65_PUBLIC_KEY_BYTES) return false;
    if (rawSk.length !== MLDSA65_SECRET_KEY_BYTES) return false;
    const probePayload = `ml-dsa-65-roundtrip-${Date.now()}-${Math.random().toString(36).slice(2)}`;
    const sig = signMlDsa65Payload(privateKeyPem, probePayload);
    return verifyMlDsa65Signature({
      publicKey: publicKeyPem,
      payload: probePayload,
      sigBase64Url: sig,
    });
  } catch {
    return false;
  }
}

function parseCreatedAtMs(value: unknown): number | null {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0 ? value : null;
}

/** Validate persisted key material and return the canonical runtime shape. */
export function validateStoredDeviceIdentity(
  value: StoredDeviceIdentity,
  identityKey = PRIMARY_DEVICE_IDENTITY_KEY,
): DeviceIdentity {
  try {
    // A wrapped row is validated on the wrap envelope (or, when the
    // caller has already unwrapped, the unwrapped privateKeyPem). A
    // plaintext row is validated by direct keyPairMatches. Either path
    // proves the row carries usable ML-DSA-65 material; this is the
    // fail-closed contract for wrapped rows that have been resolved.
    const isWrapped =
      value.mldsaPrivateKeyWrapped !== null && value.mldsaPrivateKeyWrapKeyId !== null;
    if (
      !value.deviceId ||
      !/^[a-f0-9]{64}$/.test(value.deviceId) ||
      !value.publicKeyPem ||
      parseCreatedAtMs(value.createdAtMs) === null
    ) {
      throw invalidStoredIdentityError(identityKey);
    }
    if (!isWrapped) {
      if (!value.privateKeyPem || !keyPairMatches(value.publicKeyPem, value.privateKeyPem)) {
        throw invalidStoredIdentityError(identityKey);
      }
    } else {
      // Wrapped rows must carry the envelope fields together.
      if (!value.mldsaPrivateKeyWrapped || value.mldsaPrivateKeyWrapped.length === 0) {
        throw invalidStoredIdentityError(identityKey);
      }
      if (
        typeof value.mldsaPrivateKeyWrapKeyId !== "string" ||
        value.mldsaPrivateKeyWrapKeyId.length === 0
      ) {
        throw invalidStoredIdentityError(identityKey);
      }
      if (value.privateKeyPem) {
        // Caller has already unwrapped — verify the round-trip.
        if (!keyPairMatches(value.publicKeyPem, value.privateKeyPem)) {
          throw invalidStoredIdentityError(identityKey);
        }
      }
    }
    const derivedDeviceId = fingerprintPublicKey(value.publicKeyPem);
    if (derivedDeviceId !== value.deviceId) {
      throw invalidStoredIdentityError(identityKey);
    }
    return {
      deviceId: value.deviceId,
      publicKeyPem: value.publicKeyPem,
      privateKeyPem: value.privateKeyPem,
    };
  } catch (error) {
    if (error instanceof DeviceIdentityStorageError) {
      throw error;
    }
    throw invalidStoredIdentityError(identityKey, error);
  }
}

function rowToStoredIdentity(
  row: DeviceIdentityRow,
  expectedIdentityKey: string,
  wrappingKeyProvider: SyncWrappingKeyProvider | null | undefined,
): StoredDeviceIdentity {
  if (
    row.identity_key !== expectedIdentityKey ||
    typeof row.device_id !== "string" ||
    typeof row.public_key_pem !== "string" ||
    typeof row.private_key_pem !== "string" ||
    parseCreatedAtMs(row.created_at_ms) === null ||
    parseCreatedAtMs(row.updated_at_ms) === null
  ) {
    throw invalidStoredIdentityError(expectedIdentityKey);
  }
  const mldsaPublicKeyPem =
    typeof row.mldsa_public_key_pem === "string" && row.mldsa_public_key_pem.length > 0
      ? row.mldsa_public_key_pem
      : null;
  const mldsaPrivateKeyPem =
    typeof row.mldsa_private_key_pem === "string" && row.mldsa_private_key_pem.length > 0
      ? row.mldsa_private_key_pem
      : null;
  const mldsaPrivateKeyWrapKeyId =
    typeof row.mldsa_private_key_wrap_key_id === "string" &&
    row.mldsa_private_key_wrap_key_id.length > 0
      ? row.mldsa_private_key_wrap_key_id
      : null;
  const wrappedBlob = row.mldsa_private_key_wrapped;
  const mldsaPrivateKeyWrapped =
    wrappedBlob !== null && wrappedBlob !== undefined && wrappedBlob.length > 0
      ? new Uint8Array(wrappedBlob)
      : null;

  // Read priority for the public key: mldsa_public_key_pem (M3+) > legacy
  // public_key_pem (M1/M2). The private key flow: a present wrap envelope
  // is unwrapped via the keyring; otherwise the M1/M2 plaintext PEM (under
  // the mldsa_* column when present, or the legacy private_key_pem column)
  // is used. Plaintext / wrapped are mutually exclusive in the same row.
  const publicKeyPem = mldsaPublicKeyPem ?? row.public_key_pem;
  let privateKeyPem: string;
  if (mldsaPrivateKeyWrapped && mldsaPrivateKeyWrapKeyId) {
    if (!wrappingKeyProvider) {
      throw new DeviceIdentityStorageError(
        `SQLite device identity "${expectedIdentityKey}" is wrapped under keyId "${mldsaPrivateKeyWrapKeyId}" but no WrappingKeyProvider was supplied. Run "openclaw wrap-key import" or "openclaw doctor --fix" before starting the gateway.`,
      );
    }
    const resolved = wrappingKeyProvider.getKeyById(mldsaPrivateKeyWrapKeyId);
    if (!resolved) {
      throw new DeviceIdentityStorageError(
        `Wrapping key "${mldsaPrivateKeyWrapKeyId}" is not present in the keyring. Import it with "openclaw wrap-key import" before starting the gateway.`,
      );
    }
    let envelope: WrappedSecret;
    try {
      envelope = deserializeWrappedSecret(Buffer.from(mldsaPrivateKeyWrapped).toString("utf8"));
    } catch (error) {
      throw new DeviceIdentityStorageError(
        `SQLite device identity "${expectedIdentityKey}" has a malformed wrap envelope.`,
        { cause: error },
      );
    }
    let raw: Buffer;
    try {
      raw = unwrapSecret(envelope, mldsaPrivateKeyWrapKeyId, resolved.key);
    } catch (error) {
      throw new DeviceIdentityStorageError(
        `Failed to unwrap device identity "${expectedIdentityKey}": ${(error as Error).message}`,
        { cause: error },
      );
    }
    privateKeyPem = encodeMlDsa65SecretKey(raw);
  } else if (mldsaPrivateKeyPem) {
    privateKeyPem = mldsaPrivateKeyPem;
  } else {
    privateKeyPem = row.private_key_pem;
  }
  return {
    deviceId: row.device_id,
    publicKeyPem,
    privateKeyPem,
    createdAtMs: row.created_at_ms,
    mldsaPublicKeyPem,
    mldsaPrivateKeyPem,
    mldsaPrivateKeyWrapped,
    mldsaPrivateKeyWrapKeyId,
  };
}

function salvageStoredIdentityRow(
  row: DeviceIdentityRow,
  expectedIdentityKey: string,
  repairedAtMs: number,
): StoredDeviceIdentity | null {
  // M2 + M5 salvage accepts ML-DSA-65 prefixed rows. Legacy Ed25519 PEM
  // rows fall through to the doctor-repair path which deletes the bad
  // row and writes a fresh ML-DSA-65 identity.
  if (
    row.identity_key !== expectedIdentityKey ||
    typeof row.public_key_pem !== "string" ||
    typeof row.private_key_pem !== "string" ||
    !row.public_key_pem.startsWith(MLDSA65_PUBLIC_KEY_PREFIX) ||
    !row.private_key_pem.startsWith(MLDSA65_SECRET_KEY_PREFIX)
  ) {
    return null;
  }
  try {
    if (!keyPairMatches(row.public_key_pem, row.private_key_pem)) {
      return null;
    }
    const createdAtMs =
      parseCreatedAtMs(row.created_at_ms) ?? parseCreatedAtMs(row.updated_at_ms) ?? repairedAtMs;
    const mldsaPublicKeyPem =
      typeof row.mldsa_public_key_pem === "string" && row.mldsa_public_key_pem.length > 0
        ? row.mldsa_public_key_pem
        : row.public_key_pem;
    const mldsaPrivateKeyPem =
      typeof row.mldsa_private_key_pem === "string" && row.mldsa_private_key_pem.length > 0
        ? row.mldsa_private_key_pem
        : row.private_key_pem;
    const wrappedBlob = row.mldsa_private_key_wrapped;
    const mldsaPrivateKeyWrapped =
      wrappedBlob !== null && wrappedBlob !== undefined && wrappedBlob.length > 0
        ? new Uint8Array(wrappedBlob)
        : null;
    const mldsaPrivateKeyWrapKeyId =
      typeof row.mldsa_private_key_wrap_key_id === "string" &&
      row.mldsa_private_key_wrap_key_id.length > 0
        ? row.mldsa_private_key_wrap_key_id
        : null;
    const salvaged: StoredDeviceIdentity = {
      deviceId: fingerprintPublicKey(row.public_key_pem),
      publicKeyPem: row.public_key_pem,
      privateKeyPem: row.private_key_pem,
      createdAtMs,
      mldsaPublicKeyPem,
      mldsaPrivateKeyPem,
      mldsaPrivateKeyWrapped,
      mldsaPrivateKeyWrapKeyId,
    };
    validateStoredDeviceIdentity(salvaged, expectedIdentityKey);
    return salvaged;
  } catch {
    return null;
  }
}

function storedIdentityToRow(
  identityKey: string,
  stored: StoredDeviceIdentity,
  updatedAtMs = stored.createdAtMs,
): DeviceIdentityInsert {
  return {
    identity_key: identityKey,
    device_id: stored.deviceId,
    public_key_pem: stored.publicKeyPem,
    private_key_pem: stored.privateKeyPem,
    created_at_ms: stored.createdAtMs,
    updated_at_ms: updatedAtMs,
    mldsa_public_key_pem: stored.mldsaPublicKeyPem,
    mldsa_private_key_pem: stored.mldsaPrivateKeyPem,
    mldsa_private_key_wrapped: stored.mldsaPrivateKeyWrapped
      ? Buffer.from(stored.mldsaPrivateKeyWrapped)
      : null,
    mldsa_private_key_wrap_key_id: stored.mldsaPrivateKeyWrapKeyId,
  };
}

function readStoredIdentityRowFromDatabase(
  database: { db: Parameters<typeof getNodeSqliteKysely>[0] },
  identityKey: string,
): DeviceIdentityRow | null {
  const db = getNodeSqliteKysely<DeviceIdentityDatabase>(database.db);
  return (
    executeSqliteQueryTakeFirstSync(
      database.db,
      db.selectFrom("device_identities").selectAll().where("identity_key", "=", identityKey),
    ) ?? null
  );
}

function readStoredIdentityFromDatabase(
  database: { db: Parameters<typeof getNodeSqliteKysely>[0] },
  identityKey: string,
  wrappingKeyProvider: SyncWrappingKeyProvider | null | undefined,
): StoredDeviceIdentity | null {
  const row = readStoredIdentityRowFromDatabase(database, identityKey);
  return row ? rowToStoredIdentity(row, identityKey, wrappingKeyProvider) : null;
}

/** Resolve the concrete database and row identity used by process caches and diagnostics. */
export function resolveDeviceIdentityStore(options: DeviceIdentityStoreOptions = {}): {
  databasePath: string;
  identityKey: string;
} {
  return {
    databasePath: path.resolve(
      options.path ?? resolveOpenClawStateSqlitePath(options.env ?? process.env),
    ),
    identityKey: normalizeIdentityKey(options.identityKey),
  };
}

/** Read through the writable shared-state lifecycle, validating any existing row. */
export function readStoredDeviceIdentity(
  options: DeviceIdentityReadOptions = {},
): StoredDeviceIdentity | null {
  const resolved = resolveDeviceIdentityStore(options);
  const database = openOpenClawStateDatabase({
    env: options.env,
    path: resolved.databasePath,
  });
  const stored = readStoredIdentityFromDatabase(
    database,
    resolved.identityKey,
    options.wrappingKeyProvider,
  );
  if (stored) {
    validateStoredDeviceIdentity(stored, resolved.identityKey);
  }
  return stored;
}

/** Read without creating, repairing, chmodding, or joining the writer lifecycle. */
export function readStoredDeviceIdentityReadOnly(
  options: DeviceIdentityReadOptions = {},
): StoredDeviceIdentity | null {
  const resolved = resolveDeviceIdentityStore(options);
  try {
    fs.lstatSync(resolved.databasePath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ENOENT") {
      throw error;
    }
    return null;
  }
  return withOpenClawStateDatabaseReadOnly(
    (database) => {
      const stored = readStoredIdentityFromDatabase(
        database,
        resolved.identityKey,
        options.wrappingKeyProvider,
      );
      if (stored) {
        validateStoredDeviceIdentity(stored, resolved.identityKey);
      }
      return stored;
    },
    { env: options.env, path: resolved.databasePath },
  );
}

/** Insert a candidate only when the key is still absent, then return the authoritative row. */
export function insertStoredDeviceIdentityIfAbsent(
  candidate: StoredDeviceIdentity,
  options: DeviceIdentityReadOptions = {},
): StoredDeviceIdentity {
  const resolved = resolveDeviceIdentityStore(options);
  validateStoredDeviceIdentity(candidate, resolved.identityKey);
  return runOpenClawStateWriteTransaction(
    ({ db }) => {
      const existing = readStoredIdentityFromDatabase(
        { db },
        resolved.identityKey,
        options.wrappingKeyProvider,
      );
      if (existing) {
        validateStoredDeviceIdentity(existing, resolved.identityKey);
      } else {
        const kysely = getNodeSqliteKysely<DeviceIdentityDatabase>(db);
        executeSqliteQuerySync(
          db,
          kysely
            .insertInto("device_identities")
            .values(storedIdentityToRow(resolved.identityKey, candidate))
            .onConflict((conflict) => conflict.column("identity_key").doNothing()),
        );
      }
      const authoritative = readStoredIdentityFromDatabase(
        { db },
        resolved.identityKey,
        options.wrappingKeyProvider,
      );
      if (!authoritative) {
        throw new DeviceIdentityStorageError(
          `SQLite device identity "${resolved.identityKey}" was not durable after insert.`,
        );
      }
      validateStoredDeviceIdentity(authoritative, resolved.identityKey);
      return authoritative;
    },
    { env: options.env, path: resolved.databasePath },
    { operationLabel: "device-identity.create" },
  );
}

/** Replace only an invalid authoritative row; preserve a valid concurrent winner. */
export function repairInvalidStoredDeviceIdentity(
  candidate: StoredDeviceIdentity,
  options: DeviceIdentityReadOptions = {},
): { identity: StoredDeviceIdentity; repaired: boolean; rotated: boolean } {
  const resolved = resolveDeviceIdentityStore(options);
  validateStoredDeviceIdentity(candidate, resolved.identityKey);
  return runOpenClawStateWriteTransaction(
    ({ db }) => {
      let repaired = false;
      let rotated = false;
      let existingRow: DeviceIdentityRow | null = null;
      try {
        existingRow = readStoredIdentityRowFromDatabase({ db }, resolved.identityKey);
        const existing = existingRow
          ? rowToStoredIdentity(existingRow, resolved.identityKey, options.wrappingKeyProvider)
          : null;
        if (existing) {
          validateStoredDeviceIdentity(existing, resolved.identityKey);
          return { identity: existing, repaired, rotated };
        }
      } catch (error) {
        if (!(error instanceof DeviceIdentityStorageError)) {
          throw error;
        }
      }
      if (existingRow) {
        const salvaged = salvageStoredIdentityRow(
          existingRow,
          resolved.identityKey,
          candidate.createdAtMs,
        );
        if (salvaged) {
          executeSqliteQuerySync(
            db,
            getNodeSqliteKysely<DeviceIdentityDatabase>(db)
              .updateTable("device_identities")
              .set({
                device_id: salvaged.deviceId,
                public_key_pem: salvaged.publicKeyPem,
                private_key_pem: salvaged.privateKeyPem,
                created_at_ms: salvaged.createdAtMs,
                updated_at_ms: candidate.createdAtMs,
                mldsa_public_key_pem: salvaged.mldsaPublicKeyPem,
                mldsa_private_key_pem: salvaged.mldsaPrivateKeyPem,
                mldsa_private_key_wrapped: salvaged.mldsaPrivateKeyWrapped
                  ? Buffer.from(salvaged.mldsaPrivateKeyWrapped)
                  : null,
                mldsa_private_key_wrap_key_id: salvaged.mldsaPrivateKeyWrapKeyId,
              })
              .where("identity_key", "=", resolved.identityKey),
          );
          const authoritative = readStoredIdentityFromDatabase(
            { db },
            resolved.identityKey,
            options.wrappingKeyProvider,
          );
          if (!authoritative) {
            throw new DeviceIdentityStorageError(
              `SQLite device identity "${resolved.identityKey}" was not durable after repair.`,
            );
          }
          validateStoredDeviceIdentity(authoritative, resolved.identityKey);
          return { identity: authoritative, repaired: true, rotated };
        }
        executeSqliteQuerySync(
          db,
          getNodeSqliteKysely<DeviceIdentityDatabase>(db)
            .deleteFrom("device_identities")
            .where("identity_key", "=", resolved.identityKey),
        );
      }

      // An absent row after an invalid-row detection still means identity continuity was lost.
      // Report the generated winner so Doctor always surfaces the required re-approval.
      repaired = true;
      rotated = true;

      executeSqliteQuerySync(
        db,
        getNodeSqliteKysely<DeviceIdentityDatabase>(db)
          .insertInto("device_identities")
          .values(storedIdentityToRow(resolved.identityKey, candidate))
          .onConflict((conflict) => conflict.column("identity_key").doNothing()),
      );
      const authoritative = readStoredIdentityFromDatabase(
        { db },
        resolved.identityKey,
        options.wrappingKeyProvider,
      );
      if (!authoritative) {
        throw new DeviceIdentityStorageError(
          `SQLite device identity "${resolved.identityKey}" was not durable after repair.`,
        );
      }
      validateStoredDeviceIdentity(authoritative, resolved.identityKey);
      return { identity: authoritative, repaired, rotated };
    },
    { env: options.env, path: resolved.databasePath },
    { operationLabel: "device-identity.doctor-repair" },
  );
}
