import fs from "node:fs";
import { serializeWrappedSecret, wrapSecret } from "../security/secret-wrapping.js";
import { withOpenClawStateDatabaseReadOnly } from "../state/openclaw-state-db-readonly.js";
import { runOpenClawStateWriteTransaction } from "../state/openclaw-state-db.js";
import {
  DeviceIdentityStorageError,
  readStoredIdentityFromDatabase,
  resolveDeviceIdentityStore,
  validateStoredDeviceIdentity,
  type DeviceIdentityDatabase,
  type DeviceIdentityStoreOptions,
  type StoredDeviceIdentity,
  type SyncWrappingKeyProvider,
} from "./device-identity-store.js";
import { executeSqliteQuerySync, getNodeSqliteKysely } from "./kysely-sync.js";
import { decodeMlDsa65SecretKey } from "./mldsa65-key-storage.js";

/** Enumerate identity wrap metadata without requiring the secret-unwrapping key. */
export function listStoredDeviceIdentityWrapHealth(
  options: DeviceIdentityStoreOptions = {},
): Array<{ identityKey: string; identity: StoredDeviceIdentity }> {
  const resolved = resolveDeviceIdentityStore(options);
  try {
    fs.lstatSync(resolved.databasePath);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return [];
    }
    throw error;
  }
  return withOpenClawStateDatabaseReadOnly(
    (database) => {
      const db = getNodeSqliteKysely<DeviceIdentityDatabase>(database.db);
      return executeSqliteQuerySync(
        database.db,
        db.selectFrom("device_identities").selectAll().orderBy("identity_key", "asc"),
      ).rows.map((row) => ({
        identityKey: row.identity_key,
        identity: {
          deviceId: row.device_id,
          publicKeyPem: row.public_key_pem,
          privateKeyPem: row.private_key_pem,
          createdAtMs: row.created_at_ms,
          mldsaPublicKeyPem: row.mldsa_public_key_pem,
          mldsaPrivateKeyPem: row.mldsa_private_key_pem,
          mldsaPrivateKeyWrapped:
            row.mldsa_private_key_wrapped == null
              ? null
              : new Uint8Array(row.mldsa_private_key_wrapped),
          mldsaPrivateKeyWrapKeyId: row.mldsa_private_key_wrap_key_id,
        },
      }));
    },
    { env: options.env, path: resolved.databasePath },
  );
}

/** Atomically wrap or re-wrap every stored identity under one new active key. */
export function rotateStoredDeviceIdentityWrappingKey(options: {
  env?: NodeJS.ProcessEnv;
  path?: string;
  oldWrappingKeyProvider?: SyncWrappingKeyProvider | null;
  newKey: { keyId: string; key: Buffer };
}): { rotated: number } {
  if (!options.newKey.keyId.trim() || options.newKey.key.length !== 32) {
    throw new DeviceIdentityStorageError("New wrapping key must have a keyId and 32 key bytes.");
  }
  const resolved = resolveDeviceIdentityStore(options);
  return runOpenClawStateWriteTransaction(
    ({ db }) => {
      const kysely = getNodeSqliteKysely<DeviceIdentityDatabase>(db);
      const rows = executeSqliteQuerySync(
        db,
        kysely.selectFrom("device_identities").selectAll().orderBy("identity_key", "asc"),
      ).rows;
      for (const row of rows) {
        const identity = readStoredIdentityFromDatabase(
          { db },
          row.identity_key,
          options.oldWrappingKeyProvider,
        );
        if (!identity) {
          throw new DeviceIdentityStorageError(
            `SQLite device identity "${row.identity_key}" disappeared during rotation.`,
          );
        }
        validateStoredDeviceIdentity(identity, row.identity_key);
        const envelope = wrapSecret(
          Buffer.from(decodeMlDsa65SecretKey(identity.privateKeyPem)),
          options.newKey.keyId,
          options.newKey.key,
          Date.now(),
        );
        executeSqliteQuerySync(
          db,
          kysely
            .updateTable("device_identities")
            .set({
              private_key_pem: "",
              mldsa_private_key_pem: null,
              mldsa_private_key_wrapped: Buffer.from(serializeWrappedSecret(envelope), "utf8"),
              mldsa_private_key_wrap_key_id: options.newKey.keyId,
              updated_at_ms: Date.now(),
            })
            .where("identity_key", "=", row.identity_key),
        );
      }
      return { rotated: rows.length };
    },
    { env: options.env, path: resolved.databasePath },
    { operationLabel: "device-identity.rotate-wrap-key" },
  );
}
