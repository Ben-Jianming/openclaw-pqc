import { existsSync } from "node:fs";
import type { PushKeyPolicy } from "../shared/push-key-policy.js";
import type { OpenClawStateDatabaseOptions } from "../state/openclaw-state-db-contract.js";
import { withOpenClawStateDatabaseReadOnly } from "../state/openclaw-state-db-readonly.js";
import { ensurePqcPushStateSchema } from "../state/openclaw-state-db-schema-additive.js";
import { tableExists } from "../state/openclaw-state-db-schema-helpers.js";
import type { DB } from "../state/openclaw-state-db.generated.js";
import {
  openOpenClawStateDatabase,
  runOpenClawStateWriteTransaction,
} from "../state/openclaw-state-db.js";
import { resolveOpenClawStateSqlitePath } from "../state/openclaw-state-db.paths.js";
import { loadDeviceIdentityIfPresent } from "./device-identity.js";
import {
  executeSqliteQuerySync,
  executeSqliteQueryTakeFirstSync,
  getNodeSqliteKysely,
} from "./kysely-sync.js";
import { decodeMlDsa65PublicKey } from "./mldsa65-key-storage.js";
import { getExistingPushSigningKey } from "./push-signing-key.js";

export class PushKeyEnrollmentRequiredError extends Error {
  constructor() {
    super("push key policy missing or public key changed; explicit enrollment required");
    this.name = "PushKeyEnrollmentRequiredError";
  }
}

function policyDatabase(options: OpenClawStateDatabaseOptions) {
  const database = openOpenClawStateDatabase(options);
  ensurePqcPushStateSchema(database.db);
  return database;
}

/** Existing trust survives missing key files; absence of files is not a fresh profile. */
export function hasStoredPushKeyPolicies(options: OpenClawStateDatabaseOptions = {}): boolean {
  if (!existsSync(options.path ?? resolveOpenClawStateSqlitePath(options.env))) {
    return false;
  }
  return withOpenClawStateDatabaseReadOnly(({ db }) => {
    if (!tableExists(db, "pqc_push_key_policies")) {
      return false;
    }
    return Boolean(
      executeSqliteQueryTakeFirstSync(
        db,
        getNodeSqliteKysely<DB>(db).selectFrom("pqc_push_key_policies").select("key_id"),
      ),
    );
  }, options);
}

/** Explicit local administration: never generate replacement keys or invent a lifetime. */
export function enrollExistingPushKeys(
  validity: { validFromMs: number; validUntilMs: number },
  options: OpenClawStateDatabaseOptions = {},
): void {
  persistExistingPushKeys(validity, options, "enroll");
}

/** Explicit local renewal preserves identity and cannot reverse a revocation. */
export function renewExistingPushKeys(
  validity: { validFromMs: number; validUntilMs: number },
  options: OpenClawStateDatabaseOptions = {},
): void {
  persistExistingPushKeys(validity, options, "renew");
}

function persistExistingPushKeys(
  validity: { validFromMs: number; validUntilMs: number },
  options: OpenClawStateDatabaseOptions,
  operation: "enroll" | "renew",
): void {
  if (
    !Number.isSafeInteger(validity.validFromMs) ||
    validity.validFromMs < 0 ||
    !Number.isSafeInteger(validity.validUntilMs) ||
    validity.validUntilMs <= validity.validFromMs
  ) {
    throw new Error("explicit safe-integer push key validity required");
  }
  // Read keys before opening a write transaction. Missing material is not a provisioning request.
  const ed = getExistingPushSigningKey(options.env);
  const identity = loadDeviceIdentityIfPresent(options);
  if (!identity) {
    throw new Error("existing push device identity required");
  }
  const entries = [
    {
      algorithm: "ed25519",
      keyId: ed.keyId,
      publicKey: Buffer.from(ed.publicKeyRaw).toString("base64url"),
    },
    {
      algorithm: "ml-dsa-65",
      keyId: "primary",
      publicKey: Buffer.from(decodeMlDsa65PublicKey(identity.publicKeyPem)).toString("base64url"),
    },
  ];
  const database = policyDatabase(options);
  runOpenClawStateWriteTransaction(
    ({ db }) => {
      const sql = getNodeSqliteKysely<DB>(db);
      // One local signing identity owns the pair in this profile. Looking up only
      // the candidate IDs would mistake replaced keys for a fresh enrollment.
      const existing = executeSqliteQuerySync(
        db,
        sql.selectFrom("pqc_push_key_policies").selectAll().limit(3),
      ).rows;
      if (
        existing.length > 0 &&
        (existing.length !== entries.length ||
          !entries.every((entry) =>
            existing.some(
              (row) =>
                row.sender_id === identity.deviceId &&
                row.algorithm === entry.algorithm &&
                row.key_id === entry.keyId &&
                row.public_key_base64url === entry.publicKey,
            ),
          ))
      ) {
        throw new Error(
          "existing push policy set does not match identities; explicit recovery or reviewed rotation required",
        );
      }
      for (const entry of entries) {
        const current = existing.find((row) => row.algorithm === entry.algorithm);
        if (operation === "renew") {
          // Revalidate both authoritative rows in one transaction: failure on either
          // algorithm must roll back the other, including a concurrent revocation.
          if (
            !current ||
            current.revoked_at_ms !== null ||
            current.public_key_base64url !== entry.publicKey ||
            current.valid_from_ms !== validity.validFromMs ||
            validity.validUntilMs <= current.valid_until_ms ||
            validity.validUntilMs <= Date.now()
          ) {
            throw new Error(
              "renewal requires enrolled, unrevoked keys and an extended future expiry with the original validity start",
            );
          }
          if (!Number.isSafeInteger(current.revision + 1)) {
            throw new Error("push policy revision exhausted");
          }
          executeSqliteQuerySync(
            db,
            sql
              .updateTable("pqc_push_key_policies")
              .set({ valid_until_ms: validity.validUntilMs, revision: current.revision + 1 })
              .where("sender_id", "=", identity.deviceId)
              .where("algorithm", "=", entry.algorithm)
              .where("key_id", "=", entry.keyId),
          );
          continue;
        }
        if (current) {
          // Enrollment is idempotent, not renewal/reactivation or an alias for key rotation.
          if (
            current.public_key_base64url !== entry.publicKey ||
            current.valid_from_ms !== validity.validFromMs ||
            current.valid_until_ms !== validity.validUntilMs ||
            current.revoked_at_ms !== null
          ) {
            throw new Error("existing push policy differs or is revoked; enrollment refused");
          }
          continue;
        }
        executeSqliteQuerySync(
          db,
          sql.insertInto("pqc_push_key_policies").values({
            sender_id: identity.deviceId,
            algorithm: entry.algorithm,
            key_id: entry.keyId,
            public_key_base64url: entry.publicKey,
            valid_from_ms: validity.validFromMs,
            valid_until_ms: validity.validUntilMs,
            revoked_at_ms: null,
            revision: 1,
          }),
        );
      }
    },
    { database },
  );
}

/** Called on every key RPC/signing decision; no process cache can hide a committed revocation. */
export function readPushKeyPolicy(
  senderId: string,
  algorithm: PushKeyPolicy["algorithm"],
  keyId: string,
  publicKeyBase64Url: string,
  options: OpenClawStateDatabaseOptions = {},
): PushKeyPolicy {
  // Diagnostics and recipient reads must not create tables or silently enroll keys.
  return withOpenClawStateDatabaseReadOnly(({ db }) => {
    if (!tableExists(db, "pqc_push_key_policies")) {
      throw new PushKeyEnrollmentRequiredError();
    }
    const sql = getNodeSqliteKysely<DB>(db);
    const row = executeSqliteQueryTakeFirstSync(
      db,
      sql
        .selectFrom("pqc_push_key_policies")
        .selectAll()
        .where("sender_id", "=", senderId)
        .where("algorithm", "=", algorithm)
        .where("key_id", "=", keyId),
    );
    if (!row || row.public_key_base64url !== publicKeyBase64Url) {
      throw new PushKeyEnrollmentRequiredError();
    }
    return {
      algorithm,
      keyId,
      senderId,
      publicKeyBase64Url,
      status: row.revoked_at_ms === null ? "active" : "revoked",
      validFromMs: row.valid_from_ms,
      validUntilMs: row.valid_until_ms,
      revision: row.revision,
    };
  }, options);
}

/** Local administrative API only; recipient RPCs must never expose mutation of sender trust. */
export function revokePushKeyPolicy(
  key: { senderId: string; algorithm: PushKeyPolicy["algorithm"]; keyId: string },
  options: OpenClawStateDatabaseOptions = {},
): void {
  const nowMs = Date.now();
  const database = policyDatabase(options);
  runOpenClawStateWriteTransaction(
    ({ db }) => {
      const sql = getNodeSqliteKysely<DB>(db);
      const row = executeSqliteQueryTakeFirstSync(
        db,
        sql
          .selectFrom("pqc_push_key_policies")
          .selectAll()
          .where("sender_id", "=", key.senderId)
          .where("algorithm", "=", key.algorithm)
          .where("key_id", "=", key.keyId),
      );
      if (!row) {
        throw new Error("cannot revoke an unknown push key");
      }
      if (row.revoked_at_ms !== null) {
        return;
      }
      if (!Number.isSafeInteger(row.revision + 1)) {
        throw new Error("push policy revision exhausted");
      }
      executeSqliteQuerySync(
        db,
        sql
          .updateTable("pqc_push_key_policies")
          .set({ revoked_at_ms: nowMs, revision: row.revision + 1 })
          .where("sender_id", "=", key.senderId)
          .where("algorithm", "=", key.algorithm)
          .where("key_id", "=", key.keyId),
      );
    },
    { database },
  );
}
