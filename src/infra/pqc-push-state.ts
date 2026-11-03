import { randomBytes, randomUUID } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import type { Kysely } from "kysely";
import type { PushReplayGuard } from "../security/push-dual-signature.js";
import {
  DEFAULT_PUSH_REFERENCE_TTL_MS,
  hashPushReferenceToken,
  matchesPushReferenceToken,
  type PushReferenceDescriptor,
  type PushReferenceStore,
  type StoredSignedPush,
} from "../security/push-reference.js";
import {
  MAX_PUSH_RECOVERY_PAGE_BYTES,
  MAX_PUSH_RECOVERY_PAGE_ITEMS,
} from "../shared/push-recovery.js";
import type { OpenClawStateDatabaseOptions } from "../state/openclaw-state-db-contract.js";
import { ensurePqcPushStateSchema } from "../state/openclaw-state-db-schema-additive.js";
import type { DB as OpenClawStateDb } from "../state/openclaw-state-db.generated.js";
import {
  openOpenClawStateDatabase,
  runOpenClawStateWriteTransaction,
} from "../state/openclaw-state-db.js";
import {
  executeSqliteQuerySync,
  executeSqliteQueryTakeFirstSync,
  getNodeSqliteKysely,
} from "./kysely-sync.js";
import {
  readPushRecoverySnapshotPage,
  type PushRecoverySnapshotCursor,
} from "./pqc-push-recovery-snapshot.js";

const MAX_PEERS = 10_000;
const MAX_OBJECTS = 2_000;
const MAX_DEVICE_OBJECTS = 100;
const MAX_PAYLOAD_BYTES = 64 * 1024;
const MAX_NONCES = 50_000;

function state(options: OpenClawStateDatabaseOptions) {
  const database = openOpenClawStateDatabase(options);
  ensurePqcPushStateSchema(database.db);
  return database;
}

function transaction<T>(
  options: OpenClawStateDatabaseOptions,
  operation: (db: DatabaseSync, sql: Kysely<OpenClawStateDb>) => T,
): T {
  const database = state(options);
  return runOpenClawStateWriteTransaction(
    ({ db }) => operation(db, getNodeSqliteKysely<OpenClawStateDb>(db)),
    { database },
  );
}

export function nextPushSequence(
  senderId: string,
  recipientId: string,
  options: OpenClawStateDatabaseOptions = {},
): number {
  return transaction(options, (db, sql) => {
    const row = executeSqliteQueryTakeFirstSync(
      db,
      sql
        .selectFrom("pqc_push_sequences")
        .select("sequence")
        .where("sender_id", "=", senderId)
        .where("recipient_id", "=", recipientId),
    );
    const sequence = (row?.sequence ?? 0) + 1;
    if (!Number.isSafeInteger(sequence)) {
      throw new Error("push sequence exhausted; rotate sender identity");
    }
    if (!row) {
      const count = executeSqliteQueryTakeFirstSync(
        db,
        sql.selectFrom("pqc_push_sequences").select(sql.fn.countAll<number>().as("count")),
      )!.count;
      if (count >= MAX_PEERS) {
        throw new Error("push sender state capacity exceeded");
      }
    }
    executeSqliteQuerySync(
      db,
      sql
        .insertInto("pqc_push_sequences")
        .values({ sender_id: senderId, recipient_id: recipientId, sequence })
        .onConflict((oc) => oc.columns(["sender_id", "recipient_id"]).doUpdateSet({ sequence })),
    );
    return sequence;
  });
}

/** Strictly increasing per peer; reordered messages are rejected, never rolled back. */
export class SqlitePushReplayGuard implements PushReplayGuard {
  constructor(
    private readonly options: OpenClawStateDatabaseOptions = {},
    private readonly now: () => number = Date.now,
  ) {}
  accept(input: Parameters<PushReplayGuard["accept"]>[0]): boolean {
    return transaction(this.options, (db) => this.acceptInTransaction(db, input));
  }
  /** Caller owns the enclosing commit; do not open a database or commit here. */
  acceptInTransaction(db: DatabaseSync, input: Parameters<PushReplayGuard["accept"]>[0]): boolean {
    if (!db.isTransaction) {
      throw new Error("push replay acceptance requires an active transaction");
    }
    const sql = getNodeSqliteKysely<OpenClawStateDb>(db);
    const nowMs = this.now();
    if (
      !Number.isSafeInteger(input.sequence) ||
      input.sequence < 0 ||
      input.createdAtMs > nowMs + 30_000 ||
      nowMs - input.createdAtMs > DEFAULT_PUSH_REFERENCE_TTL_MS
    ) {
      return false;
    }
    executeSqliteQuerySync(
      db,
      sql.deleteFrom("pqc_push_nonces").where("expires_at_ms", "<=", nowMs),
    );
    const peer = executeSqliteQueryTakeFirstSync(
      db,
      sql
        .selectFrom("pqc_push_replay")
        .select("sequence")
        .where("sender_id", "=", input.senderId)
        .where("recipient_id", "=", input.recipientId),
    );
    const seen = executeSqliteQueryTakeFirstSync(
      db,
      sql
        .selectFrom("pqc_push_nonces")
        .select("nonce")
        .where("sender_id", "=", input.senderId)
        .where("recipient_id", "=", input.recipientId)
        .where("nonce", "=", input.nonce),
    );
    if (seen || (peer && peer.sequence >= input.sequence)) {
      return false;
    }
    const peers = executeSqliteQueryTakeFirstSync(
      db,
      sql.selectFrom("pqc_push_replay").select(sql.fn.countAll<number>().as("count")),
    )!.count;
    const nonces = executeSqliteQueryTakeFirstSync(
      db,
      sql.selectFrom("pqc_push_nonces").select(sql.fn.countAll<number>().as("count")),
    )!.count;
    if ((!peer && peers >= MAX_PEERS) || nonces >= MAX_NONCES) {
      return false;
    }
    executeSqliteQuerySync(
      db,
      sql
        .insertInto("pqc_push_replay")
        .values({
          sender_id: input.senderId,
          recipient_id: input.recipientId,
          sequence: input.sequence,
        })
        .onConflict((oc) =>
          oc.columns(["sender_id", "recipient_id"]).doUpdateSet({ sequence: input.sequence }),
        ),
    );
    executeSqliteQuerySync(
      db,
      sql.insertInto("pqc_push_nonces").values({
        sender_id: input.senderId,
        recipient_id: input.recipientId,
        nonce: input.nonce,
        expires_at_ms: input.createdAtMs + DEFAULT_PUSH_REFERENCE_TTL_MS + 30_000,
      }),
    );
    return true;
  }
}

export class SqlitePushReferenceStore implements PushReferenceStore {
  constructor(private readonly options: OpenClawStateDatabaseOptions = {}) {}
  /** The signer must use this state environment: sequence and object publish in one commit. */
  createWithSignature(
    buildValue: (env: NodeJS.ProcessEnv) => StoredSignedPush,
    options: { nowMs?: number; ttlMs?: number } = {},
  ): PushReferenceDescriptor {
    // Signing is synchronous. The existing transaction helper rejects Promise results
    // and uses savepoints for the sequence/create calls on this same connection.
    return transaction(this.options, (db, sql) => {
      const value = buildValue(this.options.env ?? process.env);
      const current = executeSqliteQueryTakeFirstSync(
        db,
        sql
          .selectFrom("pqc_push_sequences")
          .select(["sequence", "published_sequence"])
          .where("sender_id", "=", value.envelope.sender_id)
          .where("recipient_id", "=", value.recipientId),
      );
      if (
        !current ||
        value.envelope.sequence !== current.sequence ||
        value.envelope.sequence <= current.published_sequence
      ) {
        throw new Error("push publication sequence unavailable");
      }
      const descriptor = this.create(value, options);
      executeSqliteQuerySync(
        db,
        sql
          .updateTable("pqc_push_sequences")
          .set({ published_sequence: value.envelope.sequence })
          .where("sender_id", "=", value.envelope.sender_id)
          .where("recipient_id", "=", value.recipientId),
      );
      executeSqliteQuerySync(
        db,
        sql
          .updateTable("pqc_push_objects")
          .set({ publication_version: 1 })
          .where("object_id", "=", descriptor.object_id),
      );
      return descriptor;
    });
  }
  /** New recovery protocol; immutable membership bound to the authenticated token. */
  listSnapshotForAuthenticatedRecipient(
    recipientId: string,
    tokenSha256: string,
    options: { nowMs?: number; after?: PushRecoverySnapshotCursor } = {},
  ) {
    return transaction(this.options, (db, sql) =>
      readPushRecoverySnapshotPage(db, sql, recipientId, tokenSha256, options),
    );
  }
  create(
    value: StoredSignedPush,
    options: { nowMs?: number; ttlMs?: number } = {},
  ): PushReferenceDescriptor {
    const nowMs = options.nowMs ?? Date.now();
    const ttl = options.ttlMs ?? DEFAULT_PUSH_REFERENCE_TTL_MS;
    const expiresAtMs = nowMs + ttl;
    if (
      !Number.isSafeInteger(nowMs) ||
      !Number.isSafeInteger(ttl) ||
      !Number.isSafeInteger(expiresAtMs) ||
      ttl <= 0 ||
      ttl > DEFAULT_PUSH_REFERENCE_TTL_MS ||
      Buffer.byteLength(value.payload, "utf8") > MAX_PAYLOAD_BYTES ||
      value.envelope.recipient_id !== value.recipientId ||
      Buffer.byteLength(JSON.stringify(value.envelope)) > 16 * 1024
    ) {
      throw new Error("invalid or oversized signed push reference");
    }
    const descriptor: PushReferenceDescriptor = {
      version: 1,
      object_id: randomUUID(),
      token: randomBytes(32).toString("base64url"),
      expires_at_ms: expiresAtMs,
    };
    transaction(this.options, (db, sql) => {
      executeSqliteQuerySync(
        db,
        sql.deleteFrom("pqc_push_objects").where("expires_at_ms", "<=", nowMs),
      );
      const total = executeSqliteQueryTakeFirstSync(
        db,
        sql.selectFrom("pqc_push_objects").select(sql.fn.countAll<number>().as("count")),
      )!.count;
      const device = executeSqliteQueryTakeFirstSync(
        db,
        sql
          .selectFrom("pqc_push_objects")
          .select(sql.fn.countAll<number>().as("count"))
          .where("recipient_id", "=", value.recipientId),
      )!.count;
      if (total >= MAX_OBJECTS || device >= MAX_DEVICE_OBJECTS) {
        throw new Error("push reference store capacity exceeded");
      }
      executeSqliteQuerySync(
        db,
        sql.insertInto("pqc_push_objects").values({
          object_id: descriptor.object_id,
          token_hash: hashPushReferenceToken(descriptor.token),
          recipient_id: value.recipientId,
          payload: value.payload,
          envelope_json: JSON.stringify(value.envelope),
          expires_at_ms: expiresAtMs,
        }),
      );
    });
    return descriptor;
  }
  redeem(
    descriptor: PushReferenceDescriptor,
    recipientId: string,
    nowMs = Date.now(),
  ): StoredSignedPush {
    const value = this.access(descriptor, recipientId, nowMs, "read");
    if (!value) {
      throw new Error("push reference unavailable");
    }
    return value;
  }
  acknowledge(descriptor: PushReferenceDescriptor, recipientId: string, nowMs = Date.now()): void {
    this.access(descriptor, recipientId, nowMs, "acknowledge");
  }
  /** Only call after server-side proof and current pairing authorization. Never accepts a request recipient. */
  listForAuthenticatedRecipient(
    recipientId: string,
    options: { nowMs?: number; after?: { objectId: string; expiresAtMs: number } } = {},
  ): {
    items: Array<{ object_id: string; expires_at_ms: number; value: StoredSignedPush }>;
    next?: { objectId: string; expiresAtMs: number };
  } {
    const nowMs = options.nowMs ?? Date.now();
    const after = options.after;
    if (
      !recipientId ||
      Buffer.byteLength(recipientId, "utf8") > 256 ||
      !Number.isSafeInteger(nowMs) ||
      nowMs < 0 ||
      (after &&
        (!Number.isSafeInteger(after.expiresAtMs) ||
          after.expiresAtMs < 0 ||
          !/^[0-9a-f-]{36}$/.test(after.objectId)))
    ) {
      throw new Error("invalid push recovery request");
    }
    return transaction(this.options, (db, sql) => {
      let query = sql
        .selectFrom("pqc_push_objects")
        .selectAll()
        .where("recipient_id", "=", recipientId)
        .where("expires_at_ms", ">", nowMs);
      if (after) {
        query = query.where((eb) =>
          eb.or([
            eb("expires_at_ms", ">", after.expiresAtMs),
            eb.and([
              eb("expires_at_ms", "=", after.expiresAtMs),
              eb("object_id", ">", after.objectId),
            ]),
          ]),
        );
      }
      const rows = executeSqliteQuerySync(
        db,
        query
          .orderBy("expires_at_ms")
          .orderBy("object_id")
          .limit(MAX_PUSH_RECOVERY_PAGE_ITEMS + 1),
      ).rows;
      const items: Array<{ object_id: string; expires_at_ms: number; value: StoredSignedPush }> =
        [];
      // Reserve wrapper/cursor overhead; JSON escaping counts toward the wire budget.
      let remaining = MAX_PUSH_RECOVERY_PAGE_BYTES - 1024;
      for (const row of rows.slice(0, MAX_PUSH_RECOVERY_PAGE_ITEMS)) {
        const item = {
          object_id: row.object_id,
          expires_at_ms: row.expires_at_ms,
          value: {
            payload: row.payload,
            envelope: JSON.parse(row.envelope_json),
            recipientId: row.recipient_id,
          },
        };
        const bytes = Buffer.byteLength(JSON.stringify(item), "utf8") + 1;
        if (bytes > remaining) {
          if (items.length === 0) {
            throw new Error("push recovery object exceeds response budget");
          }
          break;
        }
        remaining -= bytes;
        items.push(item);
      }
      const last = items.at(-1);
      return {
        items,
        ...(last && items.length < rows.length
          ? {
              next: { objectId: last.object_id, expiresAtMs: last.expires_at_ms },
            }
          : {}),
      };
    });
  }
  /** Caller must reauthorize current paired proof before each ACK, including retries. */
  acknowledgeForAuthenticatedRecipient(
    reference: Omit<PushReferenceDescriptor, "token">,
    recipientId: string,
    nowMs = Date.now(),
  ): void {
    this.access(reference, recipientId, nowMs, "recovery-acknowledge");
  }
  private access(
    descriptor: PushReferenceDescriptor | Omit<PushReferenceDescriptor, "token">,
    recipientId: string,
    nowMs: number,
    mode: "read" | "acknowledge" | "recovery-acknowledge",
  ): StoredSignedPush | undefined {
    if (
      descriptor.version !== 1 ||
      typeof descriptor.object_id !== "string" ||
      descriptor.object_id.length === 0 ||
      descriptor.object_id.length > 64 ||
      !Number.isSafeInteger(descriptor.expires_at_ms) ||
      !Number.isSafeInteger(nowMs) ||
      nowMs < 0
    ) {
      throw new Error("invalid push reference");
    }
    return transaction(this.options, (db, sql) => {
      const row = executeSqliteQueryTakeFirstSync(
        db,
        sql
          .selectFrom("pqc_push_objects")
          .selectAll()
          .where("object_id", "=", descriptor.object_id),
      );
      const receipt =
        mode !== "read" && !row
          ? executeSqliteQueryTakeFirstSync(
              db,
              sql
                .selectFrom("pqc_push_acknowledgements")
                .selectAll()
                .where("object_id", "=", descriptor.object_id),
            )
          : undefined;
      const binding = row ?? receipt;
      // Hash every well-formed token even for a missing id. Never reveal which
      // binding failed, and never consume another device's object on failure.
      const tokenMatches =
        mode === "recovery-acknowledge" ||
        ("token" in descriptor &&
          matchesPushReferenceToken(binding?.token_hash ?? "0".repeat(64), descriptor.token));
      if (
        !binding ||
        !tokenMatches ||
        binding.recipient_id !== recipientId ||
        binding.expires_at_ms !== descriptor.expires_at_ms ||
        nowMs >= binding.expires_at_ms
      ) {
        throw new Error("push reference unavailable");
      }
      // A read response can be lost before the receiver commits its inbox.
      // Keep the capability retryable until authenticated acknowledgement or expiry.
      if (mode !== "read") {
        if (row) {
          executeSqliteQuerySync(
            db,
            sql.deleteFrom("pqc_push_acknowledgements").where("expires_at_ms", "<=", nowMs),
          );
          const count = executeSqliteQueryTakeFirstSync(
            db,
            sql
              .selectFrom("pqc_push_acknowledgements")
              .select(sql.fn.countAll<number>().as("count")),
          )!.count;
          if (count >= MAX_NONCES) {
            throw new Error("push acknowledgement capacity exceeded");
          }
          // Retain only capability hashes until the original expiry. Lost ACK
          // responses can then be retried without releasing the body again.
          executeSqliteQuerySync(
            db,
            sql.insertInto("pqc_push_acknowledgements").values({
              object_id: descriptor.object_id,
              token_hash: row.token_hash,
              recipient_id: row.recipient_id,
              expires_at_ms: row.expires_at_ms,
            }),
          );
        }
        executeSqliteQuerySync(
          db,
          sql.deleteFrom("pqc_push_objects").where("object_id", "=", descriptor.object_id),
        );
      }
      if (!row) {
        // Only acknowledgement can reach a tombstone, whose body is erased.
        return undefined;
      }
      return {
        payload: row.payload,
        envelope: JSON.parse(row.envelope_json),
        recipientId: row.recipient_id,
      };
    });
  }
  discard(descriptor: PushReferenceDescriptor): void {
    transaction(this.options, (db, sql) => {
      executeSqliteQuerySync(
        db,
        sql.deleteFrom("pqc_push_objects").where("object_id", "=", descriptor.object_id),
      );
    });
  }
}

/** Subscription ownership is learned only from an authenticated device session. */
export function bindPushSubscriptionInTransaction(
  db: DatabaseSync,
  subscriptionId: string,
  deviceId: string,
): void {
  ensurePqcPushStateSchema(db);
  const sql = getNodeSqliteKysely<OpenClawStateDb>(db);
  const row = executeSqliteQueryTakeFirstSync(
    db,
    sql
      .selectFrom("pqc_push_bindings")
      .select("device_id")
      .where("subscription_id", "=", subscriptionId),
  );
  if (row && row.device_id !== deviceId) {
    throw new Error("push subscription belongs to another device");
  }
  if (!row) {
    const count = executeSqliteQueryTakeFirstSync(
      db,
      sql.selectFrom("pqc_push_bindings").select(sql.fn.countAll<number>().as("count")),
    )!.count;
    if (count >= MAX_PEERS) {
      throw new Error("push binding capacity exceeded");
    }
    executeSqliteQuerySync(
      db,
      sql
        .insertInto("pqc_push_bindings")
        .values({ subscription_id: subscriptionId, device_id: deviceId }),
    );
  }
}

export function pushSubscriptionRecipient(
  subscriptionId: string,
  options: OpenClawStateDatabaseOptions = {},
): string {
  const { db } = state(options);
  const sql = getNodeSqliteKysely<OpenClawStateDb>(db);
  const row = executeSqliteQueryTakeFirstSync(
    db,
    sql
      .selectFrom("pqc_push_bindings")
      .select("device_id")
      .where("subscription_id", "=", subscriptionId),
  );
  if (!row) {
    throw new Error("push subscription must be re-registered by its authenticated device");
  }
  return row.device_id;
}

export function allowPushRedemption(
  deviceId: string,
  options: OpenClawStateDatabaseOptions = {},
  nowMs = Date.now(),
  operation: "read" | "acknowledge" = "read",
): boolean {
  const budgetId = JSON.stringify([deviceId, operation]);
  return transaction(options, (db, sql) => {
    executeSqliteQuerySync(
      db,
      sql.deleteFrom("pqc_push_attempts").where("window_start_ms", "<=", nowMs - 60_000),
    );
    const row = executeSqliteQueryTakeFirstSync(
      db,
      sql.selectFrom("pqc_push_attempts").selectAll().where("device_id", "=", budgetId),
    );
    if (row && row.attempts >= 60) {
      return false;
    }
    if (!row) {
      const count = executeSqliteQueryTakeFirstSync(
        db,
        sql.selectFrom("pqc_push_attempts").select(sql.fn.countAll<number>().as("count")),
      )!.count;
      if (count >= MAX_PEERS) {
        return false;
      }
    }
    executeSqliteQuerySync(
      db,
      sql
        .insertInto("pqc_push_attempts")
        .values({
          device_id: budgetId,
          window_start_ms: row?.window_start_ms ?? nowMs,
          attempts: (row?.attempts ?? 0) + 1,
        })
        .onConflict((oc) =>
          oc.column("device_id").doUpdateSet({ attempts: (row?.attempts ?? 0) + 1 }),
        ),
    );
    return true;
  });
}
