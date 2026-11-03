import { randomUUID } from "node:crypto";
import type { DatabaseSync } from "node:sqlite";
import type { Kysely } from "kysely";
import type { StoredSignedPush } from "../security/push-reference.js";
import {
  MAX_PUSH_RECOVERY_PAGE_BYTES,
  MAX_PUSH_RECOVERY_PAGE_ITEMS,
} from "../shared/push-recovery.js";
import type { DB } from "../state/openclaw-state-db.generated.js";
import { executeSqliteQuerySync, executeSqliteQueryTakeFirstSync } from "./kysely-sync.js";

export type PushRecoverySnapshotCursor = { snapshotId: string; offset: number };
type SnapshotReference = { objectId: string; expiresAtMs: number };
const SNAPSHOT_TTL_MS = 60_000;
const MAX_SNAPSHOTS = 128;
const MAX_DEVICE_SNAPSHOTS = 4;
const MAX_SNAPSHOT_OBJECTS = 100;
const MAX_SNAPSHOT_JSON_BYTES = 32768;
const uuid = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;

/** Caller owns one immediate transaction and has verified the current recipient/token binding. */
export function readPushRecoverySnapshotPage(
  db: DatabaseSync,
  sql: Kysely<DB>,
  recipientId: string,
  tokenSha256: string,
  options: { nowMs?: number; after?: PushRecoverySnapshotCursor } = {},
): {
  snapshotId: string;
  items: Array<{ object_id: string; expires_at_ms: number; value: StoredSignedPush }>;
  next?: PushRecoverySnapshotCursor;
} {
  const nowMs = options.nowMs ?? Date.now();
  const after = options.after;
  if (
    !db.isTransaction ||
    !recipientId ||
    Buffer.byteLength(recipientId) > 256 ||
    !/^[0-9a-f]{64}$/.test(tokenSha256) ||
    !Number.isSafeInteger(nowMs) ||
    !Number.isSafeInteger(nowMs + SNAPSHOT_TTL_MS) ||
    nowMs < 0 ||
    (after &&
      (!uuid.test(after.snapshotId) ||
        !Number.isSafeInteger(after.offset) ||
        after.offset < 0 ||
        after.offset > MAX_SNAPSHOT_OBJECTS))
  ) {
    throw new Error("push recovery snapshot unavailable");
  }
  executeSqliteQuerySync(
    db,
    sql.deleteFrom("pqc_push_recovery_snapshots").where("expires_at_ms", "<=", nowMs),
  );
  let snapshotId: string;
  let references: SnapshotReference[];
  if (after) {
    const row = executeSqliteQueryTakeFirstSync(
      db,
      sql
        .selectFrom("pqc_push_recovery_snapshots")
        .selectAll()
        .where("snapshot_id", "=", after.snapshotId)
        .where("recipient_id", "=", recipientId)
        .where("token_sha256", "=", tokenSha256)
        .where("expires_at_ms", ">", nowMs),
    );
    if (!row || Buffer.byteLength(row.objects_json) > MAX_SNAPSHOT_JSON_BYTES) {
      throw new Error("push recovery snapshot unavailable");
    }
    references = JSON.parse(row.objects_json) as SnapshotReference[];
    snapshotId = row.snapshot_id;
  } else {
    const rows = executeSqliteQuerySync(
      db,
      sql
        .selectFrom("pqc_push_objects")
        .selectAll()
        .where("recipient_id", "=", recipientId)
        .where("expires_at_ms", ">", nowMs)
        .orderBy("expires_at_ms")
        .orderBy("object_id")
        .limit(MAX_SNAPSHOT_OBJECTS + 1),
    ).rows;
    // Old/non-atomic writers must drain before enabling the new guarantee. Do not
    // silently omit their objects or infer an ordering from their expiry times.
    if (rows.length > MAX_SNAPSHOT_OBJECTS || rows.some((row) => row.publication_version !== 1)) {
      throw new Error("push recovery awaits atomic publication");
    }
    snapshotId = randomUUID();
    references = rows.map((row) => ({ objectId: row.object_id, expiresAtMs: row.expires_at_ms }));
    if (references.length === 0) {
      return { snapshotId, items: [] };
    }
    executeSqliteQuerySync(
      db,
      sql
        .deleteFrom("pqc_push_recovery_snapshots")
        .where("recipient_id", "=", recipientId)
        .where("token_sha256", "!=", tokenSha256),
    );
    const total = executeSqliteQueryTakeFirstSync(
      db,
      sql.selectFrom("pqc_push_recovery_snapshots").select(sql.fn.countAll<number>().as("count")),
    )!.count;
    const device = executeSqliteQueryTakeFirstSync(
      db,
      sql
        .selectFrom("pqc_push_recovery_snapshots")
        .select(sql.fn.countAll<number>().as("count"))
        .where("recipient_id", "=", recipientId),
    )!.count;
    const encoded = JSON.stringify(references);
    if (
      total >= MAX_SNAPSHOTS ||
      device >= MAX_DEVICE_SNAPSHOTS ||
      Buffer.byteLength(encoded) > MAX_SNAPSHOT_JSON_BYTES
    ) {
      throw new Error("push recovery snapshot capacity exceeded");
    }
    executeSqliteQuerySync(
      db,
      sql.insertInto("pqc_push_recovery_snapshots").values({
        snapshot_id: snapshotId,
        recipient_id: recipientId,
        token_sha256: tokenSha256,
        expires_at_ms: nowMs + SNAPSHOT_TTL_MS,
        objects_json: encoded,
      }),
    );
  }
  if (
    !Array.isArray(references) ||
    references.length > MAX_SNAPSHOT_OBJECTS ||
    references.some(
      (row) => !row || !uuid.test(row.objectId) || !Number.isSafeInteger(row.expiresAtMs),
    ) ||
    (after && after.offset > references.length)
  ) {
    throw new Error("push recovery snapshot unavailable");
  }
  const items: Array<{ object_id: string; expires_at_ms: number; value: StoredSignedPush }> = [];
  let remaining = MAX_PUSH_RECOVERY_PAGE_BYTES - 1024;
  let offset = after?.offset ?? 0;
  for (; offset < references.length; offset++) {
    const reference = references[offset]!;
    const row = executeSqliteQueryTakeFirstSync(
      db,
      sql
        .selectFrom("pqc_push_objects")
        .selectAll()
        .where("object_id", "=", reference.objectId)
        .where("recipient_id", "=", recipientId)
        .where("expires_at_ms", "=", reference.expiresAtMs)
        .where("expires_at_ms", ">", nowMs)
        .where("publication_version", "=", 1),
    );
    if (!row) {
      continue;
    }
    const item = {
      object_id: row.object_id,
      expires_at_ms: row.expires_at_ms,
      value: {
        payload: row.payload,
        recipientId: row.recipient_id,
        envelope: JSON.parse(row.envelope_json),
      } as StoredSignedPush,
    };
    const bytes = Buffer.byteLength(JSON.stringify(item)) + 1;
    if (bytes > remaining || items.length === MAX_PUSH_RECOVERY_PAGE_ITEMS) {
      if (items.length === 0) {
        throw new Error("push recovery object exceeds response budget");
      }
      break;
    }
    remaining -= bytes;
    items.push(item);
  }
  return {
    snapshotId,
    items,
    ...(offset < references.length ? { next: { snapshotId, offset } } : {}),
  };
}
