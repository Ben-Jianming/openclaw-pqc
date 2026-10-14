import { createHash } from "node:crypto";
import {
  encodePushSigningTranscript,
  verifyPushPayloadDual,
  type PushDualEnvelope,
  type VerifyPushPayloadDualOptions,
} from "../security/push-dual-signature.js";
import type {
  OpenClawStateDatabase,
  OpenClawStateDatabaseOptions,
} from "../state/openclaw-state-db-contract.js";
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
import { SqlitePushReplayGuard } from "./pqc-push-state.js";

type PushCompletionValue =
  | null
  | boolean
  | number
  | string
  | PushCompletionValue[]
  | { [key: string]: PushCompletionValue };
type ConsumePushOptions = Omit<
  VerifyPushPayloadDualOptions,
  "replayGuard" | "expectedRecipientId"
> & {
  expectedRecipientId: string;
  state?: OpenClawStateDatabaseOptions;
};

/**
 * Commit a local SQLite effect, replay decision and completion together.
 * The callback must use this database synchronously; external effects need
 * their own idempotency protocol and cannot be made atomic by this helper.
 */
export function consumePushPayloadDual<T extends PushCompletionValue>(
  options: ConsumePushOptions,
  apply: (database: OpenClawStateDatabase) => T,
): { status: "fresh_completed" | "already_completed"; value: T } {
  if (!options.expectedRecipientId) {
    throw new Error("expectedRecipientId is required for push consumption");
  }
  // Snapshot caller input and finish cryptographic work before taking the lock.
  const envelope = JSON.parse(
    typeof options.envelope === "string" ? options.envelope : JSON.stringify(options.envelope),
  ) as PushDualEnvelope;
  const nowMs = options.nowMs ?? Date.now();
  verifyPushPayloadDual({
    payload: options.payload,
    envelope,
    registry: options.registry,
    expectedRecipientId: options.expectedRecipientId,
    nowMs,
    maxAgeMs: options.maxAgeMs,
  });
  const transcriptHash = createHash("sha256")
    .update(encodePushSigningTranscript(envelope))
    .digest("hex");
  const database = openOpenClawStateDatabase(options.state);
  ensurePqcPushStateSchema(database.db);
  const guard = new SqlitePushReplayGuard({ database }, () => nowMs);
  return runOpenClawStateWriteTransaction(
    ({ db }) => {
      const sql = getNodeSqliteKysely<OpenClawStateDb>(db);
      const key = {
        sender_id: envelope.sender_id,
        recipient_id: envelope.recipient_id,
        nonce: envelope.nonce,
      };
      const previous = executeSqliteQueryTakeFirstSync(
        db,
        sql
          .selectFrom("pqc_push_completions")
          .selectAll()
          .where("sender_id", "=", key.sender_id)
          .where("recipient_id", "=", key.recipient_id)
          .where("nonce", "=", key.nonce),
      );
      if (previous) {
        if (
          previous.transcript_hash !== transcriptHash ||
          previous.expires_at_ms <= nowMs ||
          previous.state !== "completed"
        ) {
          throw new Error("push completion binding failed");
        }
        return { status: "already_completed", value: JSON.parse(previous.result_json) as T };
      }
      executeSqliteQuerySync(
        db,
        sql.deleteFrom("pqc_push_completions").where("expires_at_ms", "<=", nowMs),
      );
      const count = executeSqliteQueryTakeFirstSync(
        db,
        sql.selectFrom("pqc_push_completions").select(sql.fn.countAll<number>().as("count")),
      )!.count;
      if (count >= 50_000) {
        throw new Error("push completion capacity exceeded");
      }
      // No independent replay commit: callback failure or process death rolls
      // back replay rows together with the local effect.
      if (
        !guard.acceptInTransaction(db, {
          senderId: envelope.sender_id,
          recipientId: envelope.recipient_id,
          sequence: envelope.sequence,
          nonce: envelope.nonce,
          createdAtMs: envelope.created_at_ms,
        })
      ) {
        throw new Error("replayed or out-of-order envelope");
      }
      const value = apply(database);
      if (value && typeof (value as { then?: unknown }).then === "function") {
        throw new Error("push consumption callback must be synchronous");
      }
      const resultJson = JSON.stringify(value, (_key, item: unknown) => {
        if (
          (typeof item === "number" && !Number.isFinite(item)) ||
          ["undefined", "function", "symbol"].includes(typeof item)
        ) {
          throw new Error("push completion result must contain JSON values");
        }
        return item;
      });
      if (resultJson === undefined || Buffer.byteLength(resultJson, "utf8") > 64 * 1024) {
        throw new Error("push completion result must be bounded JSON");
      }
      executeSqliteQuerySync(
        db,
        sql.insertInto("pqc_push_completions").values({
          ...key,
          transcript_hash: transcriptHash,
          result_json: resultJson,
          state: "completed",
          reference_id: null,
          expires_at_ms: envelope.created_at_ms + Math.min(options.maxAgeMs ?? 300_000, 300_000),
        }),
      );
      return { status: "fresh_completed", value: JSON.parse(resultJson) as T };
    },
    { database },
  );
}
