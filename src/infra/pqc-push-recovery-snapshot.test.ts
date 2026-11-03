import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { PushDualEnvelope } from "../security/push-dual-signature.js";
import { MAX_PUSH_RECOVERY_PAGE_BYTES } from "../shared/push-recovery.js";
import { ensurePqcPushStateSchema } from "../state/openclaw-state-db-schema-additive.js";
import { closeOpenClawStateDatabase } from "../state/openclaw-state-db.js";
import { nextPushSequence, SqlitePushReferenceStore } from "./pqc-push-state.js";

let directory: string;
let env: NodeJS.ProcessEnv;
let store: SqlitePushReferenceStore;
const binding = "a".repeat(64);
beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), "pqc-snapshot-"));
  env = { ...process.env, OPENCLAW_STATE_DIR: directory };
  store = new SqlitePushReferenceStore({ env });
});
afterEach(() => {
  closeOpenClawStateDatabase();
  rmSync(directory, { recursive: true, force: true });
});
function publish(nowMs = 1000, ttlMs = 300000, payload = "private") {
  return store.createWithSignature(
    (stateEnv) => ({
      payload,
      recipientId: "alice",
      envelope: {
        sender_id: "gateway",
        recipient_id: "alice",
        sequence: nextPushSequence("gateway", "alice", { env: stateEnv }),
      } as PushDualEnvelope,
    }),
    { nowMs, ttlMs },
  );
}
const page = (
  nowMs = 1000,
  after?: { snapshotId: string; offset: number },
  owner = "alice",
  token = binding,
) => store.listSnapshotForAuthenticatedRecipient(owner, token, { nowMs, after });

describe("immutable authorized recovery snapshot membership", () => {
  it("adds snapshot/publication metadata without replacing old rows or resetting their sequence", () => {
    const database = new DatabaseSync(join(directory, "legacy.sqlite"));
    try {
      database.exec(`CREATE TABLE pqc_push_sequences(sender_id TEXT NOT NULL,recipient_id TEXT NOT NULL,sequence INTEGER NOT NULL,PRIMARY KEY(sender_id,recipient_id)) STRICT;
        CREATE TABLE pqc_push_objects(object_id TEXT PRIMARY KEY,token_hash TEXT NOT NULL,recipient_id TEXT NOT NULL,payload TEXT NOT NULL,envelope_json TEXT NOT NULL,expires_at_ms INTEGER NOT NULL) STRICT;
        INSERT INTO pqc_push_sequences VALUES('gateway','alice',42);
        INSERT INTO pqc_push_objects VALUES('legacy','fixture','alice','retained','{}',301000);`);
      ensurePqcPushStateSchema(database);
      expect(
        database.prepare("SELECT sequence,published_sequence FROM pqc_push_sequences").get(),
      ).toMatchObject({ sequence: 42, published_sequence: 0 });
      expect(
        database.prepare("SELECT payload,publication_version FROM pqc_push_objects").get(),
      ).toMatchObject({ payload: "retained", publication_version: 0 });
      expect(
        database.prepare("SELECT COUNT(*) AS count FROM pqc_push_recovery_snapshots").get(),
      ).toMatchObject({ count: 0 });
      ensurePqcPushStateSchema(database);
      expect(database.prepare("SELECT sequence FROM pqc_push_sequences").get()).toMatchObject({
        sequence: 42,
      });
    } finally {
      database.close();
    }
  });
  it("bounds global snapshots across recipients without consuming their messages", () => {
    for (let recipient = 0; recipient < 33; recipient++) {
      const recipientId = "recipient-" + recipient;
      store.createWithSignature(
        (stateEnv) => ({
          payload: "private",
          recipientId,
          envelope: {
            sender_id: "gateway",
            recipient_id: recipientId,
            sequence: nextPushSequence("gateway", recipientId, { env: stateEnv }),
          } as PushDualEnvelope,
        }),
        { nowMs: 1000, ttlMs: 300000 },
      );
      if (recipient < 32) {
        for (let n = 0; n < 4; n++) {
          store.listSnapshotForAuthenticatedRecipient(recipientId, binding, { nowMs: 1000 });
        }
      }
    }
    expect(() =>
      store.listSnapshotForAuthenticatedRecipient("recipient-32", binding, { nowMs: 1000 }),
    ).toThrow("capacity");
    expect(
      store.listSnapshotForAuthenticatedRecipient("recipient-32", binding, { nowMs: 61000 }).items,
    ).toHaveLength(1);
  });
  it("keeps a later earlier-expiring insertion out of all current pages and includes it in the next scan", () => {
    const originals = Array.from({ length: 17 }, () => publish());
    const first = page();
    expect(first.items).toHaveLength(16);
    expect(first.next).toBeDefined();
    const late = publish(1001, 100000);
    const second = page(1001, first.next);
    expect(second.snapshotId).toBe(first.snapshotId);
    expect(new Set([...first.items, ...second.items].map((x) => x.object_id))).toEqual(
      new Set(originals.map((x) => x.object_id)),
    );
    expect(second.next).toBeUndefined();
    expect(page(1001).items.some((x) => x.object_id === late.object_id)).toBe(true);
  });
  it("rejects publishing a stale or repeated sequence after a later publication", () => {
    publish();
    publish();
    for (const sequence of [1, 2]) {
      expect(() =>
        store.createWithSignature(
          () => ({
            payload: "late",
            recipientId: "alice",
            envelope: { sender_id: "gateway", recipient_id: "alice", sequence } as PushDualEnvelope,
          }),
          { nowMs: 1001 },
        ),
      ).toThrow("publication sequence");
    }
    expect(page(1001).items).toHaveLength(2);
  });
  it("binds continuation to recipient and the actual session credential fingerprint", () => {
    Array.from({ length: 17 }, () => publish());
    const first = page();
    expect(() => page(1001, first.next, "bob")).toThrow("unavailable");
    expect(() => page(1001, first.next, "alice", "b".repeat(64))).toThrow("unavailable");
    expect(page(1001, first.next).items).toHaveLength(1);
  });
  it("preserves the exact snapshot and lost-page retry after database reopen", () => {
    Array.from({ length: 17 }, () => publish());
    const first = page();
    const second = page(1001, first.next);
    closeOpenClawStateDatabase();
    expect(page(1001, first.next)).toEqual(second);
  });
  it("does not return acknowledged objects and never extends their original expiry", () => {
    const originals = Array.from({ length: 17 }, () => publish());
    const first = page();
    const nextId = originals.find((x) => !first.items.some((y) => y.object_id === x.object_id))!;
    store.acknowledge(nextId, "alice", 1001);
    expect(page(1001, first.next).items).toEqual([]);
    expect(first.items.every((x) => x.expires_at_ms === 301000)).toBe(true);
  });
  it("expires the snapshot at equality without consuming the still-live objects", () => {
    Array.from({ length: 17 }, () => publish());
    const first = page();
    expect(() => page(61000, first.next)).toThrow("unavailable");
    expect(page(61000).items).toHaveLength(16);
  });
  it("bounds concurrent device snapshots and reclaims expired membership", () => {
    publish();
    for (let n = 0; n < 4; n++) {
      page();
    }
    expect(() => page()).toThrow("capacity");
    expect(page(61000).items).toHaveLength(1);
  });
  it("requires legacy/non-atomic objects to drain rather than silently omitting them", () => {
    store.create(
      {
        payload: "legacy",
        recipientId: "alice",
        envelope: { recipient_id: "alice" } as PushDualEnvelope,
      },
      { nowMs: 1000, ttlMs: 1000 },
    );
    expect(() => page()).toThrow("atomic publication");
    expect(page(2000).items).toEqual([]);
  });
  it("rejects forged and out-of-range continuation offsets", () => {
    expect(() => page(Number.MAX_SAFE_INTEGER)).toThrow("unavailable");
    publish();
    const first = page();
    expect(() => page(1001, { snapshotId: first.snapshotId, offset: 2 })).toThrow("unavailable");
    expect(() => page(1001, { snapshotId: first.snapshotId, offset: -1 })).toThrow("unavailable");
    expect(() => page(1001, { snapshotId: "not-a-snapshot", offset: 0 })).toThrow("unavailable");
  });
  it("scans100 maximally escaped payloads within the existing byte/page budgets", () => {
    for (let n = 0; n < 100; n++) {
      publish(1000, 300000, "\u0000".repeat(65536));
    }
    let current = page();
    const ids = new Set<string>();
    let pages = 0;
    while (true) {
      pages++;
      expect(Buffer.byteLength(JSON.stringify(current))).toBeLessThanOrEqual(
        MAX_PUSH_RECOVERY_PAGE_BYTES,
      );
      for (const item of current.items) {
        expect(ids.has(item.object_id)).toBe(false);
        ids.add(item.object_id);
      }
      if (!current.next) {
        break;
      }
      current = page(1001, current.next);
    }
    expect(ids.size).toBe(100);
    expect(pages).toBeLessThanOrEqual(32);
  });
});
