import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { PushDualEnvelope } from "../security/push-dual-signature.js";
import { closeOpenClawStateDatabase } from "../state/openclaw-state-db.js";
import { SqlitePushReferenceStore } from "./pqc-push-state.js";

let directory: string;
let store: SqlitePushReferenceStore;
beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), "pqc-recovery-"));
  store = new SqlitePushReferenceStore({ env: { ...process.env, OPENCLAW_STATE_DIR: directory } });
});
afterEach(() => {
  closeOpenClawStateDatabase();
  rmSync(directory, { recursive: true, force: true });
});
const create = (recipientId = "alice", payload = "private body", nowMs = 1000, ttlMs = 1000) =>
  store.create(
    { payload, recipientId, envelope: { recipient_id: recipientId } as PushDualEnvelope },
    { nowMs, ttlMs },
  );
const recoveryRef = (descriptor: ReturnType<typeof create>) => ({
  version: descriptor.version,
  object_id: descriptor.object_id,
  expires_at_ms: descriptor.expires_at_ms,
});

describe("bounded durable push recovery storage (caller authorization required)", () => {
  it("discovers only the recipient's live objects without token hashes or consuming them", () => {
    const descriptor = create();
    create("bob", "other private body");
    const page = store.listForAuthenticatedRecipient("alice", { nowMs: 1000 });
    expect(page.items.map((x) => x.object_id)).toEqual([descriptor.object_id]);
    expect(page.items[0]?.value.payload).toBe("private body");
    expect(JSON.stringify(page)).not.toContain("token");
    expect(store.redeem(descriptor, "alice", 1000).payload).toBe("private body");
    expect(store.listForAuthenticatedRecipient("alice", { nowMs: 1000 })).toEqual(page);
  });
  it("retains unacknowledged objects across database reopen", () => {
    const descriptor = create();
    closeOpenClawStateDatabase();
    expect(store.listForAuthenticatedRecipient("alice", { nowMs: 1000 }).items[0]?.object_id).toBe(
      descriptor.object_id,
    );
  });
  it("excludes equality at expiry and does not renew TTL", () => {
    const descriptor = create();
    expect(
      store.listForAuthenticatedRecipient("alice", { nowMs: 1999 }).items[0]?.expires_at_ms,
    ).toBe(2000);
    expect(store.listForAuthenticatedRecipient("alice", { nowMs: 2000 }).items).toEqual([]);
    expect(() =>
      store.acknowledgeForAuthenticatedRecipient(recoveryRef(descriptor), "alice", 2000),
    ).toThrow("unavailable");
  });
  it("binds recovered acknowledgement to owner and exact original expiry", () => {
    const descriptor = create();
    const ref = recoveryRef(descriptor);
    expect(() => store.acknowledgeForAuthenticatedRecipient(ref, "bob", 1000)).toThrow(
      "unavailable",
    );
    expect(() =>
      store.acknowledgeForAuthenticatedRecipient({ ...ref, expires_at_ms: 2001 }, "alice", 1000),
    ).toThrow("unavailable");
    expect(store.listForAuthenticatedRecipient("alice", { nowMs: 1000 }).items).toHaveLength(1);
    store.acknowledgeForAuthenticatedRecipient(ref, "alice", 1000);
    expect(store.listForAuthenticatedRecipient("alice", { nowMs: 1000 }).items).toEqual([]);
  });
  it("retries lost recovery ACK responses after reopen and preserves legacy token ACKs", () => {
    const descriptor = create();
    const ref = recoveryRef(descriptor);
    store.acknowledgeForAuthenticatedRecipient(ref, "alice", 1000);
    closeOpenClawStateDatabase();
    store.acknowledgeForAuthenticatedRecipient(ref, "alice", 1001);
    store.acknowledge(descriptor, "alice", 1001);
    expect(() =>
      store.acknowledge({ ...descriptor, token: "A".repeat(43) }, "alice", 1001),
    ).toThrow("unavailable");
    expect(() => store.redeem(descriptor, "alice", 1001)).toThrow("unavailable");
  });
  it("accepts recovery ACK after a legacy ACK without returning deleted plaintext", () => {
    const descriptor = create();
    store.acknowledge(descriptor, "alice", 1000);
    store.acknowledgeForAuthenticatedRecipient(recoveryRef(descriptor), "alice", 1001);
    expect(store.listForAuthenticatedRecipient("alice", { nowMs: 1001 }).items).toEqual([]);
  });
  it("pages equal-expiry rows without duplication or loss while acknowledged rows are removed", () => {
    const expected = Array.from({ length: 35 }, () => create())
      .map((d) => d.object_id)
      .toSorted();
    const ids: string[] = [];
    let after: { objectId: string; expiresAtMs: number } | undefined;
    do {
      const page = store.listForAuthenticatedRecipient("alice", { nowMs: 1000, after });
      expect(page.items.length).toBeLessThanOrEqual(16);
      ids.push(...page.items.map((x) => x.object_id));
      for (const item of page.items)
        {store.acknowledgeForAuthenticatedRecipient(
          { version: 1, object_id: item.object_id, expires_at_ms: item.expires_at_ms },
          "alice",
          1000,
        );}
      after = page.next;
    } while (after);
    expect(ids).toEqual(expected);
  });
  it("counts JSON escaping against the response budget and leaves remaining rows discoverable", () => {
    for (let i = 0; i < 6; i++) {create("alice", "\u0001".repeat(65536));}
    const first = store.listForAuthenticatedRecipient("alice", { nowMs: 1000 });
    expect(Buffer.byteLength(JSON.stringify(first), "utf8")).toBeLessThanOrEqual(2 * 1024 * 1024);
    expect(first.items).toHaveLength(5);
    expect(first.next).toBeDefined();
    const next = store.listForAuthenticatedRecipient("alice", { nowMs: 1000, after: first.next });
    expect(next.items).toHaveLength(1);
    expect(first.items.map((x) => x.object_id)).not.toContain(next.items[0]?.object_id);
  });
  it("scans the full maximum-size device queue within the unchanged read budget", () => {
    for (let i = 0; i < 100; i++) {
      store.create(
        {
          recipientId: "alice",
          payload: "\u0001".repeat(65536),
          envelope: {
            recipient_id: "alice",
            padding: "p".repeat(16300),
          } as unknown as PushDualEnvelope,
        },
        { nowMs: 1000, ttlMs: 1000 },
      );
    }
    let after: { objectId: string; expiresAtMs: number } | undefined;
    const seen = new Set<string>();
    let pages = 0;
    do {
      const page = store.listForAuthenticatedRecipient("alice", { nowMs: 1000, after });
      expect(Buffer.byteLength(JSON.stringify(page), "utf8")).toBeLessThanOrEqual(2 * 1024 * 1024);
      for (const row of page.items) {
        expect(seen.has(row.object_id)).toBe(false);
        seen.add(row.object_id);
      }
      after = page.next;
      pages++;
    } while (after);
    expect(seen.size).toBe(100);
    expect(pages).toBeLessThanOrEqual(20);
    expect(pages).toBeLessThan(60);
  });
  it.each([-1, Number.NaN, Infinity, 1.5])("rejects an invalid clock %s", (nowMs) => {
    expect(() => store.listForAuthenticatedRecipient("alice", { nowMs })).toThrow("invalid");
  });
  it("rejects invalid cursors, empty owners and unknown recovery acknowledgements", () => {
    expect(() => store.listForAuthenticatedRecipient("", { nowMs: 1000 })).toThrow("invalid");
    expect(() =>
      store.listForAuthenticatedRecipient("alice", {
        nowMs: 1000,
        after: { objectId: "bad", expiresAtMs: 2000 },
      }),
    ).toThrow("invalid");
    expect(() =>
      store.acknowledgeForAuthenticatedRecipient(
        { version: 1, object_id: "missing", expires_at_ms: 2000 },
        "alice",
        1000,
      ),
    ).toThrow("unavailable");
  });
});
