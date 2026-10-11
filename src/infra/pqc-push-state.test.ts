import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { PushDualEnvelope } from "../security/push-dual-signature.js";
import { closeOpenClawStateDatabase } from "../state/openclaw-state-db.js";
import {
  SqlitePushReferenceStore,
  SqlitePushReplayGuard,
  nextPushSequence,
  pushSubscriptionRecipient,
  allowPushRedemption,
} from "./pqc-push-state.js";
import { upsertWebPushSubscription, listWebPushSubscriptions } from "./push-web-store.js";

let directory: string;
let options: { env: NodeJS.ProcessEnv };
beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), "pqc-state-v2-"));
  options = { env: { ...process.env, OPENCLAW_STATE_DIR: directory } };
});
afterEach(() => {
  closeOpenClawStateDatabase();
  rmSync(directory, { recursive: true, force: true });
});
const envelope = { recipient_id: "alice" } as PushDualEnvelope;

function compete(operation: "sequence" | "redeem", descriptor?: unknown): Promise<unknown> {
  const source = new URL("./pqc-push-state.ts", import.meta.url).href;
  const code = `
    const {nextPushSequence, SqlitePushReferenceStore} = await import(${JSON.stringify(source)});
    let input = ''; for await (const part of process.stdin) input += part;
    const data = JSON.parse(input);
    if (data.operation === 'sequence') {
      process.stdout.write(JSON.stringify(Array.from({length: 20}, () => nextPushSequence('gateway', 'alice'))));
    } else {
      let accepted = false;
      try { new SqlitePushReferenceStore().redeem(data.descriptor, 'alice'); accepted = true; } catch {}
      process.stdout.write(JSON.stringify(accepted));
    }
  `;
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["--import", "tsx", "--input-type=module", "-e", code], {
      env: options.env,
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"],
    });
    let output = "";
    let diagnostics = "";
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error("state competitor timed out"));
    }, 20000);
    child.stdout.on("data", (part) => {
      output += String(part);
    });
    child.stderr.on("data", (part) => {
      diagnostics += String(part);
    });
    child.once("error", (error) => {
      clearTimeout(timer);
      reject(error);
    });
    child.once("close", (status) => {
      clearTimeout(timer);
      if (status !== 0) {
        reject(new Error(`state competitor failed: ${diagnostics}`));
        return;
      }
      try {
        resolve(JSON.parse(output));
      } catch (error) {
        reject(error instanceof Error ? error : new Error(String(error)));
      }
    });
    child.stdin.end(JSON.stringify({ operation, descriptor }));
  });
}

describe("durable push security state", () => {
  it("serializes counters and once-only redemption across independent processes", async () => {
    expect(nextPushSequence("gateway", "alice", options)).toBe(1);
    const descriptor = new SqlitePushReferenceStore(options).create({
      payload: "x",
      recipientId: "alice",
      envelope,
    });
    closeOpenClawStateDatabase();
    const sequences = (
      await Promise.all(Array.from({ length: 4 }, () => compete("sequence")))
    ).flat() as number[];
    expect(sequences.toSorted((a, b) => a - b)).toEqual(
      Array.from({ length: 80 }, (_, i) => i + 2),
    );
    const redemptions = await Promise.all(
      Array.from({ length: 4 }, () => compete("redeem", descriptor)),
    );
    expect(redemptions.filter(Boolean)).toHaveLength(1);
  }, 30000);
  it("preserves counters and replay decisions across a database close/reopen", () => {
    expect(nextPushSequence("gateway", "alice", options)).toBe(1);
    const now = Date.now();
    const input = {
      senderId: "gateway",
      recipientId: "alice",
      sequence: 1,
      nonce: "nonce",
      createdAtMs: now,
    };
    expect(new SqlitePushReplayGuard(options).accept(input)).toBe(true);
    closeOpenClawStateDatabase();
    expect(nextPushSequence("gateway", "alice", options)).toBe(2);
    const guard = new SqlitePushReplayGuard(options);
    expect(guard.accept(input)).toBe(false);
    expect(guard.accept({ ...input, sequence: 2 })).toBe(false);
    expect(guard.accept({ ...input, sequence: 2, nonce: "new" })).toBe(true);
    expect(guard.accept({ ...input, nonce: "reordered" })).toBe(false);
  });
  it("binds once-only redemption to recipient, token and expiry without burning valid content", () => {
    let store = new SqlitePushReferenceStore(options);
    const descriptor = store.create({ payload: "private body", recipientId: "alice", envelope });
    closeOpenClawStateDatabase();
    store = new SqlitePushReferenceStore(options);
    expect(() => store.redeem(descriptor, "bob")).toThrow("unavailable");
    expect(() =>
      store.redeem({ ...descriptor, expires_at_ms: descriptor.expires_at_ms + 1 }, "alice"),
    ).toThrow("unavailable");
    expect(() => store.redeem({ ...descriptor, token: "A".repeat(43) }, "alice")).toThrow(
      "unavailable",
    );
    expect(store.redeem(descriptor, "alice").payload).toBe("private body");
    expect(() => store.redeem(descriptor, "alice")).toThrow("unavailable");
  });
  it("rejects expiry equality and discards failed sends", () => {
    const store = new SqlitePushReferenceStore(options);
    const descriptor = store.create(
      { payload: "x", recipientId: "alice", envelope },
      { nowMs: 1000, ttlMs: 1 },
    );
    expect(() => store.redeem(descriptor, "alice", 1001)).toThrow("unavailable");
    store.discard(descriptor);
    expect(() => store.redeem(descriptor, "alice", 1000)).toThrow("unavailable");
    expect(() => store.create({ payload: "x", recipientId: "bob", envelope })).toThrow("invalid");
    expect(() =>
      store.create({ payload: "x", recipientId: "alice", envelope }, { ttlMs: 300001 }),
    ).toThrow("invalid");
  });
  it("limits outstanding objects per recipient", () => {
    const store = new SqlitePushReferenceStore(options);
    for (let i = 0; i < 100; i++) {
      store.create({ payload: "x", recipientId: "alice", envelope });
    }
    expect(() => store.create({ payload: "x", recipientId: "alice", envelope })).toThrow(
      "capacity",
    );
  });
  it("refuses cross-device subscription updates atomically", () => {
    const params = {
      endpointHash: "hash",
      endpoint: "https://push.example/a",
      keys: { p256dh: "key", auth: "auth" },
      candidateSubscriptionId: "subscription",
      nowMs: Date.now(),
      stateDir: directory,
    };
    upsertWebPushSubscription({ ...params, deviceId: "alice" });
    expect(() =>
      upsertWebPushSubscription({
        ...params,
        keys: { p256dh: "attacker", auth: "attacker" },
        deviceId: "bob",
      }),
    ).toThrow("another device");
    expect(listWebPushSubscriptions(directory)[0]?.keys.p256dh).toBe("key");
    expect(pushSubscriptionRecipient("subscription", options)).toBe("alice");
  });
  it("keeps per-device redemption limits across restart", () => {
    for (let i = 0; i < 60; i++) {
      expect(allowPushRedemption("alice", options, 1000)).toBe(true);
    }
    closeOpenClawStateDatabase();
    expect(allowPushRedemption("alice", options, 2000)).toBe(false);
    expect(allowPushRedemption("bob", options, 2000)).toBe(true);
    expect(allowPushRedemption("alice", options, 61000)).toBe(true);
  });
});
