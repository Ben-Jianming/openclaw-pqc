import { spawn } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import type { PushDualEnvelope } from "../security/push-dual-signature.js";
import { closeOpenClawStateDatabase } from "../state/openclaw-state-db.js";
import { nextPushSequence, SqlitePushReferenceStore } from "./pqc-push-state.js";

let directory: string;
let env: NodeJS.ProcessEnv;
let store: SqlitePushReferenceStore;
beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), "pqc-publication-"));
  env = { ...process.env, OPENCLAW_STATE_DIR: directory };
  store = new SqlitePushReferenceStore({ env });
});
afterEach(() => {
  closeOpenClawStateDatabase();
  rmSync(directory, { recursive: true, force: true });
});
const value = (sequence: number, payload = "private") => ({
  payload,
  recipientId: "alice",
  envelope: { sender_id: "gateway", recipient_id: "alice", sequence } as PushDualEnvelope,
});

describe("atomic sequence and signed-object publication", () => {
  it("serializes two publishing processes without duplicate or missing committed objects", async () => {
    store.listForAuthenticatedRecipient("alice");
    const source = new URL("./pqc-push-state.ts", import.meta.url).href;
    const code = `const {nextPushSequence,SqlitePushReferenceStore}=await import(${JSON.stringify(source)});
      const store=new SqlitePushReferenceStore();const out=[];
      for(let n=0;n<10;n++){
        let assigned;
        store.createWithSignature(env=>{
          const sequence=nextPushSequence('gateway','alice',{env});assigned=sequence;
          Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,5);
          return {payload:String(sequence),recipientId:'alice',envelope:{sender_id:'gateway',recipient_id:'alice',sequence}};
        });out.push(assigned);
      }process.stdout.write(JSON.stringify(out));`;
    const jobs = Array.from({ length: 2 }, () => {
      const child = spawn(
        process.execPath,
        ["--import", "tsx", "--input-type=module", "-e", code],
        {
          env,
          windowsHide: true,
          stdio: ["ignore", "pipe", "pipe"],
        },
      );
      let output = "";
      let diagnostics = "";
      child.stdout.on("data", (data) => {
        output += String(data);
      });
      child.stderr.on("data", (data) => {
        diagnostics += String(data);
      });
      const timeout = setTimeout(() => child.kill(), 20000);
      const done = new Promise<number[]>((resolve, reject) => {
        child.once("error", reject);
        child.once("exit", (exitCode) => {
          clearTimeout(timeout);
          if (exitCode !== 0) {
            reject(new Error("publisher process failed: " + diagnostics.slice(-1000)));
            return;
          }
          try {
            resolve(JSON.parse(output) as number[]);
          } catch (error) {
            reject(error instanceof Error ? error : new Error("invalid publisher response"));
          }
        });
      });
      return { child, done, timeout };
    });
    try {
      const committed = (await Promise.all(jobs.map((job) => job.done)))
        .flat()
        .toSorted((a, b) => a - b);
      expect(committed).toEqual(Array.from({ length: 20 }, (_, n) => n + 1));
      const first = store.listSnapshotForAuthenticatedRecipient("alice", "a".repeat(64));
      const second = store.listSnapshotForAuthenticatedRecipient("alice", "a".repeat(64), {
        after: first.next,
      });
      const visible = [...first.items, ...second.items]
        .map((item) => item.value.envelope.sequence)
        .toSorted((a, b) => a - b);
      expect(visible).toEqual(committed);
    } finally {
      for (const job of jobs) {
        clearTimeout(job.timeout);
        if (job.child.exitCode === null && job.child.signalCode === null) {
          job.child.kill();
        }
      }
      await Promise.allSettled(jobs.map((job) => job.done));
    }
  });
  it("commits the sequence and object together using the store state environment", () => {
    const descriptor = store.createWithSignature((stateEnv) => {
      expect(stateEnv.OPENCLAW_STATE_DIR).toBe(directory);
      return value(nextPushSequence("gateway", "alice", { env: stateEnv }));
    });
    expect(store.redeem(descriptor, "alice").envelope.sequence).toBe(1);
    expect(nextPushSequence("gateway", "alice", { env })).toBe(2);
  });
  it("rolls back allocation when signing fails before object creation", () => {
    expect(() =>
      store.createWithSignature((stateEnv) => {
        nextPushSequence("gateway", "alice", { env: stateEnv });
        throw new Error("test signing failure");
      }),
    ).toThrow("signing failure");
    expect(store.listForAuthenticatedRecipient("alice").items).toEqual([]);
    expect(nextPushSequence("gateway", "alice", { env })).toBe(1);
  });
  it("rolls back allocation when object admission fails after signing", () => {
    expect(() =>
      store.createWithSignature((stateEnv) =>
        value(nextPushSequence("gateway", "alice", { env: stateEnv }), "x".repeat(65537)),
      ),
    ).toThrow("oversized");
    expect(store.listForAuthenticatedRecipient("alice").items).toEqual([]);
    expect(nextPushSequence("gateway", "alice", { env })).toBe(1);
  });
  it("recovers after a publishing process exits with an uncommitted sequence", async () => {
    const source = new URL("./pqc-push-state.ts", import.meta.url).href;
    const code = `const {nextPushSequence,SqlitePushReferenceStore}=await import(${JSON.stringify(source)});
      new SqlitePushReferenceStore().createWithSignature(env=>{
        const sequence=nextPushSequence('gateway','alice',{env});
        process.stdout.write('READY\\n');
        Atomics.wait(new Int32Array(new SharedArrayBuffer(4)),0,0,15000);
        return {payload:'uncommitted',recipientId:'alice',envelope:{sender_id:'gateway',recipient_id:'alice',sequence}};
      });`;
    const child = spawn(process.execPath, ["--import", "tsx", "--input-type=module", "-e", code], {
      env,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let ready = false;
    const exited = new Promise<void>((resolve, reject) => {
      child.once("error", reject);
      child.once("exit", () => resolve());
    });
    const timeout = setTimeout(() => child.kill(), 20000);
    try {
      await new Promise<void>((resolve, reject) => {
        child.stdout.on("data", (data) => {
          if (String(data).includes("READY")) {
            ready = true;
            resolve();
          }
        });
        child.once("error", reject);
        child.once("exit", () => {
          if (!ready) {
            reject(new Error("publisher exited before transaction probe"));
          }
        });
      });
      child.kill();
      await exited;
      expect(store.listForAuthenticatedRecipient("alice").items).toEqual([]);
      expect(nextPushSequence("gateway", "alice", { env })).toBe(1);
    } finally {
      clearTimeout(timeout);
      if (child.exitCode === null && child.signalCode === null) {
        child.kill();
      }
      await exited;
    }
  });
});
