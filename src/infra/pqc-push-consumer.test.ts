import { spawn } from "node:child_process";
import { generateKeyPairSync } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import {
  signPushPayloadDual,
  type PushTrustedKeyRegistry,
} from "../security/push-dual-signature.js";
import {
  closeOpenClawStateDatabase,
  openOpenClawStateDatabase,
} from "../state/openclaw-state-db.js";
import { generateMlDsa65Keypair } from "./mldsa65-key-storage.js";
import { consumePushPayloadDual } from "./pqc-push-consumer.js";

let directory: string;
beforeEach(() => {
  directory = mkdtempSync(join(tmpdir(), "pqc-consume-"));
});
afterEach(() => {
  closeOpenClawStateDatabase();
  rmSync(directory, { recursive: true, force: true });
});

function message() {
  const ed = generateKeyPairSync("ed25519");
  const secret = ed.privateKey.export({ format: "der", type: "pkcs8" }).subarray(-32);
  const publicKey = ed.publicKey.export({ format: "der", type: "spki" }).subarray(-32);
  const ml = generateMlDsa65Keypair();
  const nowMs = Date.now();
  const signed = signPushPayloadDual({
    payload: '{"task":"local-write"}',
    ed25519SecretKeyRaw: secret,
    mldsa65SecretKeyRaw: ml.secretKey,
    keyIdEd25519: "ed",
    keyIdMldsa65: "ml",
    senderId: "gateway",
    recipientId: "alice",
    createdAtMs: nowMs,
    sequence: 1,
  });
  const registry: PushTrustedKeyRegistry = {
    resolve: (algorithm, keyId) => ({
      algorithm,
      keyId,
      senderId: "gateway",
      publicKeyRaw: algorithm === "ed25519" ? publicKey : ml.publicKey,
    }),
  };
  return {
    signed,
    registry,
    nowMs,
    publicKeys: {
      ed: Buffer.from(publicKey).toString("base64url"),
      ml: Buffer.from(ml.publicKey).toString("base64url"),
    },
  };
}

function options(m: ReturnType<typeof message>) {
  return {
    ...m.signed,
    registry: m.registry,
    expectedRecipientId: "alice",
    nowMs: m.nowMs,
    state: { path: join(directory, "openclaw.sqlite") },
  };
}
function rows() {
  const { db } = openOpenClawStateDatabase({ path: join(directory, "openclaw.sqlite") });
  return Object.fromEntries(
    ["effect_rows", "pqc_push_replay", "pqc_push_nonces", "pqc_push_completions"].map((table) => [
      table,
      db.prepare(`SELECT COUNT(*) AS n FROM ${table}`).get()!.n,
    ]),
  );
}
function initialize() {
  openOpenClawStateDatabase({ path: join(directory, "openclaw.sqlite") }).db.exec(
    "CREATE TABLE effect_rows(id INTEGER PRIMARY KEY AUTOINCREMENT, payload TEXT NOT NULL) STRICT",
  );
}
function worker(
  m: ReturnType<typeof message>,
  fault?: "after-effect" | "after-commit",
): Promise<unknown> {
  const source = new URL("./pqc-push-consumer.ts", import.meta.url).href;
  const code = `
    const { consumePushPayloadDual } = await import(${JSON.stringify(source)});
    let input=''; for await (const chunk of process.stdin) input+=chunk;
    const data=JSON.parse(input);
    const registry={resolve:(algorithm,keyId)=>({algorithm,keyId,senderId:'gateway',
      publicKeyRaw:Buffer.from(algorithm==='ed25519'?data.keys.ed:data.keys.ml,'base64url')})};
    const result=consumePushPayloadDual({...data.signed,registry,expectedRecipientId:'alice',
      nowMs:data.nowMs,state:{path:data.path}},({db})=>{
      db.prepare('INSERT INTO effect_rows(payload) VALUES (?)').run(data.signed.payload);
      if(data.fault==='after-effect')process.exit(93);
      return {written:true};
    });
    if(data.fault==='after-commit')process.exit(94);
    process.stdout.write(JSON.stringify(result));
  `;
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, ["--import", "tsx", "--input-type=module", "-e", code], {
      windowsHide: true,
      stdio: ["pipe", "pipe", "pipe"],
    });
    let output = "";
    let error = "";
    const timer = setTimeout(() => {
      child.kill();
      reject(new Error("consumer worker timeout"));
    }, 20_000);
    child.stdout.on("data", (p) => {
      output += String(p);
    });
    child.stderr.on("data", (p) => {
      error += String(p);
    });
    child.once("error", (e) => {
      clearTimeout(timer);
      reject(e);
    });
    child.once("close", (status) => {
      clearTimeout(timer);
      if (status === 93 || status === 94) {
        resolve(status);
      } else if (status !== 0) {
        reject(new Error(error));
      } else {
        try {
          resolve(JSON.parse(output));
        } catch (e) {
          reject(e instanceof Error ? e : new Error("invalid child result", { cause: e }));
        }
      }
    });
    child.stdin.end(
      JSON.stringify({
        signed: m.signed,
        keys: m.publicKeys,
        nowMs: m.nowMs,
        path: join(directory, "openclaw.sqlite"),
        fault,
      }),
    );
  });
}

describe("atomic signed push consumption", () => {
  it("rolls back the local effect and replay state when the callback fails", () => {
    initialize();
    const m = message();
    expect(() =>
      consumePushPayloadDual(options(m), ({ db }) => {
        db.prepare("INSERT INTO effect_rows(payload) VALUES (?)").run(m.signed.payload);
        throw new Error("business interrupted");
      }),
    ).toThrow("business interrupted");
    closeOpenClawStateDatabase();
    expect(rows()).toEqual({
      effect_rows: 0,
      pqc_push_replay: 0,
      pqc_push_nonces: 0,
      pqc_push_completions: 0,
    });
    expect(
      consumePushPayloadDual(options(m), ({ db }) => {
        db.prepare("INSERT INTO effect_rows(payload) VALUES (?)").run(m.signed.payload);
        return { written: true };
      }).status,
    ).toBe("fresh_completed");
    expect(rows().effect_rows).toBe(1);
  });
  it.each(["after-effect", "after-commit"] as const)(
    "recovers after actual process exit %s",
    async (fault) => {
      initialize();
      const m = message();
      closeOpenClawStateDatabase();
      expect(await worker(m, fault)).toBe(fault === "after-effect" ? 93 : 94);
      expect(rows().effect_rows).toBe(fault === "after-effect" ? 0 : 1);
      closeOpenClawStateDatabase();
      expect(await worker(m)).toEqual({
        status: fault === "after-effect" ? "fresh_completed" : "already_completed",
        value: { written: true },
      });
      expect(rows()).toEqual({
        effect_rows: 1,
        pqc_push_replay: 1,
        pqc_push_nonces: 1,
        pqc_push_completions: 1,
      });
    },
    30_000,
  );
  it("commits one effect when eight independent processes consume the same message", async () => {
    initialize();
    const m = message();
    closeOpenClawStateDatabase();
    const results = (await Promise.all(Array.from({ length: 8 }, () => worker(m)))) as Array<{
      status: string;
    }>;
    expect(results.filter((r) => r.status === "fresh_completed")).toHaveLength(1);
    expect(results.filter((r) => r.status === "already_completed")).toHaveLength(7);
    expect(rows().effect_rows).toBe(1);
  }, 30_000);
  it("revalidates signatures, recipient and key revocation before returning a completion", () => {
    initialize();
    const m = message();
    const apply = () => ({ written: true });
    consumePushPayloadDual(options(m), apply);
    expect(() => consumePushPayloadDual({ ...options(m), payload: "tampered" }, apply)).toThrow(
      "hash mismatch",
    );
    expect(() =>
      consumePushPayloadDual({ ...options(m), expectedRecipientId: "bob" }, apply),
    ).toThrow("recipient");
    expect(() =>
      consumePushPayloadDual(
        {
          ...options(m),
          registry: {
            resolve: (a, k) => ({
              ...m.registry.resolve(a, k)!,
              revokedAtMs: m.nowMs,
            }),
          },
        },
        apply,
      ),
    ).toThrow("revoked");
  });
});
