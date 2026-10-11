// New measurements only: never rewrite the paper's historical samples.
import { execFileSync } from "node:child_process";
import { createHash, randomBytes } from "node:crypto";
import { mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { cpus, platform, release } from "node:os";
import { resolve, join } from "node:path";
import { performance } from "node:perf_hooks";
import { ed25519 } from "@noble/curves/ed25519.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { encryptNip44V2, decryptNip44V2 } from "../src/security/nip44-v2.js";
import {
  InMemoryPushReplayGuard,
  signPushPayloadDual,
  verifyPushPayloadDualStrict,
} from "../src/security/push-dual-signature.js";

const sizes = [64, 1024, 16384];
const repeats = 100;
const runIndex = Number(process.argv[2] ?? "0");
const output = resolve(process.argv[3] ?? ".artifacts/pqc-benchmark");
if (!Number.isSafeInteger(runIndex) || runIndex < 0 || runIndex > 38) {
  throw new Error("run index must be 0..38 (one balanced 13-operation × 3-payload cycle)");
}
function git(...args: string[]): string {
  return execFileSync(
    "git",
    ["-c", `safe.directory=${process.cwd().replace(/\\/g, "/")}`, ...args],
    { encoding: "utf8", windowsHide: true },
  ).trim();
}
if (git("status", "--porcelain", "--untracked-files=no")) {
  throw new Error("benchmark requires a clean committed source tree");
}
const commit = git("rev-parse", "HEAD");
mkdirSync(output, { recursive: true });
const hashFile = (file: string) => createHash("sha256").update(readFileSync(file)).digest("hex");
const sourceFiles = [
  "scripts/bench-pqc-production.ts",
  "src/security/nip44-v2.ts",
  "src/security/push-dual-signature.ts",
  "src/infra/mldsa65-key-storage.ts",
  "src/infra/ed25519-signature.ts",
  "pnpm-lock.yaml",
  "package.json",
];
const ed = randomBytes(32);
const edPublic = ed25519.getPublicKey(ed);
const ml = ml_dsa65.keygen();
const kem = ml_kem768.keygen();
const context = {
  senderPubkey: "a".repeat(64),
  recipientPubkey: "b".repeat(64),
  purpose: "nostr-dm" as const,
};
let sequence = 0;
const guard = new InMemoryPushReplayGuard();
const registry = {
  resolve(algorithm: "ed25519" | "ml-dsa-65", keyId: string) {
    return {
      algorithm,
      keyId,
      senderId: "bench",
      publicKeyRaw: algorithm === "ed25519" ? edPublic : ml.publicKey,
    };
  },
};
const samples: Array<{
  operation: string;
  payloadBytes: number;
  sample: number;
  milliseconds: number;
}> = [];
// Rotate operation and payload order between independent processes. Input
// preparation is outside each timed operation; strict Accept sees a fresh
// sequence/nonce on every sample and reuses one guard throughout the process.
const sizeOrder = sizes.map((_, i) => sizes[(i + runIndex) % sizes.length]!);
for (const size of sizeOrder) {
  const bytes = new Uint8Array(size).fill(65);
  const payload = new TextDecoder().decode(bytes);
  const edSig = ed25519.sign(bytes, ed);
  const mlSig = ml_dsa65.sign(bytes, ml.secretKey);
  const encapsulated = ml_kem768.encapsulate(kem.publicKey);
  const encrypted = encryptNip44V2(kem.publicKey, bytes, context);
  const sign = () =>
    signPushPayloadDual({
      payload,
      ed25519SecretKeyRaw: ed,
      mldsa65SecretKeyRaw: ml.secretKey,
      keyIdEd25519: "ed",
      keyIdMldsa65: "ml",
      senderId: "bench",
      recipientId: "receiver",
      sequence: ++sequence,
    });
  const operations: Array<[string, () => void, (() => void)?]> = [
    [
      "ed25519-keygen",
      () => {
        ed25519.getPublicKey(randomBytes(32));
      },
    ],
    [
      "ed25519-sign",
      () => {
        ed25519.sign(bytes, ed);
      },
    ],
    [
      "ed25519-verify",
      () => {
        if (!ed25519.verify(edSig, bytes, edPublic)) {
          throw new Error("Ed25519 verification failed");
        }
      },
    ],
    [
      "mldsa65-keygen",
      () => {
        ml_dsa65.keygen();
      },
    ],
    [
      "mldsa65-sign",
      () => {
        ml_dsa65.sign(bytes, ml.secretKey);
      },
    ],
    [
      "mldsa65-verify",
      () => {
        if (!ml_dsa65.verify(mlSig, bytes, ml.publicKey)) {
          throw new Error("ML-DSA verification failed");
        }
      },
    ],
    [
      "dual-sign",
      () => {
        sign();
      },
    ],
    [
      "dual-strict-accept",
      () => {
        verifyPushPayloadDualStrict({
          payload,
          envelope: current.envelope,
          registry,
          expectedRecipientId: "receiver",
          replayGuard: guard,
        });
      },
      () => {
        current = sign();
      },
    ],
    [
      "mlkem768-keygen",
      () => {
        ml_kem768.keygen();
      },
    ],
    [
      "mlkem768-encapsulate",
      () => {
        ml_kem768.encapsulate(kem.publicKey);
      },
    ],
    [
      "mlkem768-decapsulate",
      () => {
        const shared = ml_kem768.decapsulate(encapsulated.cipherText, kem.secretKey);
        if (!Buffer.from(shared).equals(Buffer.from(encapsulated.sharedSecret))) {
          throw new Error("KEM mismatch");
        }
      },
    ],
    [
      "pqc3-encrypt",
      () => {
        encryptNip44V2(kem.publicKey, bytes, context);
      },
    ],
    [
      "pqc3-decrypt",
      () => {
        if (
          !Buffer.from(decryptNip44V2(kem.secretKey, encrypted, context)).equals(Buffer.from(bytes))
        ) {
          throw new Error("message mismatch");
        }
      },
    ],
  ];
  let current = sign();
  const shift = runIndex % operations.length;
  const ordered = [...operations.slice(shift), ...operations.slice(0, shift)];
  for (const [operation, run, prepare] of ordered) {
    for (let warm = 0; warm < 10; warm++) {
      prepare?.();
      run();
    }
    for (let sample = 0; sample < repeats; sample++) {
      prepare?.();
      const start = performance.now();
      run();
      samples.push({
        operation,
        payloadBytes: size,
        sample,
        milliseconds: performance.now() - start,
      });
    }
  }
}
const result = {
  format: "openclaw-pqc-benchmark-v2",
  runIndex,
  processId: process.pid,
  createdAt: new Date().toISOString(),
  sourceCommit: commit,
  node: process.version,
  platform: platform(),
  osRelease: release(),
  cpu: cpus()[0]?.model,
  lockSha256: hashFile("pnpm-lock.yaml"),
  installedDependencies: Object.fromEntries(
    ["@noble/curves", "@noble/post-quantum"].map((name) => {
      const file = join("node_modules", name, "package.json");
      return [
        name,
        { version: JSON.parse(readFileSync(file, "utf8")).version, packageSha256: hashFile(file) },
      ];
    }),
  ),
  sourceHashes: Object.fromEntries(sourceFiles.map((f) => [f, hashFile(f)])),
  repetitions: repeats,
  warmup: 10,
  sizeOrder,
  operationRotation: runIndex % 13,
  samples,
  limits:
    "Process-local strict replay guard; excludes RPC/SQLite/transport/device latency; not historical paper reproduction or full product acceptance.",
};
const name = `pqc-${runIndex}-${process.pid}.json`;
writeFileSync(join(output, name), JSON.stringify(result, null, 2) + "\n", { flag: "wx" });
process.stdout.write(
  `Recorded ${samples.length} measurements at ${join(output, name)} from ${commit}.\n`,
);
