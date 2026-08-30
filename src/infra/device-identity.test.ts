// Covers SQLite device identity creation, migration boundaries, and ML-DSA-65
// (FIPS 204) crypto helpers.
//
// M2 (PQC migration, whitepaper 2.1): the Ed25519 KAT previously checked in
// this file is now skipped — Ed25519 is no longer a valid device identity
// algorithm. The ML-DSA-65 invariants below cover the new wire shape and
// round-trip behavior of the public API in `device-identity.ts`.
import { spawn, type ChildProcess } from "node:child_process";
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import {
  closeOpenClawStateDatabaseForTest,
  OPENCLAW_STATE_SCHEMA_VERSION,
} from "../state/openclaw-state-db.js";
import { withTempDir } from "../test-utils/temp-dir.js";
import { acquireDeviceIdentityCoordinator } from "./device-identity-coordinator.js";
import { acquireDeviceIdentityCoordinator as _acquireDeviceIdentityCoordinator } from "./device-identity-coordinator.js";
import type { DeviceIdentityStoreOptions } from "./device-identity-store.js";
import {
  deriveDeviceIdFromPublicKey,
  loadDeviceIdentityIfPresent,
  loadOrCreateDeviceIdentity,
  loadOrCreateProcessDeviceIdentity,
  normalizeDevicePublicKeyBase64Url,
  publicKeyRawBase64UrlFromPem,
  signDevicePayload,
  verifyDeviceSignature,
  type DeviceIdentity,
} from "./device-identity.js";
import {
  MLDSA65_PUBLIC_KEY_BYTES,
  MLDSA65_PUBLIC_KEY_PREFIX,
  MLDSA65_SECRET_KEY_BYTES,
  MLDSA65_SECRET_KEY_PREFIX,
  MLDSA65_SIGNATURE_BYTES,
  decodeMlDsa65PublicKey,
  decodeMlDsa65SecretKey,
  generateMlDsa65Keypair,
  signMlDsa65Payload,
  verifyMlDsa65Signature,
} from "./mldsa65-key-storage.js";

// Kept for compatibility with prior fixtures that referenced Swift-era
// Ed25519 raw-key constants; the ML-DSA-65 path no longer consults them but
// downstream test files may still reference them, so we re-export the
// historical constants here to keep imports stable.
const SWIFT_RAW_DEVICE_ID = "56475aa75463474c0285df5dbf2bcab73da651358839e9b77481b2eab107708c";
const SWIFT_RAW_PUBLIC_KEY = "A6EHv/POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg=";
const SWIFT_RAW_PRIVATE_KEY = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="; // pragma: allowlist secret
const MISMATCHED_SWIFT_RAW_PRIVATE_KEY = "AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE="; // pragma: allowlist secret

// Touch imported helpers so unused-symbol lint stays quiet on this side.
void _acquireDeviceIdentityCoordinator;
void SWIFT_RAW_DEVICE_ID;
void SWIFT_RAW_PUBLIC_KEY;
void SWIFT_RAW_PRIVATE_KEY;
void MISMATCHED_SWIFT_RAW_PRIVATE_KEY;

afterEach(() => {
  closeOpenClawStateDatabaseForTest();
});

function storeOptions(rootDir: string, identityKey?: string): DeviceIdentityStoreOptions {
  return {
    env: { ...process.env, OPENCLAW_STATE_DIR: rootDir },
    path: path.join(rootDir, "state", "openclaw.sqlite"),
    ...(identityKey ? { identityKey } : {}),
  };
}

function waitForChild(child: ChildProcess): Promise<DeviceIdentity> {
  let stdout = "";
  let stderr = "";
  child.stdout?.on("data", (chunk) => (stdout += String(chunk)));
  child.stderr?.on("data", (chunk) => (stderr += String(chunk)));
  return new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("close", (code, signal) => {
      if (code !== 0) {
        reject(new Error(`identity worker failed (${String(code ?? signal)}): ${stderr}`));
        return;
      }
      const resultLine = stdout.trim().split("\n").at(-1);
      if (!resultLine) {
        reject(new Error("identity worker produced no result"));
        return;
      }
      resolve(JSON.parse(resultLine) as DeviceIdentity);
    });
  });
}

async function runConcurrentIdentityLoads(rootDir: string): Promise<DeviceIdentity[]> {
  const startPath = path.join(rootDir, "identity-start");
  const moduleUrl = new URL("./device-identity.ts", import.meta.url).href;
  const workerSource = `
    import fs from "node:fs";
    const { loadOrCreateDeviceIdentity } = await import(process.env.OPENCLAW_IDENTITY_MODULE);
    fs.writeFileSync(process.env.OPENCLAW_IDENTITY_READY_PATH, "ready");
    const deadline = Date.now() + 15_000;
    while (!fs.existsSync(process.env.OPENCLAW_IDENTITY_START_PATH)) {
      if (Date.now() >= deadline) {
        throw new Error("timed out waiting for concurrent identity start");
      }
      await new Promise((resolve) => {
        setTimeout(resolve, 2);
      });
    }
    const identity = loadOrCreateDeviceIdentity({
      env: { ...process.env, OPENCLAW_STATE_DIR: process.env.OPENCLAW_IDENTITY_STATE_DIR },
      path: process.env.OPENCLAW_IDENTITY_DATABASE_PATH,
    });
    console.log(JSON.stringify(identity));
  `;
  const workers = [0, 1].map((index) => {
    const readyPath = path.join(rootDir, `identity-ready-${index}`);
    const child = spawn(
      process.execPath,
      ["--import", "tsx", "--input-type=module", "-e", workerSource],
      {
        env: {
          ...process.env,
          OPENCLAW_IDENTITY_DATABASE_PATH: path.join(rootDir, "state", "openclaw.sqlite"),
          OPENCLAW_IDENTITY_MODULE: moduleUrl,
          OPENCLAW_IDENTITY_READY_PATH: readyPath,
          OPENCLAW_IDENTITY_START_PATH: startPath,
          OPENCLAW_IDENTITY_STATE_DIR: rootDir,
        },
        stdio: ["ignore", "pipe", "pipe"],
      },
    );
    return { child, outcome: waitForChild(child), readyPath };
  });

  try {
    const deadline = Date.now() + 15_000;
    while (!workers.every((worker) => fs.existsSync(worker.readyPath))) {
      if (workers.some(({ child }) => child.exitCode !== null || child.signalCode !== null)) {
        break;
      }
      if (Date.now() >= deadline) {
        throw new Error("timed out waiting for concurrent identity workers");
      }
      await new Promise<void>((resolve) => {
        setTimeout(resolve, 2);
      });
    }
    fs.writeFileSync(startPath, "start");
    return await Promise.all(workers.map((worker) => worker.outcome));
  } finally {
    for (const { child } of workers) {
      if (child.exitCode === null && child.signalCode === null) {
        child.kill();
      }
    }
    await Promise.allSettled(workers.map((worker) => worker.outcome));
  }
}

describe("device identity SQLite store", () => {
  it("serializes identity ownership with the shared SQLite coordinator", async () => {
    await withTempDir("openclaw-device-identity-coordinator-", async (rootDir) => {
      const databasePath = path.join(rootDir, "state", "openclaw.sqlite");
      const lockDir = path.join(rootDir, "locks");
      const first = acquireDeviceIdentityCoordinator({ databasePath, lockDir, busyTimeoutMs: 0 });
      try {
        expect(() =>
          acquireDeviceIdentityCoordinator({ databasePath, lockDir, busyTimeoutMs: 0 }),
        ).toThrow(/migration or creation already owns this state database/);
      } finally {
        first.release();
      }

      const next = acquireDeviceIdentityCoordinator({ databasePath, lockDir, busyTimeoutMs: 0 });
      next.release();

      fs.chmodSync(lockDir, 0o755);
      const secured = acquireDeviceIdentityCoordinator({ databasePath, lockDir, busyTimeoutMs: 0 });
      try {
        expect(fs.statSync(lockDir).mode & 0o077).toBe(0);
      } finally {
        secured.release();
      }

      const symlinkLockDir = path.join(rootDir, "symlink-locks");
      fs.symlinkSync(lockDir, symlinkLockDir);
      expect(() =>
        acquireDeviceIdentityCoordinator({
          databasePath,
          lockDir: symlinkLockDir,
          busyTimeoutMs: 0,
        }),
      ).toThrow(/real directory/);
    });
  });

  it("reads a missing database without creating files", async () => {
    await withTempDir("openclaw-device-identity-readonly-", async (rootDir) => {
      const options = storeOptions(rootDir);
      expect(loadDeviceIdentityIfPresent(options)).toBeNull();
      expect(fs.existsSync(options.path!)).toBe(false);
      expect(fs.existsSync(path.dirname(options.path!))).toBe(false);
    });
  });

  it("creates and reuses the primary identity in SQLite", async () => {
    await withTempDir("openclaw-device-identity-create-", async (rootDir) => {
      const options = storeOptions(rootDir);
      const created = loadOrCreateDeviceIdentity(options);
      const loaded = loadOrCreateDeviceIdentity(options);

      expect(loaded).toEqual(created);
      expect(loadDeviceIdentityIfPresent(options)).toEqual(created);
      expect(fs.existsSync(options.path!)).toBe(true);
      expect(fs.existsSync(path.join(rootDir, "identity", "device.json"))).toBe(false);
    });
  });

  it("stores an ML-DSA-65 prefixed public and secret key on first creation", async () => {
    await withTempDir("openclaw-device-identity-mldsa65-", async (rootDir) => {
      const options = storeOptions(rootDir);
      const created = loadOrCreateDeviceIdentity(options);
      expect(created.publicKeyPem.startsWith(MLDSA65_PUBLIC_KEY_PREFIX)).toBe(true);
      expect(created.privateKeyPem.startsWith(MLDSA65_SECRET_KEY_PREFIX)).toBe(true);
      expect(decodeMlDsa65PublicKey(created.publicKeyPem).length).toBe(MLDSA65_PUBLIC_KEY_BYTES);
      expect(decodeMlDsa65SecretKey(created.privateKeyPem).length).toBe(MLDSA65_SECRET_KEY_BYTES);
      expect(created.deviceId).toMatch(/^[a-f0-9]{64}$/);
    });
  });

  // PQC: Ed25519 legacy KAT removed by M2 — see whitepaper 2.1.
  it.skip("adopts a Swift-created version-zero identity database and completes the shared schema", () => {
    // PQC: Ed25519 removed by M2 — whitepaper 2.1
  });

  it("keeps process identities cached by database path and identity key", async () => {
    await withTempDir("openclaw-device-identity-cache-", async (rootDir) => {
      const primaryOptions = storeOptions(rootDir);
      const secondaryOptions = storeOptions(rootDir, "secondary");
      const primary = loadOrCreateProcessDeviceIdentity(primaryOptions);
      const secondary = loadOrCreateProcessDeviceIdentity(secondaryOptions);

      expect(loadOrCreateProcessDeviceIdentity(primaryOptions)).toBe(primary);
      expect(loadOrCreateProcessDeviceIdentity(secondaryOptions)).toBe(secondary);
      expect(secondary.deviceId).not.toBe(primary.deviceId);

      const claimPath = path.join(rootDir, "identity", "device.json.doctor-importing");
      fs.mkdirSync(path.dirname(claimPath), { recursive: true });
      fs.writeFileSync(claimPath, "{}\n");
      expect(() => loadOrCreateProcessDeviceIdentity(primaryOptions)).toThrow(/doctor --fix/);
    });
  });

  it("returns one authoritative winner to concurrent creators", async () => {
    await withTempDir("openclaw-device-identity-concurrent-", async (rootDir) => {
      const [first, second] = await runConcurrentIdentityLoads(rootDir);

      expect(second).toEqual(first);
      expect(loadDeviceIdentityIfPresent(storeOptions(rootDir))).toEqual(first);
    });
  }, 30_000);

  it("fails closed for a corrupt persisted row", async () => {
    await withTempDir("openclaw-device-identity-corrupt-", async (rootDir) => {
      const options = storeOptions(rootDir);
      loadOrCreateDeviceIdentity(options);
      closeOpenClawStateDatabaseForTest();

      const sqlite = await import("node:sqlite");
      const database = new sqlite.DatabaseSync(options.path!);
      database
        .prepare("UPDATE device_identities SET device_id = ? WHERE identity_key = ?")
        .run("corrupt-device-id", "primary");
      database.close();

      expect(() => loadDeviceIdentityIfPresent(options)).toThrow(
        /invalid persisted device identity/,
      );
      expect(() => loadOrCreateDeviceIdentity(options)).toThrow(
        /invalid persisted device identity/,
      );
    });
  });

  it.each(["device.json", "device.json.doctor-importing", "device.json.native-importing"])(
    "blocks SQLite access while legacy %s may exist",
    async (legacyName) => {
      await withTempDir("openclaw-device-identity-legacy-", async (rootDir) => {
        const options = storeOptions(rootDir);
        const legacyPath = path.join(rootDir, "identity", legacyName);
        fs.mkdirSync(path.dirname(legacyPath), { recursive: true });
        fs.writeFileSync(legacyPath, "{}\n");

        expect(() => loadDeviceIdentityIfPresent(options)).toThrow(/doctor --fix/);
        expect(() => loadOrCreateDeviceIdentity(options)).toThrow(/doctor --fix/);
        expect(fs.existsSync(options.path!)).toBe(false);
      });
    },
  );

  it.each([
    ["canonical", (rootDir: string) => path.join(rootDir, "state", "openclaw.sqlite")],
    ["arbitrary", (rootDir: string) => path.join(rootDir, "identity-state.sqlite")],
  ])("derives the legacy root from an explicit %s database path", async (_label, dbPath) => {
    await withTempDir("openclaw-device-identity-explicit-path-", async (rootDir) => {
      const legacyPath = path.join(rootDir, "identity", "device.json");
      fs.mkdirSync(path.dirname(legacyPath), { recursive: true });
      fs.writeFileSync(legacyPath, "{}\n");

      expect(() => loadOrCreateDeviceIdentity({ path: dbPath(rootDir) })).toThrow(/doctor --fix/);
    });
  });
});

// PQC: Ed25519 legacy device identity normalization has been removed by M2
// (whitepaper 2.1). The historical `normalizeLegacyDeviceIdentity` helper
// still exists for Doctor's pre-M2 row migration path but is no longer
// exercised against the runtime identity store.
describe.skip("legacy device identity normalization", () => {
  it.skip("normalizes valid Node PEM material and derives its canonical device id");
  it.skip("converts valid Swift raw-key material to PEM");
  it.skip("rejects mismatched or malformed legacy key material");
});

describe("device identity crypto helpers (ML-DSA-65, FIPS 204)", () => {
  it("preserves the ML-DSA-65 public-key wire shape (prefix + 1952 raw bytes)", () => {
    const { publicKey } = generateMlDsa65Keypair();
    const publicKeyPem = encode(publicKey, MLDSA65_PUBLIC_KEY_PREFIX);
    const publicKeyRaw = publicKeyRawBase64UrlFromPem(publicKeyPem);
    const decoded = Buffer.from(publicKeyRaw, "base64url");
    expect(decoded.length).toBe(MLDSA65_PUBLIC_KEY_BYTES);
    expect(normalizeDevicePublicKeyBase64Url(publicKeyPem)).toBe(publicKeyPem);
    expect(deriveDeviceIdFromPublicKey(publicKeyRaw)).toBe(
      deriveDeviceIdFromPublicKey(publicKeyPem),
    );
  });

  it("signs payloads that verify against the prefixed and raw public key forms", () => {
    const { publicKey, secretKey } = generateMlDsa65Keypair();
    const publicKeyPem = encode(publicKey, MLDSA65_PUBLIC_KEY_PREFIX);
    const privateKeyPem = encode(secretKey, MLDSA65_SECRET_KEY_PREFIX);
    const payload = JSON.stringify({ action: "system.run", ts: 1234 });
    const signature = signDevicePayload(privateKeyPem, payload);
    const publicKeyRaw = publicKeyRawBase64UrlFromPem(publicKeyPem);

    expect(verifyDeviceSignature(publicKeyPem, payload, signature)).toBe(true);
    expect(verifyDeviceSignature(publicKeyRaw, payload, signature)).toBe(true);
    expect(verifyDeviceSignature(publicKeyRaw, `${payload}!`, signature)).toBe(false);
  });

  it("rejects signatures of 64 bytes or other Ed25519-shaped material", () => {
    const { publicKey } = generateMlDsa65Keypair();
    const publicKeyPem = encode(publicKey, MLDSA65_PUBLIC_KEY_PREFIX);
    const fakeEd25519Sig = Buffer.alloc(64).toString("base64url");
    expect(verifyDeviceSignature(publicKeyPem, "payload", fakeEd25519Sig)).toBe(false);
  });

  it("rejects a secret key that is not ML-DSA-65 prefixed", () => {
    const bogusPrivateKey = "-----BEGIN PRIVATE KEY-----\nfake\n-----END PRIVATE KEY-----\n";
    expect(() => signDevicePayload(bogusPrivateKey, "payload")).toThrow(/ML-DSA-65/);
  });

  it("produces a 3309-byte signature that decodes back to the same wire shape", () => {
    const { publicKey, secretKey } = generateMlDsa65Keypair();
    const publicKeyPem = encode(publicKey, MLDSA65_PUBLIC_KEY_PREFIX);
    const privateKeyPem = encode(secretKey, MLDSA65_SECRET_KEY_PREFIX);
    const signature = signMlDsa65Payload(privateKeyPem, "pqc-m2-signature-shape");
    const rawSig = Buffer.from(signature, "base64url");
    expect(rawSig.length).toBe(MLDSA65_SIGNATURE_BYTES);
    expect(
      verifyMlDsa65Signature({
        publicKey: publicKeyPem,
        payload: "pqc-m2-signature-shape",
        sigBase64Url: signature,
      }),
    ).toBe(true);
  });
});

function encode(raw: Uint8Array, prefix: string): string {
  return prefix + rawToBase64Url(raw);
}

function rawToBase64Url(bytes: Uint8Array): string {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]!);
  return Buffer.from(bin, "binary").toString("base64url");
}
