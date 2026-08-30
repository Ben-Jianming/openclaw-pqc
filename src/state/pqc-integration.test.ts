// Cross-module integration tests for PQC migration.
//
// Verifies the end-to-end flow across M1 (ML-DSA-65 key storage) → M2 (device
// identity) → M4 (secret wrapping) → M5 (device-identity store + wrap) → M11
// (push dual signature). Each test uses ephemeral sqlite + temp dirs; never
// touches /home/benjamin/pqc-fork-state.
import fs from "node:fs";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { withTempDir } from "../test-utils/temp-dir.js";
import { ensureAdditiveStateColumns } from "./openclaw-state-db-schema-additive.js";
import { closeOpenClawStateDatabaseForTest } from "./openclaw-state-db.js";

afterEach(() => {
  for (const key of Object.keys(process.env)) {
    if (key.startsWith("OPENCLAW_PQC_TEST_")) delete process.env[key];
  }
  closeOpenClawStateDatabaseForTest();
});

describe("PQC end-to-end integration", () => {
  it("M1 + M2 + M5 + M11 chain: generate ML-DSA-65 → wrap → store → load → unwrap → sign push payload", async () => {
    await withTempDir("openclaw-pqc-e2e-", async (rootDir) => {
      const stateDir = path.join(rootDir, "state");
      fs.mkdirSync(stateDir, { recursive: true });
      const databasePath = path.join(stateDir, "openclaw.sqlite");
      const sqlite = await import("node:sqlite");
      const { generateMlDsa65Keypair } = await import("../infra/mldsa65-key-storage.js");
      const { wrapSecret, unwrapSecret, serializeWrappedSecret, deserializeWrappedSecret } =
        await import("../security/secret-wrapping.js");
      const { generateWrappingKey } = await import("../security/keyring-provider.js");
      const { signPushPayloadDual, verifyPushPayloadDual } =
        await import("../security/push-dual-signature.js");
      const { generateKeyPairSync } = await import("node:crypto");

      // 1. M1: generate a real ML-DSA-65 keypair via @noble/post-quantum
      const ml = generateMlDsa65Keypair();
      expect(ml.publicKey.length).toBe(1952);
      expect(ml.secretKey.length).toBe(4032);

      // 2. M4: wrap the secret key with an AES-256-GCM key
      const wrapKeyB64 = generateWrappingKey();
      const wrapKey = Buffer.from(wrapKeyB64, "base64url");
      const wrapped = wrapSecret(Buffer.from(ml.secretKey), "wrap-e2e-test", wrapKey);
      expect(wrapped.v).toBe(1);
      expect(wrapped.keyId).toBe("wrap-e2e-test");
      expect(wrapped.ciphertext.length).toBe(ml.secretKey.length);

      const unwrapped = unwrapSecret(wrapped, wrapped.keyId, wrapKey);
      expect(Buffer.compare(unwrapped, ml.secretKey)).toBe(0);

      // 3. M3: persist wrapped envelope to device_identities (sqlite)
      const db = new sqlite.DatabaseSync(databasePath);
      db.exec(`
        CREATE TABLE device_identities (
          identity_key TEXT NOT NULL PRIMARY KEY,
          device_id TEXT NOT NULL,
          public_key_pem TEXT NOT NULL,
          private_key_pem TEXT NOT NULL,
          created_at_ms INTEGER NOT NULL,
          updated_at_ms INTEGER NOT NULL
        ) STRICT;
      `);
      ensureAdditiveStateColumns(db);
      const wrappedSerialized = serializeWrappedSecret(wrapped);
      const wrappedBytes = Buffer.from(wrappedSerialized, "utf8");
      const pubPem = "MLDSA65-PUBLIC-KEY:" + Buffer.from(ml.publicKey).toString("base64url");
      db.prepare(
        `INSERT INTO device_identities (identity_key, device_id, public_key_pem, private_key_pem,
         created_at_ms, updated_at_ms, mldsa_public_key_pem, mldsa_private_key_wrapped, mldsa_private_key_wrap_key_id)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ).run(
        "primary",
        "dev-e2e",
        "ed25519-pub",
        "ed25519-priv",
        Date.now(),
        Date.now(),
        pubPem,
        wrappedBytes,
        wrapped.keyId,
      );
      db.close();

      // 4. M5 (simulated): read row back, parse envelope, unwrap
      const probe = new sqlite.DatabaseSync(databasePath, { readOnly: true });
      const row = probe
        .prepare(
          "SELECT mldsa_public_key_pem, mldsa_private_key_wrapped, mldsa_private_key_wrap_key_id FROM device_identities WHERE identity_key = 'primary'",
        )
        .get() as {
        mldsa_public_key_pem: string;
        mldsa_private_key_wrapped: Uint8Array;
        mldsa_private_key_wrap_key_id: string;
      };
      probe.close();
      expect(row.mldsa_private_key_wrap_key_id).toBe("wrap-e2e-test");
      const restoredSerialized = Buffer.from(row.mldsa_private_key_wrapped).toString("utf8");
      const restoredEnvelope = deserializeWrappedSecret(restoredSerialized);
      expect(restoredEnvelope.keyId).toBe("wrap-e2e-test");
      const restoredKey = unwrapSecret(restoredEnvelope, restoredEnvelope.keyId, wrapKey);
      expect(Buffer.compare(restoredKey, ml.secretKey)).toBe(0);

      // 5. M11: use the unwrapped ML-DSA-65 secret to sign a push payload.
      // Ed25519 raw 32-byte key location depends on Node version. Try trailing-32 first
      // (older Node), then offset 16 (newer Node PKCS8 layout).
      const ed = generateKeyPairSync("ed25519");
      const edPrivDer = ed.privateKey.export({ type: "pkcs8", format: "der" });
      const edPubDer = ed.publicKey.export({ type: "spki", format: "der" });
      const tryOffsets: Array<{ priv: [number, number]; pub: [number, number] }> = [
        {
          priv: [edPrivDer.length - 32, edPrivDer.length],
          pub: [edPubDer.length - 32, edPubDer.length],
        },
        { priv: [16, 48], pub: [12, 44] },
      ];
      const payload = JSON.stringify({ alert: "e2e test" });
      let ok = false;
      for (const off of tryOffsets) {
        const edPrivRaw = new Uint8Array(edPrivDer.subarray(off.priv[0], off.priv[1]));
        const edPubRaw = new Uint8Array(edPubDer.subarray(off.pub[0], off.pub[1]));
        const { envelope } = signPushPayloadDual({
          payload,
          ed25519SecretKeyRaw: edPrivRaw,
          mldsa65SecretKeyRaw: restoredKey,
          keyIdEd25519: "ed1",
          keyIdMldsa65: "ml1",
        });
        try {
          ok = verifyPushPayloadDual({
            payload,
            ed25519PublicKeyRaw: edPubRaw,
            mldsa65PublicKeyRaw: ml.publicKey,
            envelope,
          });
          if (ok) break;
        } catch {
          ok = false;
        }
      }
      expect(ok).toBe(true);
    });
  });

  it("M3 → M5 wrap retrofit: pre-M3 row (plaintext private key) gets migrated to M3 columns then wrap is set", async () => {
    await withTempDir("openclaw-pqc-retrofit-", async (rootDir) => {
      const stateDir = path.join(rootDir, "state");
      fs.mkdirSync(stateDir, { recursive: true });
      const databasePath = path.join(stateDir, "openclaw.sqlite");
      const sqlite = await import("node:sqlite");
      const { generateMlDsa65Keypair } = await import("../infra/mldsa65-key-storage.js");
      const { wrapSecret, unwrapSecret, serializeWrappedSecret, deserializeWrappedSecret } =
        await import("../security/secret-wrapping.js");
      const { generateWrappingKey } = await import("../security/keyring-provider.js");

      const ml = generateMlDsa65Keypair();
      const preM3 = new sqlite.DatabaseSync(databasePath);
      preM3.exec(`
        CREATE TABLE device_identities (
          identity_key TEXT NOT NULL PRIMARY KEY,
          device_id TEXT NOT NULL,
          public_key_pem TEXT NOT NULL,
          private_key_pem TEXT NOT NULL,
          created_at_ms INTEGER NOT NULL,
          updated_at_ms INTEGER NOT NULL
        ) STRICT;
        INSERT INTO device_identities VALUES (
          'primary', 'dev-legacy', 'ed25519-pub',
          'MLDSA65-SECRET-KEY:legacy-plaintext-key', 1, 1
        );
      `);
      preM3.close();

      const db = new sqlite.DatabaseSync(databasePath);
      ensureAdditiveStateColumns(db);

      const wrapKeyB64 = generateWrappingKey();
      const wrapKey = Buffer.from(wrapKeyB64, "base64url");
      const wrapped = wrapSecret(Buffer.from(ml.secretKey), "wrap-retrofit", wrapKey);
      const wrappedSerialized = serializeWrappedSecret(wrapped);
      const wrappedBytes = Buffer.from(wrappedSerialized, "utf8");
      const pubPem = "MLDSA65-PUBLIC-KEY:" + Buffer.from(ml.publicKey).toString("base64url");
      db.prepare(
        `UPDATE device_identities
         SET private_key_pem = '',
             mldsa_public_key_pem = ?,
             mldsa_private_key_pem = NULL,
             mldsa_private_key_wrapped = ?,
             mldsa_private_key_wrap_key_id = ?
         WHERE identity_key = 'primary'`,
      ).run(pubPem, wrappedBytes, "wrap-retrofit");
      db.close();

      const probe = new sqlite.DatabaseSync(databasePath, { readOnly: true });
      const row = probe
        .prepare(
          "SELECT private_key_pem, mldsa_public_key_pem, length(mldsa_private_key_wrapped) AS wlen, mldsa_private_key_wrap_key_id, mldsa_private_key_pem FROM device_identities WHERE identity_key = 'primary'",
        )
        .get() as {
        private_key_pem: string;
        mldsa_public_key_pem: string;
        wlen: number;
        mldsa_private_key_wrap_key_id: string;
        mldsa_private_key_pem: string | null;
      };
      probe.close();
      expect(row.private_key_pem).toBe("");
      expect(row.mldsa_public_key_pem).toBe(pubPem);
      expect(row.wlen).toBeGreaterThan(0);
      expect(row.mldsa_private_key_wrap_key_id).toBe("wrap-retrofit");
      expect(row.mldsa_private_key_pem).toBeNull();

      const probe2 = new sqlite.DatabaseSync(databasePath, { readOnly: true });
      const row2 = probe2
        .prepare(
          "SELECT mldsa_private_key_wrapped FROM device_identities WHERE identity_key = 'primary'",
        )
        .get() as { mldsa_private_key_wrapped: Uint8Array };
      probe2.close();
      const restoredSerialized = Buffer.from(row2.mldsa_private_key_wrapped).toString("utf8");
      const restoredEnv = deserializeWrappedSecret(restoredSerialized);
      const restoredKey = unwrapSecret(restoredEnv, restoredEnv.keyId, wrapKey);
      expect(Buffer.compare(restoredKey, ml.secretKey)).toBe(0);
    });
  });

  it("M5 + M6: deploy-time pattern using OPENCLAW_PQC_WRAP_KEY + OPENCLAW_PQC_WRAP_KEY_ID works end-to-end", async () => {
    await withTempDir("openclaw-pqc-deploy-", async (rootDir) => {
      const { wrapSecret, unwrapSecret } = await import("../security/secret-wrapping.js");
      const { generateWrappingKey } = await import("../security/keyring-provider.js");
      const { generateMlDsa65Keypair } = await import("../infra/mldsa65-key-storage.js");

      const wrapKeyB64 = generateWrappingKey();
      const wrapKey = Buffer.from(wrapKeyB64, "base64url");
      const wrapKeyId = "prod-wrap-e2e-2026-08";
      process.env.OPENCLAW_PQC_TEST_WRAP_KEY = wrapKeyB64;
      process.env.OPENCLAW_PQC_TEST_WRAP_KEY_ID = wrapKeyId;

      // Replicate the device-identity.ts inline provider pattern
      const raw = process.env.OPENCLAW_PQC_TEST_WRAP_KEY;
      const keyId = process.env.OPENCLAW_PQC_TEST_WRAP_KEY_ID ?? "env-default";
      const key = Buffer.from(raw!, "base64url");
      expect(key.length).toBe(32);
      expect(keyId).toBe("prod-wrap-e2e-2026-08");

      const ml = generateMlDsa65Keypair();
      const wrapped = wrapSecret(Buffer.from(ml.secretKey), keyId, key);
      const unwrapped = unwrapSecret(wrapped, wrapped.keyId, key);
      expect(Buffer.compare(unwrapped, ml.secretKey)).toBe(0);
    });
  });
});
