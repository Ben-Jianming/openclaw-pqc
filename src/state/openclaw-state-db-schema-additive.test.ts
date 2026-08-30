// M3 (PQC migration, whitepaper 2.1.3 + 2.2.1): schema-additive invariants for
// the 4 new ML-DSA-65 columns on `device_identities`.
//
// These tests verify the additive ALTER TABLE behavior: an existing pre-M3 row
// (with NULL mldsa_* columns) keeps working under a downgraded build, while
// an M3 build fills the columns when it generates a fresh ML-DSA-65 identity.
import fs from "node:fs";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { withTempDir } from "../test-utils/temp-dir.js";
import { ensureAdditiveStateColumns } from "./openclaw-state-db-schema-additive.js";
import {
  closeOpenClawStateDatabaseForTest,
  openOpenClawStateDatabase,
  runOpenClawStateWriteTransaction,
} from "./openclaw-state-db.js";

afterEach(() => {
  closeOpenClawStateDatabaseForTest();
});

function freshStatePath(rootDir: string): string {
  return path.join(rootDir, "state", "openclaw.sqlite");
}

async function openDbWithM3Columns(databasePath: string) {
  const database = openOpenClawStateDatabase({ path: databasePath });
  runOpenClawStateWriteTransaction(
    ({ db }) => {
      ensureAdditiveStateColumns(db);
    },
    { path: databasePath },
    { operationLabel: "schema-additive.m3" },
  );
  return database;
}

describe("device_identities schema additive (M3, whitepaper 2.1.3)", () => {
  it("adds the 4 ML-DSA-65 columns to a fresh database", async () => {
    await withTempDir("openclaw-m3-additive-", async (rootDir) => {
      const databasePath = freshStatePath(rootDir);
      fs.mkdirSync(path.dirname(databasePath), { recursive: true });
      const database = openOpenClawStateDatabase({ path: databasePath });
      // Force the canonical schema to land first; the additive columns are
      // injected by the migration pass.
      const sqlite = await import("node:sqlite");
      const db = new sqlite.DatabaseSync(databasePath);
      ensureAdditiveStateColumns(db);
      db.close();

      const probe = new sqlite.DatabaseSync(databasePath, { readOnly: true });
      const columns = (
        probe.prepare("PRAGMA table_info(device_identities)").all() as Array<{ name: string }>
      ).map((row) => row.name);
      expect(columns).toContain("mldsa_public_key_pem");
      expect(columns).toContain("mldsa_private_key_pem");
      expect(columns).toContain("mldsa_private_key_wrapped");
      expect(columns).toContain("mldsa_private_key_wrap_key_id");
      // Legacy columns are untouched.
      expect(columns).toContain("public_key_pem");
      expect(columns).toContain("private_key_pem");
      probe.close();
    });
  });

  it("is idempotent — re-running ensureAdditiveStateColumns does not double-add", async () => {
    await withTempDir("openclaw-m3-additive-idem-", async (rootDir) => {
      const databasePath = freshStatePath(rootDir);
      fs.mkdirSync(path.dirname(databasePath), { recursive: true });
      const sqlite = await import("node:sqlite");
      // Build a device_identities table first (mirrors a real downgraded fork
      // that already had the canonical schema but no additive columns).
      const seed = new sqlite.DatabaseSync(databasePath);
      seed.exec(`
        CREATE TABLE device_identities (
          identity_key TEXT NOT NULL PRIMARY KEY,
          device_id TEXT NOT NULL,
          public_key_pem TEXT NOT NULL,
          private_key_pem TEXT NOT NULL,
          created_at_ms INTEGER NOT NULL,
          updated_at_ms INTEGER NOT NULL
        ) STRICT;
      `);
      seed.close();

      const first = new sqlite.DatabaseSync(databasePath);
      ensureAdditiveStateColumns(first);
      first.close();

      const second = new sqlite.DatabaseSync(databasePath);
      ensureAdditiveStateColumns(second);
      second.close();

      const probe = new sqlite.DatabaseSync(databasePath, { readOnly: true });
      const columns = (
        probe.prepare("PRAGMA table_info(device_identities)").all() as Array<{ name: string }>
      ).map((row) => row.name);
      const mldsaCount = columns.filter((n) => n.startsWith("mldsa_")).length;
      expect(mldsaCount).toBe(4);
      probe.close();
    });
  });

  it("leaves a pre-M3 row readable (mldsa_* columns stay NULL)", async () => {
    await withTempDir("openclaw-m3-additive-legacy-", async (rootDir) => {
      const databasePath = freshStatePath(rootDir);
      fs.mkdirSync(path.dirname(databasePath), { recursive: true });
      const sqlite = await import("node:sqlite");
      // Simulate a pre-M3 fork by writing a row with only the legacy columns.
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
        INSERT INTO device_identities
          (identity_key, device_id, public_key_pem, private_key_pem, created_at_ms, updated_at_ms)
          VALUES ('primary', 'legacydeviceid', 'MLDSA65-PUBLIC-KEY:legacy', 'MLDSA65-SECRET-KEY:legacy', 1, 1);
      `);
      db.close();

      // Run the additive migration; this should add the 4 columns and
      // leave the existing row readable with NULL mldsa_* values.
      const migrated = new sqlite.DatabaseSync(databasePath);
      ensureAdditiveStateColumns(migrated);
      migrated.close();

      const probe = new sqlite.DatabaseSync(databasePath, { readOnly: true });
      const row = probe
        .prepare(
          "SELECT identity_key, device_id, public_key_pem, mldsa_public_key_pem, mldsa_private_key_pem, mldsa_private_key_wrapped, mldsa_private_key_wrap_key_id FROM device_identities WHERE identity_key = 'primary'",
        )
        .get() as Record<string, unknown>;
      probe.close();

      expect(row.identity_key).toBe("primary");
      expect(row.device_id).toBe("legacydeviceid");
      expect(row.public_key_pem).toBe("MLDSA65-PUBLIC-KEY:legacy");
      expect(row.mldsa_public_key_pem).toBeNull();
      expect(row.mldsa_private_key_pem).toBeNull();
      expect(row.mldsa_private_key_wrapped).toBeNull();
      expect(row.mldsa_private_key_wrap_key_id).toBeNull();
    });
  });

  it("accepts a fresh ML-DSA-65 row written through the additive columns", async () => {
    await withTempDir("openclaw-m3-additive-write-", async (rootDir) => {
      const databasePath = freshStatePath(rootDir);
      fs.mkdirSync(path.dirname(databasePath), { recursive: true });
      const sqlite = await import("node:sqlite");
      const db = new sqlite.DatabaseSync(databasePath);
      ensureAdditiveStateColumns(db);
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
      // Re-run the additive migration so it ALTERs the just-created table.
      ensureAdditiveStateColumns(db);
      db.exec(`
        INSERT INTO device_identities
          (identity_key, device_id, public_key_pem, private_key_pem,
           created_at_ms, updated_at_ms,
           mldsa_public_key_pem, mldsa_private_key_pem,
           mldsa_private_key_wrap_key_id, mldsa_private_key_wrapped)
          VALUES ('primary', 'freshid', 'old-pub', 'old-priv', 1, 1,
                  'MLDSA65-PUBLIC-KEY:fresh', 'MLDSA65-SECRET-KEY:fresh',
                  'wrap-key-2026-08', X'deadbeef');
      `);
      db.close();

      const probe = new sqlite.DatabaseSync(databasePath, { readOnly: true });
      const row = probe
        .prepare(
          "SELECT mldsa_public_key_pem, mldsa_private_key_pem, mldsa_private_key_wrap_key_id, mldsa_private_key_wrapped FROM device_identities WHERE identity_key = 'primary'",
        )
        .get() as Record<string, unknown>;
      probe.close();
      expect(row.mldsa_public_key_pem).toBe("MLDSA65-PUBLIC-KEY:fresh");
      expect(row.mldsa_private_key_pem).toBe("MLDSA65-SECRET-KEY:fresh");
      expect(row.mldsa_private_key_wrap_key_id).toBe("wrap-key-2026-08");
      expect(row.mldsa_private_key_wrapped).toBeInstanceOf(Uint8Array);
      expect(Array.from(row.mldsa_private_key_wrapped as Uint8Array)).toEqual([
        0xde, 0xad, 0xbe, 0xef,
      ]);
    });
  });
});
