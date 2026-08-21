// M3 schema-additive — Batch 2: type strictness, idempotency, envelope clear.
// Extends openclaw-state-db-schema-additive.extended.test.ts (Batch 1) and
// the original 4 tests in openclaw-state-db-schema-additive.test.ts.
//
// Group C: Type strictness (column types match PRAGMA, NOT NULL contracts)
// Group D: Reentrant / safe re-runs (idempotency, post-M3 no-op)
// Group E: Wrap envelope clear (downgrade wrap → plaintext)
import fs from "node:fs";
import path from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { withTempDir } from "../test-utils/temp-dir.js";
import { ensureAdditiveStateColumns } from "./openclaw-state-db-schema-additive.js";
import { closeOpenClawStateDatabaseForTest } from "./openclaw-state-db.js";

afterEach(() => {
  closeOpenClawStateDatabaseForTest();
});

function freshStatePath(rootDir: string): string {
  return path.join(rootDir, "state", "openclaw.sqlite");
}

async function sqlite() {
  return await import("node:sqlite");
}

function makeLegacyTableWithRow(
  databasePath: string,
  keyId: string | null,
  wrap: Uint8Array | null,
): void {
  // Pre-M3 schema (6 columns) seeded with one row. Migration must be applied
  // BEFORE the UPDATE below; the mldsa_* columns don't exist on the pre-M3
  // table. We never touch /home/benjamin/pqc-fork-state — every test owns a
  // fresh temp dir.
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { DatabaseSync } = require("node:sqlite") as typeof import("node:sqlite");
  const seed = new DatabaseSync(databasePath);
  seed.exec(`
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
      VALUES ('primary', 'dev-1', 'ed25519-pub', 'ed25519-priv', 1, 1);
  `);
  // Run the additive migration first so mldsa_* columns exist.
  ensureAdditiveStateColumns(seed);
  // Now we can simulate post-M5 by populating wrap state.
  if (keyId !== null) {
    seed
      .prepare(
        "UPDATE device_identities SET mldsa_private_key_wrap_key_id = ? WHERE identity_key = 'primary'",
      )
      .run(keyId);
  }
  if (wrap !== null) {
    seed
      .prepare(
        "UPDATE device_identities SET mldsa_private_key_wrapped = ? WHERE identity_key = 'primary'",
      )
      .run(wrap);
  }
  seed.close();
}

describe("device_identities M3 additive — type strictness (Group C)", () => {
  it("mldsa_private_key_wrapped is exactly BLOB type (not TEXT, not null)", async () => {
    await withTempDir("openclaw-m3-type-", async (rootDir) => {
      const databasePath = freshStatePath(rootDir);
      fs.mkdirSync(path.dirname(databasePath), { recursive: true });
      const { DatabaseSync } = await sqlite();
      const db = new DatabaseSync(databasePath);
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
      db.close();

      const probe = new DatabaseSync(databasePath, { readOnly: true });
      const cols = probe.prepare("PRAGMA table_info(device_identities)").all() as Array<{
        name: string;
        type: string;
        notnull: number;
        pk: number;
      }>;
      probe.close();
      const wrap = cols.find((c) => c.name === "mldsa_private_key_wrapped");
      expect(wrap).toBeDefined();
      expect(wrap?.type).toBe("BLOB");
      expect(wrap?.notnull).toBe(0); // nullable
      expect(wrap?.pk).toBe(0);
    });
  });

  it("mldsa_public_key_pem and mldsa_private_key_pem are exactly TEXT type", async () => {
    await withTempDir("openclaw-m3-type-text-", async (rootDir) => {
      const databasePath = freshStatePath(rootDir);
      fs.mkdirSync(path.dirname(databasePath), { recursive: true });
      const { DatabaseSync } = await sqlite();
      const db = new DatabaseSync(databasePath);
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
      db.close();

      const probe = new DatabaseSync(databasePath, { readOnly: true });
      const cols = probe.prepare("PRAGMA table_info(device_identities)").all() as Array<{
        name: string;
        type: string;
        notnull: number;
        pk: number;
      }>;
      probe.close();
      for (const name of [
        "mldsa_public_key_pem",
        "mldsa_private_key_pem",
        "mldsa_private_key_wrap_key_id",
      ]) {
        const col = cols.find((c) => c.name === name);
        expect(col, `column ${name} should exist`).toBeDefined();
        expect(col?.type, `column ${name} should be TEXT`).toBe("TEXT");
        expect(col?.notnull, `column ${name} should be nullable`).toBe(0);
      }
    });
  });

  it("all 4 ML-DSA-65 columns are nullable (insert with all NULLs succeeds)", async () => {
    await withTempDir("openclaw-m3-nullable-", async (rootDir) => {
      const databasePath = freshStatePath(rootDir);
      fs.mkdirSync(path.dirname(databasePath), { recursive: true });
      const { DatabaseSync } = await sqlite();
      const db = new DatabaseSync(databasePath);
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
      // Insert a row with ALL 4 mldsa columns explicitly NULL.
      expect(() =>
        db
          .prepare(
            "INSERT INTO device_identities (identity_key, device_id, public_key_pem, private_key_pem, created_at_ms, updated_at_ms) VALUES (?, ?, ?, ?, ?, ?)",
          )
          .run("primary", "dev-1", "p", "v", 1, 1),
      ).not.toThrow();
      db.close();

      const probe = new DatabaseSync(databasePath, { readOnly: true });
      const row = probe
        .prepare(
          "SELECT mldsa_public_key_pem, mldsa_private_key_pem, mldsa_private_key_wrapped, mldsa_private_key_wrap_key_id FROM device_identities WHERE identity_key = 'primary'",
        )
        .get() as Record<string, unknown>;
      probe.close();
      expect(row.mldsa_public_key_pem).toBeNull();
      expect(row.mldsa_private_key_pem).toBeNull();
      expect(row.mldsa_private_key_wrapped).toBeNull();
      expect(row.mldsa_private_key_wrap_key_id).toBeNull();
    });
  });

  it("PRAGMA integrity_check passes after M3 migration on a pre-M3 row", async () => {
    await withTempDir("openclaw-m3-integrity-", async (rootDir) => {
      const databasePath = freshStatePath(rootDir);
      fs.mkdirSync(path.dirname(databasePath), { recursive: true });
      makeLegacyTableWithRow(databasePath, "wrap-2026-08", new Uint8Array([1, 2, 3, 4, 5]));
      const { DatabaseSync } = await sqlite();
      const db = new DatabaseSync(databasePath);
      ensureAdditiveStateColumns(db);
      db.close();

      const probe = new DatabaseSync(databasePath, { readOnly: true });
      const result = probe.prepare("PRAGMA integrity_check").all() as Array<{
        integrity_check: string;
      }>;
      probe.close();
      expect(result).toEqual([{ integrity_check: "ok" }]);
    });
  });
});

describe("device_identities M3 additive — reentrant / idempotent (Group D)", () => {
  it("running ensureAdditiveStateColumns 5x produces a stable schema (column count + types)", async () => {
    await withTempDir("openclaw-m3-reentrant-", async (rootDir) => {
      const databasePath = freshStatePath(rootDir);
      fs.mkdirSync(path.dirname(databasePath), { recursive: true });
      const { DatabaseSync } = await sqlite();
      const db = new DatabaseSync(databasePath);
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

      for (let i = 0; i < 5; i++) {
        expect(() => ensureAdditiveStateColumns(db)).not.toThrow();
      }
      db.close();

      const probe = new DatabaseSync(databasePath, { readOnly: true });
      const cols = probe.prepare("PRAGMA table_info(device_identities)").all() as Array<{
        name: string;
        type: string;
      }>;
      probe.close();
      const mldsaCols = cols.filter((c) => c.name.startsWith("mldsa_"));
      expect(mldsaCols).toHaveLength(4);
      // No duplicates
      const names = mldsaCols.map((c) => c.name).sort();
      expect(names).toEqual([
        "mldsa_private_key_pem",
        "mldsa_private_key_wrap_key_id",
        "mldsa_private_key_wrapped",
        "mldsa_public_key_pem",
      ]);
    });
  });

  it("ensureAdditiveStateColumns is a no-op on already-M3 DB (no error, no schema change)", async () => {
    await withTempDir("openclaw-m3-noop-", async (rootDir) => {
      const databasePath = freshStatePath(rootDir);
      fs.mkdirSync(path.dirname(databasePath), { recursive: true });
      const { DatabaseSync } = await sqlite();
      const db = new DatabaseSync(databasePath);
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

      // Snapshot schema after 1st pass
      const cols1 = db.prepare("PRAGMA table_info(device_identities)").all() as Array<{
        name: string;
        cid: number;
      }>;
      const mldsaCount1 = cols1.filter((c) => c.name.startsWith("mldsa_")).length;
      expect(mldsaCount1).toBe(4);

      // Insert a row
      db.prepare(
        "INSERT INTO device_identities (identity_key, device_id, public_key_pem, private_key_pem, created_at_ms, updated_at_ms, mldsa_public_key_pem, mldsa_private_key_wrapped, mldsa_private_key_wrap_key_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
      ).run(
        "primary",
        "dev-1",
        "ed1",
        "ed1p",
        1,
        1,
        "MLDSA65-PUBLIC-KEY:abc",
        new Uint8Array([0xff]),
        "wrap-A",
      );

      // 2nd pass must not drop the row or alter columns
      expect(() => ensureAdditiveStateColumns(db)).not.toThrow();
      db.close();

      const probe = new DatabaseSync(databasePath, { readOnly: true });
      const cols2 = probe.prepare("PRAGMA table_info(device_identities)").all() as Array<{
        name: string;
        cid: number;
      }>;
      const mldsaCount2 = cols2.filter((c) => c.name.startsWith("mldsa_")).length;
      expect(mldsaCount2).toBe(4);
      const row = probe
        .prepare(
          "SELECT mldsa_public_key_pem, mldsa_private_key_wrap_key_id, length(mldsa_private_key_wrapped) AS wlen FROM device_identities WHERE identity_key = 'primary'",
        )
        .get() as {
        mldsa_public_key_pem: string;
        mldsa_private_key_wrap_key_id: string;
        wlen: number;
      };
      probe.close();
      expect(row.mldsa_public_key_pem).toBe("MLDSA65-PUBLIC-KEY:abc");
      expect(row.mldsa_private_key_wrap_key_id).toBe("wrap-A");
      expect(row.wlen).toBe(1);
    });
  });
});

describe("device_identities M3 additive — wrap envelope clear (Group E)", () => {
  it("clearing the wrap envelope (UPDATE → NULL) and re-wrapping with a new key_id works", async () => {
    await withTempDir("openclaw-m3-clear-", async (rootDir) => {
      const databasePath = freshStatePath(rootDir);
      fs.mkdirSync(path.dirname(databasePath), { recursive: true });
      const { DatabaseSync } = await sqlite();
      makeLegacyTableWithRow(databasePath, "wrap-A", new Uint8Array([1, 2, 3, 4]));
      const db = new DatabaseSync(databasePath);
      ensureAdditiveStateColumns(db);

      // Verify initial state
      const initial = db
        .prepare(
          "SELECT mldsa_private_key_wrap_key_id, length(mldsa_private_key_wrapped) AS wlen FROM device_identities WHERE identity_key = 'primary'",
        )
        .get() as { mldsa_private_key_wrap_key_id: string; wlen: number };
      expect(initial.mldsa_private_key_wrap_key_id).toBe("wrap-A");
      expect(initial.wlen).toBe(4);

      // Clear wrap envelope (downgrade wrap → plaintext storage path)
      db.prepare(
        "UPDATE device_identities SET mldsa_private_key_wrapped = NULL, mldsa_private_key_wrap_key_id = NULL WHERE identity_key = 'primary'",
      ).run();

      const cleared = db
        .prepare(
          "SELECT mldsa_private_key_wrapped, mldsa_private_key_wrap_key_id FROM device_identities WHERE identity_key = 'primary'",
        )
        .get() as { mldsa_private_key_wrapped: null; mldsa_private_key_wrap_key_id: null };
      expect(cleared.mldsa_private_key_wrapped).toBeNull();
      expect(cleared.mldsa_private_key_wrap_key_id).toBeNull();

      // Re-wrap with a new key_id (M7 rotation follow-up)
      const newEnvelope = new Uint8Array([10, 20, 30, 40, 50, 60, 70, 80]);
      db.prepare(
        "UPDATE device_identities SET mldsa_private_key_wrapped = ?, mldsa_private_key_wrap_key_id = ? WHERE identity_key = 'primary'",
      ).run(newEnvelope, "wrap-B-rotated");
      db.close();

      const probe = new DatabaseSync(databasePath, { readOnly: true });
      const rotated = probe
        .prepare(
          "SELECT mldsa_private_key_wrap_key_id, mldsa_private_key_wrapped FROM device_identities WHERE identity_key = 'primary'",
        )
        .get() as { mldsa_private_key_wrap_key_id: string; mldsa_private_key_wrapped: Uint8Array };
      probe.close();
      expect(rotated.mldsa_private_key_wrap_key_id).toBe("wrap-B-rotated");
      expect(Array.from(rotated.mldsa_private_key_wrapped)).toEqual([
        10, 20, 30, 40, 50, 60, 70, 80,
      ]);
    });
  });
});
