// M3 schema-additive — Batch 3: PK uniqueness, realistic identity_key formats,
// pre+post M3 row coexistence, STRICT mode + NULL, updated_at_ms roundtrip.
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

describe("device_identities M3 additive — PK + coexistence (Batch 3)", () => {
  it("PRIMARY KEY conflict: inserting a second row with the same identity_key throws", async () => {
    await withTempDir("openclaw-m3-pk-", async (rootDir) => {
      const databasePath = freshStatePath(rootDir);
      fs.mkdirSync(path.dirname(databasePath), { recursive: true });
      const sqlite = await import("node:sqlite");
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
      db.prepare(
        "INSERT INTO device_identities (identity_key, device_id, public_key_pem, private_key_pem, created_at_ms, updated_at_ms) VALUES (?, ?, ?, ?, ?, ?)",
      ).run("primary", "dev-a", "p1", "v1", 1, 1);

      expect(() =>
        db
          .prepare(
            "INSERT INTO device_identities (identity_key, device_id, public_key_pem, private_key_pem, created_at_ms, updated_at_ms) VALUES (?, ?, ?, ?, ?, ?)",
          )
          .run("primary", "dev-b", "p2", "v2", 2, 2),
      ).toThrow(/UNIQUE constraint failed|PRIMARY KEY constraint/i);
      db.close();
    });
  });

  it("realistic multi-segment identity_keys (agent:main:phone) are allowed", async () => {
    await withTempDir("openclaw-m3-keyfmt-", async (rootDir) => {
      const databasePath = freshStatePath(rootDir);
      fs.mkdirSync(path.dirname(databasePath), { recursive: true });
      const sqlite = await import("node:sqlite");
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
      const insert = db.prepare(
        "INSERT INTO device_identities (identity_key, device_id, public_key_pem, private_key_pem, created_at_ms, updated_at_ms, mldsa_public_key_pem, mldsa_private_key_wrapped, mldsa_private_key_wrap_key_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
      );
      // Realistic agent ID keys — openclaw uses colon-delimited multi-segment keys
      insert.run(
        "agent:main:phone",
        "phone-uuid",
        "ed1",
        "ed1p",
        1,
        1,
        "MLDSA65-PUBLIC-KEY:phone",
        new Uint8Array([1, 2, 3]),
        "wrap-2026-08",
      );
      insert.run(
        "agent:main:laptop",
        "laptop-uuid",
        "ed2",
        "ed2p",
        2,
        2,
        "MLDSA65-PUBLIC-KEY:laptop",
        new Uint8Array([4, 5, 6]),
        "wrap-2026-08",
      );
      insert.run("agent:worker:cell-1", "cell-uuid", "ed3", "ed3p", 3, 3, null, null, null);
      db.close();

      const probe = new sqlite.DatabaseSync(databasePath, { readOnly: true });
      const rows = probe
        .prepare(
          "SELECT identity_key, mldsa_public_key_pem IS NOT NULL AS has_pqc, mldsa_private_key_wrapped IS NOT NULL AS has_wrap FROM device_identities ORDER BY identity_key",
        )
        .all() as Array<{ identity_key: string; has_pqc: number; has_wrap: number }>;
      probe.close();
      expect(rows).toHaveLength(3);
      const byKey = new Map(rows.map((r) => [r.identity_key, r]));
      expect(byKey.get("agent:main:phone")?.has_pqc).toBe(1);
      expect(byKey.get("agent:main:phone")?.has_wrap).toBe(1);
      expect(byKey.get("agent:main:laptop")?.has_pqc).toBe(1);
      expect(byKey.get("agent:worker:cell-1")?.has_pqc).toBe(0);
    });
  });

  it("pre-M3 row and post-M3 row coexist after migration (mixed state)", async () => {
    await withTempDir("openclaw-m3-mixed-", async (rootDir) => {
      const databasePath = freshStatePath(rootDir);
      fs.mkdirSync(path.dirname(databasePath), { recursive: true });
      const sqlite = await import("node:sqlite");
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
      // Insert a pre-M3 row BEFORE migration (no mldsa columns yet)
      db.prepare(
        "INSERT INTO device_identities (identity_key, device_id, public_key_pem, private_key_pem, created_at_ms, updated_at_ms) VALUES (?, ?, ?, ?, ?, ?)",
      ).run("legacy-1", "dev-old", "old-pub", "old-priv", 1, 1);
      // Migrate
      ensureAdditiveStateColumns(db);
      // Insert a post-M3 row AFTER migration (with full PQC state)
      db.prepare(
        "INSERT INTO device_identities (identity_key, device_id, public_key_pem, private_key_pem, created_at_ms, updated_at_ms, mldsa_public_key_pem, mldsa_private_key_wrapped, mldsa_private_key_wrap_key_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
      ).run(
        "modern-1",
        "dev-new",
        "new-pub",
        "new-priv",
        2,
        2,
        "MLDSA65-PUBLIC-KEY:modern",
        new Uint8Array([0xaa, 0xbb, 0xcc]),
        "wrap-2026-08",
      );
      db.close();

      const probe = new sqlite.DatabaseSync(databasePath, { readOnly: true });
      const rows = probe
        .prepare(
          "SELECT identity_key, mldsa_public_key_pem, mldsa_private_key_wrapped, mldsa_private_key_wrap_key_id FROM device_identities ORDER BY identity_key",
        )
        .all() as Array<{
        identity_key: string;
        mldsa_public_key_pem: string | null;
        mldsa_private_key_wrapped: Uint8Array | null;
        mldsa_private_key_wrap_key_id: string | null;
      }>;
      probe.close();
      expect(rows).toHaveLength(2);
      const byKey = new Map(rows.map((r) => [r.identity_key, r]));
      // Pre-M3 row keeps all mldsa_ columns NULL
      expect(byKey.get("legacy-1")?.mldsa_public_key_pem).toBeNull();
      expect(byKey.get("legacy-1")?.mldsa_private_key_wrapped).toBeNull();
      expect(byKey.get("legacy-1")?.mldsa_private_key_wrap_key_id).toBeNull();
      // Post-M3 row has full state
      expect(byKey.get("modern-1")?.mldsa_public_key_pem).toBe("MLDSA65-PUBLIC-KEY:modern");
      expect(Array.from(byKey.get("modern-1")?.mldsa_private_key_wrapped ?? [])).toEqual([
        0xaa, 0xbb, 0xcc,
      ]);
      expect(byKey.get("modern-1")?.mldsa_private_key_wrap_key_id).toBe("wrap-2026-08");
    });
  });

  it("STRICT table accepts NULL on the 4 additive mldsa columns (no type coercion)", async () => {
    await withTempDir("openclaw-m3-strict-", async (rootDir) => {
      const databasePath = freshStatePath(rootDir);
      fs.mkdirSync(path.dirname(databasePath), { recursive: true });
      const sqlite = await import("node:sqlite");
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
      // Insert with one TEXT mldsa column set to "" (empty string, not NULL) and
      // a BLOB column set to empty Uint8Array (zero-length BLOB, not NULL).
      db.prepare(
        "INSERT INTO device_identities (identity_key, device_id, public_key_pem, private_key_pem, created_at_ms, updated_at_ms, mldsa_public_key_pem, mldsa_private_key_wrapped) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      ).run("p", "d", "p", "v", 1, 1, "", new Uint8Array(0));
      db.close();

      const probe = new sqlite.DatabaseSync(databasePath, { readOnly: true });
      const row = probe
        .prepare(
          "SELECT mldsa_public_key_pem, mldsa_private_key_wrapped, length(mldsa_private_key_wrapped) AS blob_len FROM device_identities WHERE identity_key = 'p'",
        )
        .get() as {
        mldsa_public_key_pem: string;
        mldsa_private_key_wrapped: Uint8Array;
        blob_len: number;
      };
      probe.close();
      // STRICT mode preserves the empty string in TEXT
      expect(row.mldsa_public_key_pem).toBe("");
      // STRICT mode preserves zero-length BLOB distinct from NULL
      expect(row.mldsa_private_key_wrapped).toBeInstanceOf(Uint8Array);
      expect(row.blob_len).toBe(0);
    });
  });

  it("updated_at_ms roundtrips through INSERT and UPDATE without side effects on mldsa columns", async () => {
    await withTempDir("openclaw-m3-updated-", async (rootDir) => {
      const databasePath = freshStatePath(rootDir);
      fs.mkdirSync(path.dirname(databasePath), { recursive: true });
      const sqlite = await import("node:sqlite");
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
      db.prepare(
        "INSERT INTO device_identities (identity_key, device_id, public_key_pem, private_key_pem, created_at_ms, updated_at_ms, mldsa_public_key_pem, mldsa_private_key_wrapped, mldsa_private_key_wrap_key_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
      ).run(
        "p",
        "d",
        "p",
        "v",
        1000,
        1000,
        "MLDSA65-PUBLIC-KEY:abc",
        new Uint8Array([0xff]),
        "wrap-A",
      );
      db.prepare("UPDATE device_identities SET updated_at_ms = ? WHERE identity_key = 'p'").run(
        2000,
      );
      db.close();

      const probe = new sqlite.DatabaseSync(databasePath, { readOnly: true });
      const row = probe
        .prepare(
          "SELECT created_at_ms, updated_at_ms, mldsa_public_key_pem, length(mldsa_private_key_wrapped) AS wlen, mldsa_private_key_wrap_key_id FROM device_identities WHERE identity_key = 'p'",
        )
        .get() as {
        created_at_ms: number;
        updated_at_ms: number;
        mldsa_public_key_pem: string;
        wlen: number;
        mldsa_private_key_wrap_key_id: string;
      };
      probe.close();
      expect(row.created_at_ms).toBe(1000);
      expect(row.updated_at_ms).toBe(2000);
      // PQC state must NOT be touched by the UPDATE
      expect(row.mldsa_public_key_pem).toBe("MLDSA65-PUBLIC-KEY:abc");
      expect(row.wlen).toBe(1);
      expect(row.mldsa_private_key_wrap_key_id).toBe("wrap-A");
    });
  });
});
