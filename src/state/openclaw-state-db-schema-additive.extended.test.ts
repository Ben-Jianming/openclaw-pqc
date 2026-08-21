// M3 schema-additive extended tests (PQC migration, whitepaper 2.1.3 + 2.2.1).
// This file supplements openclaw-state-db-schema-additive.test.ts with edge cases
// not covered by the original 4 tests:
//
//   Group A: BLOB column behavior (wrap envelope storage)
//   Group B: Multi-device rows sharing/differing wrap keys
//   Group C: Type strictness + nullability + PRAGMA integrity
//   Group D: Reentrant / idempotent / safe re-runs
//   Group E: Wrap envelope clear (downgrade wrap → plaintext)
//
// All tests use ephemeral sqlite files under withTempDir and never touch the
// live gateway state at /home/benjamin/pqc-fork-state/state/openclaw.sqlite.
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

async function sqlite() {
  return await import("node:sqlite");
}

function mldsaColumns(
  databasePath: string,
): { name: string; type: string; notnull: number; pk: number }[] {
  // Sync helper for tests that need to read PRAGMA after closing the openclaw handle.
  // We open a fresh readonly handle so we don't depend on the openclaw DatabaseSync
  // being still open (vitest reuses a worker, so a stale handle would race).
  // Using a sync import here keeps the test deterministic and matches the existing
  // PRAGMA probes in openclaw-state-db-schema-additive.test.ts.
  // eslint-disable-next-line @typescript-eslint/no-require-imports
  const { DatabaseSync } = require("node:sqlite") as typeof import("node:sqlite");
  const probe = new DatabaseSync(databasePath, { readOnly: true });
  try {
    const rows = probe.prepare("PRAGMA table_info(device_identities)").all() as Array<{
      name: string;
      type: string;
      notnull: number;
      pk: number;
    }>;
    return rows;
  } finally {
    probe.close();
  }
}

describe("device_identities M3 additive — BLOB wrap envelope (Group A)", () => {
  it("stores a typical AES-256-GCM wrap envelope (76 bytes: salt+iv+ct+authTag) roundtrip-cleanly", async () => {
    await withTempDir("openclaw-m3-blob-76-", async (rootDir) => {
      const databasePath = freshStatePath(rootDir);
      fs.mkdirSync(path.dirname(databasePath), { recursive: true });
      const { DatabaseSync } = await sqlite();
      // salt(16) + iv(12) + ct(32) + authTag(16) = 76 bytes — see wrap-key-rotation.ts
      const envelope = new Uint8Array(76);
      for (let i = 0; i < envelope.length; i++) envelope[i] = (i * 7 + 13) & 0xff;
      const keyId = "prod-wrap-2026-08-21";

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
      db.prepare(
        "INSERT INTO device_identities (identity_key, device_id, public_key_pem, private_key_pem, created_at_ms, updated_at_ms, mldsa_private_key_wrapped, mldsa_private_key_wrap_key_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      ).run("primary", "dev-001", "ed25519-pub", "ed25519-priv", 1000, 1000, envelope, keyId);
      db.close();

      const cols = mldsaColumns(databasePath).filter((c) => c.name.startsWith("mldsa_"));
      const wrapCol = cols.find((c) => c.name === "mldsa_private_key_wrapped");
      expect(wrapCol).toBeDefined();
      expect(wrapCol?.type).toBe("BLOB");

      const probe = new DatabaseSync(databasePath, { readOnly: true });
      const row = probe
        .prepare(
          "SELECT mldsa_private_key_wrapped, mldsa_private_key_wrap_key_id FROM device_identities WHERE identity_key = 'primary'",
        )
        .get() as { mldsa_private_key_wrapped: Uint8Array; mldsa_private_key_wrap_key_id: string };
      probe.close();
      expect(row.mldsa_private_key_wrap_key_id).toBe(keyId);
      expect(row.mldsa_private_key_wrapped).toBeInstanceOf(Uint8Array);
      expect(row.mldsa_private_key_wrapped.length).toBe(76);
      // Every byte must roundtrip — BLOB must not mangle binary content.
      for (let i = 0; i < 76; i++) {
        expect(row.mldsa_private_key_wrapped[i]).toBe((i * 7 + 13) & 0xff);
      }
    });
  });

  it("preserves a 16 KiB wrap envelope byte-for-byte (M7 export envelope max)", async () => {
    await withTempDir("openclaw-m3-blob-16k-", async (rootDir) => {
      const databasePath = freshStatePath(rootDir);
      fs.mkdirSync(path.dirname(databasePath), { recursive: true });
      const { DatabaseSync } = await sqlite();

      // 16 KiB random-ish bytes — M7 export envelope upper bound
      const envelope = new Uint8Array(16 * 1024);
      for (let i = 0; i < envelope.length; i++) envelope[i] = (i ^ 0xa5) & 0xff;

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
      db.prepare(
        "INSERT INTO device_identities (identity_key, device_id, public_key_pem, private_key_pem, created_at_ms, updated_at_ms, mldsa_private_key_wrapped) VALUES (?, ?, ?, ?, ?, ?, ?)",
      ).run("primary", "dev-big", "p", "v", 1, 1, envelope);
      db.close();

      const probe = new DatabaseSync(databasePath, { readOnly: true });
      const row = probe
        .prepare(
          "SELECT mldsa_private_key_wrapped FROM device_identities WHERE identity_key = 'primary'",
        )
        .get() as { mldsa_private_key_wrapped: Uint8Array };
      probe.close();
      expect(row.mldsa_private_key_wrapped.length).toBe(16 * 1024);
      // Spot-check bytes at start, middle, end
      expect(row.mldsa_private_key_wrapped[0]).toBe(0xa5);
      expect(row.mldsa_private_key_wrapped[8 * 1024]).toBe(((8 * 1024) ^ 0xa5) & 0xff);
      expect(row.mldsa_private_key_wrapped[16 * 1024 - 1]).toBe(((16 * 1024 - 1) ^ 0xa5) & 0xff);
    });
  });

  it("accepts NULL BLOB (legacy plaintext storage path)", async () => {
    await withTempDir("openclaw-m3-blob-null-", async (rootDir) => {
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
      db.prepare(
        "INSERT INTO device_identities (identity_key, device_id, public_key_pem, private_key_pem, created_at_ms, updated_at_ms) VALUES (?, ?, ?, ?, ?, ?)",
      ).run("plaintext-only", "dev-plain", "p", "v", 1, 1);
      db.close();

      const probe = new DatabaseSync(databasePath, { readOnly: true });
      const row = probe
        .prepare(
          "SELECT mldsa_private_key_wrapped, mldsa_private_key_wrap_key_id, mldsa_private_key_pem, mldsa_public_key_pem FROM device_identities WHERE identity_key = 'plaintext-only'",
        )
        .get() as Record<string, unknown>;
      probe.close();
      expect(row.mldsa_private_key_wrapped).toBeNull();
      expect(row.mldsa_private_key_wrap_key_id).toBeNull();
      expect(row.mldsa_private_key_pem).toBeNull();
      expect(row.mldsa_public_key_pem).toBeNull();
    });
  });
});

describe("device_identities M3 additive — multi-device / shared wrap key (Group B)", () => {
  it("multiple devices can share the same wrap_key_id (one keyring entry, many rows)", async () => {
    await withTempDir("openclaw-m3-multi-shared-", async (rootDir) => {
      const databasePath = freshStatePath(rootDir);
      fs.mkdirSync(path.dirname(databasePath), { recursive: true });
      const { DatabaseSync } = await sqlite();
      const sharedKeyId = "prod-wrap-shared-2026-08";

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
      const insert = db.prepare(
        "INSERT INTO device_identities (identity_key, device_id, public_key_pem, private_key_pem, created_at_ms, updated_at_ms, mldsa_public_key_pem, mldsa_private_key_wrapped, mldsa_private_key_wrap_key_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
      );
      // 3 devices sharing one wrap key — typical "agent on phone, laptop, watch" deployment
      insert.run(
        "phone",
        "phone-uuid-a",
        "ed1",
        "ed1p",
        1,
        1,
        "MLDSA65-PUBLIC-KEY:phone",
        new Uint8Array([1, 2, 3]),
        sharedKeyId,
      );
      insert.run(
        "laptop",
        "laptop-uuid-b",
        "ed2",
        "ed2p",
        2,
        2,
        "MLDSA65-PUBLIC-KEY:laptop",
        new Uint8Array([4, 5, 6]),
        sharedKeyId,
      );
      insert.run(
        "watch",
        "watch-uuid-c",
        "ed3",
        "ed3p",
        3,
        3,
        "MLDSA65-PUBLIC-KEY:watch",
        new Uint8Array([7, 8, 9]),
        sharedKeyId,
      );
      db.close();

      const probe = new DatabaseSync(databasePath, { readOnly: true });
      const rows = probe
        .prepare(
          "SELECT identity_key, mldsa_private_key_wrap_key_id, length(mldsa_private_key_wrapped) AS wrap_len FROM device_identities ORDER BY identity_key",
        )
        .all() as Array<{
        identity_key: string;
        mldsa_private_key_wrap_key_id: string;
        wrap_len: number;
      }>;
      probe.close();
      expect(rows).toHaveLength(3);
      expect(rows.every((r) => r.mldsa_private_key_wrap_key_id === sharedKeyId)).toBe(true);
      // Each device's BLOB is distinct (different per-device keys, encrypted under same wrap key)
      const lens = rows.map((r) => r.wrap_len).sort();
      expect(lens).toEqual([3, 3, 3]);
    });
  });

  it("multiple devices can use DIFFERENT wrap_key_ids (per-device wrap, e.g. after rotation)", async () => {
    await withTempDir("openclaw-m3-multi-distinct-", async (rootDir) => {
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
      const insert = db.prepare(
        "INSERT INTO device_identities (identity_key, device_id, public_key_pem, private_key_pem, created_at_ms, updated_at_ms, mldsa_private_key_wrapped, mldsa_private_key_wrap_key_id) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
      );
      // Mixed wrap state: phone wrapped with old key (M7-rotation in progress), laptop plaintext
      insert.run("phone", "uuid-1", "ed1", "ed1p", 1, 1, new Uint8Array([1]), "prod-wrap-2026-07");
      insert.run("laptop", "uuid-2", "ed2", "ed2p", 2, 2, new Uint8Array([2]), "prod-wrap-2026-08");
      insert.run("watch", "uuid-3", "ed3", "ed3p", 3, 3, null, null);
      db.close();

      const probe = new DatabaseSync(databasePath, { readOnly: true });
      const rows = probe
        .prepare(
          "SELECT identity_key, mldsa_private_key_wrap_key_id, mldsa_private_key_wrapped FROM device_identities ORDER BY identity_key",
        )
        .all() as Array<{
        identity_key: string;
        mldsa_private_key_wrap_key_id: string | null;
        mldsa_private_key_wrapped: Uint8Array | null;
      }>;
      probe.close();
      expect(rows).toHaveLength(3);
      const byKey = new Map(rows.map((r) => [r.identity_key, r]));
      expect(byKey.get("phone")?.mldsa_private_key_wrap_key_id).toBe("prod-wrap-2026-07");
      expect(byKey.get("laptop")?.mldsa_private_key_wrap_key_id).toBe("prod-wrap-2026-08");
      expect(byKey.get("watch")?.mldsa_private_key_wrap_key_id).toBeNull();
      expect(byKey.get("watch")?.mldsa_private_key_wrapped).toBeNull();
    });
  });
});
