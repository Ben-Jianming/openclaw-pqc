import { createHash, randomBytes } from "node:crypto";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { describe, expect, it } from "vitest";
import { closeOpenClawStateDatabaseForTest } from "../state/openclaw-state-db.js";
import { withTempDir } from "../test-utils/temp-dir.js";
import {
  generateStoredDeviceIdentity,
  insertStoredDeviceIdentityIfAbsent,
  readStoredDeviceIdentity,
  repairInvalidStoredDeviceIdentity,
  type SyncWrappingKeyProvider,
} from "./device-identity-store.js";
import { repairInvalidCanonicalIdentity } from "./state-migrations.device-identity-repair.js";

function digestRow(databasePath: string): string {
  const db = new DatabaseSync(databasePath, { readOnly: true });
  try {
    return createHash("sha256")
      .update(JSON.stringify(db.prepare("SELECT * FROM device_identities").all()))
      .digest("hex");
  } finally {
    db.close();
  }
}

describe("Doctor preserves wrapped identity on unavailable wrapping material", () => {
  it.each(["missing-key-id", "empty-key-id", "missing-envelope", "empty-envelope"])(
    "preserves an incomplete wrapping tuple: %s",
    async (mode) => {
      await withTempDir("openclaw-doctor-wrap-metadata-", async (directory) => {
        try {
          const keyId = "doctor-metadata-test";
          const key = randomBytes(32);
          const provider: SyncWrappingKeyProvider = {
            getActiveKey: () => ({ keyId, key }),
            getKeyById: (id) => (id === keyId ? { keyId, key } : null),
          };
          const options = {
            env: { ...process.env, OPENCLAW_STATE_DIR: directory },
            path: path.join(directory, "state", "openclaw.sqlite"),
          };
          const original = generateStoredDeviceIdentity({ wrappingKeyProvider: provider });
          insertStoredDeviceIdentityIfAbsent(original, {
            ...options,
            wrappingKeyProvider: provider,
          });
          closeOpenClawStateDatabaseForTest();
          const db = new DatabaseSync(options.path);
          try {
            if (mode.endsWith("key-id")) {
              db.prepare("UPDATE device_identities SET mldsa_private_key_wrap_key_id = ?").run(
                mode === "missing-key-id" ? null : "",
              );
            } else {
              db.prepare("UPDATE device_identities SET mldsa_private_key_wrapped = ?").run(
                mode === "missing-envelope" ? null : Buffer.alloc(0),
              );
            }
          } finally {
            db.close();
          }
          const before = digestRow(options.path);
          expect(() =>
            repairInvalidStoredDeviceIdentity(generateStoredDeviceIdentity(), {
              ...options,
              wrappingKeyProvider: provider,
            }),
          ).toThrow(/incomplete wrapping metadata/);
          closeOpenClawStateDatabaseForTest();
          expect(digestRow(options.path)).toBe(before);
          const restore = new DatabaseSync(options.path);
          try {
            restore
              .prepare(
                "UPDATE device_identities SET mldsa_private_key_wrap_key_id = ?, mldsa_private_key_wrapped = ?",
              )
              .run(keyId, Buffer.from(original.mldsaPrivateKeyWrapped!));
          } finally {
            restore.close();
          }
          expect(
            readStoredDeviceIdentity({ ...options, wrappingKeyProvider: provider })?.deviceId,
          ).toBe(original.deviceId);
        } finally {
          closeOpenClawStateDatabaseForTest();
        }
      });
    },
  );

  it.each(["no-provider", "unknown-key-id", "wrong-key", "doctor-no-provider"])(
    "%s",
    async (mode) => {
      await withTempDir("openclaw-doctor-wrap-preserve-", async (directory) => {
        try {
          const keyId = "doctor-preservation-test";
          const key = randomBytes(32);
          const provider: SyncWrappingKeyProvider = {
            getActiveKey: () => ({ keyId, key }),
            getKeyById: (requested) => (requested === keyId ? { keyId, key } : null),
          };
          const options = {
            env: { ...process.env, OPENCLAW_STATE_DIR: directory },
            path: path.join(directory, "state", "openclaw.sqlite"),
          };
          const original = generateStoredDeviceIdentity({ wrappingKeyProvider: provider });
          insertStoredDeviceIdentityIfAbsent(original, {
            ...options,
            wrappingKeyProvider: provider,
          });
          closeOpenClawStateDatabaseForTest();
          const before = digestRow(options.path);
          const unavailable =
            mode === "no-provider" || mode === "doctor-no-provider"
              ? undefined
              : {
                  getActiveKey: () => ({ keyId, key: randomBytes(32) }),
                  getKeyById: () =>
                    mode === "unknown-key-id" ? null : { keyId, key: randomBytes(32) },
                };
          let refused = false;
          try {
            if (mode === "doctor-no-provider") {
              const repair = repairInvalidCanonicalIdentity(options.env);
              refused = repair.changes.length === 0 && repair.warnings.length > 0;
            } else {
              repairInvalidStoredDeviceIdentity(generateStoredDeviceIdentity(), {
                ...options,
                wrappingKeyProvider: unavailable,
              });
            }
          } catch {
            refused = true;
          }
          closeOpenClawStateDatabaseForTest();
          // Compare only digests: failed assertions must never dump secret row contents.
          expect(digestRow(options.path)).toBe(before);
          expect(refused).toBe(true);
          expect(
            readStoredDeviceIdentity({ ...options, wrappingKeyProvider: provider })?.deviceId,
          ).toBe(original.deviceId);
        } finally {
          closeOpenClawStateDatabaseForTest();
        }
      });
    },
  );
});
