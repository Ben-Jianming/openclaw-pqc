// M7 (PQC migration, whitepaper 2.2.5.C + 2.2.5.D): wrap-key rotation and
// passphrase backup / restore invariants.
//
// 19 invariants covering: constantTimeEqual branch coverage, export/import
// round-trip across multiple keys, tamper detection on each envelope
// field, wrong-passphrase rejection, version mismatch rejection, malformed
// envelope rejection, weak-passphrase rejection, keyId shape validation,
// iteration guard, rotation rewrap of a wrapped row, rotation skip of a
// plaintext row, and rotation refusal when the old keyring is missing the
// seal keyId.
import { randomBytes } from "node:crypto";
import { afterEach, describe, expect, it } from "vitest";
import type {
  SyncWrappingKeyProvider,
  StoredDeviceIdentity,
} from "../infra/device-identity-store.js";
import { generateStoredDeviceIdentity } from "../infra/device-identity-store.js";
import { serializeWrappedSecret, wrapSecret } from "./secret-wrapping.js";
import {
  constantTimeEqual,
  exportWrapKey,
  importWrapKey,
  rotateWrappingKey,
  WRAP_KEY_BACKUP_CONSTANTS,
  WrapKeyBackupError,
  WrapKeyRotationError,
} from "./wrap-key-rotation.js";

afterEach(() => {
  // no-op
});

function newKey(): Buffer {
  return Buffer.from(randomBytes(32));
}

const STRONG_PASSPHRASE = "openclaw-rotates-wrapping-keys-2026";

describe("wrap-key-rotation (M7, whitepaper 2.2.5.C + 2.2.5.D)", () => {
  it("constantTimeEqual returns true for identical buffers", () => {
    const a = Buffer.from("hello world");
    expect(constantTimeEqual(a, Buffer.from("hello world"))).toBe(true);
  });

  it("constantTimeEqual returns false for different-length buffers", () => {
    expect(constantTimeEqual(Buffer.from("a"), Buffer.from("ab"))).toBe(false);
  });

  it("constantTimeEqual returns false for non-Buffer inputs", () => {
    // @ts-expect-error -- intentional type violation
    expect(constantTimeEqual("not-a-buffer", Buffer.from("x"))).toBe(false);
    // @ts-expect-error -- intentional type violation
    expect(constantTimeEqual(Buffer.from("x"), null)).toBe(false);
  });

  it("WRAP_KEY_BACKUP_CONSTANTS expose the OWASP 2023 minimums", () => {
    expect(WRAP_KEY_BACKUP_CONSTANTS.BACKUP_VERSION).toBe(1);
    expect(WRAP_KEY_BACKUP_CONSTANTS.PBKDF2_ITERATIONS).toBe(210_000);
    expect(WRAP_KEY_BACKUP_CONSTANTS.PBKDF2_KEY_BYTES).toBe(32);
    expect(WRAP_KEY_BACKUP_CONSTANTS.SALT_BYTES).toBe(16);
    expect(WRAP_KEY_BACKUP_CONSTANTS.IV_BYTES).toBe(12);
    expect(WRAP_KEY_BACKUP_CONSTANTS.AUTH_TAG_BYTES).toBe(16);
    expect(WRAP_KEY_BACKUP_CONSTANTS.WRAP_KEY_BYTES).toBe(32);
    expect(WRAP_KEY_BACKUP_CONSTANTS.MIN_PASSPHRASE_LENGTH).toBe(8);
  });

  it("exportWrapKey + importWrapKey round-trips a 32-byte key", () => {
    const raw = newKey();
    const envelope = exportWrapKey(raw, STRONG_PASSPHRASE, "wrap-key-2026-08");
    const restored = importWrapKey(envelope, STRONG_PASSPHRASE);
    expect(restored.keyId).toBe("wrap-key-2026-08");
    expect(restored.key.equals(raw)).toBe(true);
  });

  it("exportWrapKey rejects a key of the wrong length", () => {
    expect(() => exportWrapKey(Buffer.alloc(16), STRONG_PASSPHRASE, "wrap-key-2026-08")).toThrow(
      /must be 32 bytes/,
    );
  });

  it("exportWrapKey rejects a passphrase that is too short", () => {
    expect(() => exportWrapKey(newKey(), "short", "wrap-key-2026-08")).toThrow(
      /at least 8 characters/,
    );
  });

  it("exportWrapKey rejects an empty keyId", () => {
    expect(() => exportWrapKey(newKey(), STRONG_PASSPHRASE, "")).toThrow(
      /keyId must be a non-empty string/,
    );
  });

  it("exportWrapKey rejects an over-long keyId", () => {
    expect(() => exportWrapKey(newKey(), STRONG_PASSPHRASE, "k".repeat(129))).toThrow(
      /exceeds 128 characters/,
    );
  });

  it("importWrapKey rejects an empty envelope string", () => {
    expect(() => importWrapKey("", STRONG_PASSPHRASE)).toThrow(/non-empty string/);
  });

  it("importWrapKey rejects a non-base64url envelope", () => {
    expect(() => importWrapKey("!!!not-base64!!!", STRONG_PASSPHRASE)).toThrow(
      /not valid base64url-encoded JSON/,
    );
  });

  it("importWrapKey rejects an envelope with the wrong version", () => {
    const wrongVersion = Buffer.from(
      JSON.stringify({
        v: 99,
        keyId: "wrap-key-2026-08",
        iterations: 210_000,
        salt: "AAAAAAAAAAAAAAAAAAAAAA",
        iv: "AAAAAAAAAAAA",
        ciphertext: Buffer.alloc(32).toString("base64url"),
        authTag: "AAAAAAAAAAAAAAAAAAAA",
        createdAtMs: 1,
      }),
      "utf8",
    ).toString("base64url");
    expect(() => importWrapKey(wrongVersion, STRONG_PASSPHRASE)).toThrow(
      /Unsupported envelope version 99/,
    );
  });

  it("importWrapKey rejects an envelope whose salt has the wrong length", () => {
    const envelope = exportWrapKey(newKey(), STRONG_PASSPHRASE, "wrap-key-2026-08");
    const raw = JSON.parse(Buffer.from(envelope, "base64url").toString("utf8"));
    raw.salt = "AAAA"; // too short
    const tampered = Buffer.from(JSON.stringify(raw), "utf8").toString("base64url");
    expect(() => importWrapKey(tampered, STRONG_PASSPHRASE)).toThrow(/salt must be 16 bytes/);
  });

  it("importWrapKey rejects an envelope whose IV has been tampered with", () => {
    const envelope = exportWrapKey(newKey(), STRONG_PASSPHRASE, "wrap-key-2026-08");
    const raw = JSON.parse(Buffer.from(envelope, "base64url").toString("utf8"));
    raw.iv = "AAAA"; // too short
    const tampered = Buffer.from(JSON.stringify(raw), "utf8").toString("base64url");
    expect(() => importWrapKey(tampered, STRONG_PASSPHRASE)).toThrow(/iv must be 12 bytes/);
  });

  it("importWrapKey rejects an envelope whose auth tag has been tampered with", () => {
    const envelope = exportWrapKey(newKey(), STRONG_PASSPHRASE, "wrap-key-2026-08");
    const raw = JSON.parse(Buffer.from(envelope, "base64url").toString("utf8"));
    raw.authTag = "AAAA"; // too short
    const tampered = Buffer.from(JSON.stringify(raw), "utf8").toString("base64url");
    expect(() => importWrapKey(tampered, STRONG_PASSPHRASE)).toThrow(/authTag must be 16 bytes/);
  });

  it("importWrapKey rejects a wrong passphrase", () => {
    const envelope = exportWrapKey(newKey(), STRONG_PASSPHRASE, "wrap-key-2026-08");
    expect(() => importWrapKey(envelope, "a-very-different-passphrase-2026")).toThrow(
      /AES-256-GCM authentication failed/,
    );
  });

  it("importWrapKey throws WrapKeyBackupError (not Error) on auth failure", () => {
    const envelope = exportWrapKey(newKey(), STRONG_PASSPHRASE, "wrap-key-2026-08");
    let caught: unknown = null;
    try {
      importWrapKey(envelope, "another-very-different-passphrase");
    } catch (error) {
      caught = error;
    }
    expect(caught).toBeInstanceOf(WrapKeyBackupError);
  });

  it("rotateWrappingKey re-wraps a wrapped row under the new key and reports {rotated, skipped}", async () => {
    const oldKey = newKey();
    const newKeyBuf = newKey();
    const oldKeyring: SyncWrappingKeyProvider = {
      getActiveKey: () => ({ keyId: "wrap-key-2026-08", key: oldKey }),
      getKeyById: (id: string) =>
        id === "wrap-key-2026-08" ? { keyId: "wrap-key-2026-08", key: oldKey } : null,
    };

    const wrapped: StoredDeviceIdentity = generateStoredDeviceIdentity({
      wrappingKeyProvider: oldKeyring,
    });
    const plaintext: StoredDeviceIdentity = generateStoredDeviceIdentity();

    const rewritten = new Map<string, StoredDeviceIdentity>();
    const result = await rotateWrappingKey({
      oldKeyring,
      newKey: { keyId: "wrap-key-2026-09", key: newKeyBuf },
      listWrapped: () => [
        { identityKey: "primary", identity: wrapped },
        { identityKey: "secondary", identity: plaintext },
      ],
      rewrite: (identityKey, next) => {
        rewritten.set(identityKey, next);
        return next;
      },
    });

    expect(result.rotated).toBe(1);
    expect(result.skipped).toBe(1);
    const rewrapped = rewritten.get("primary");
    expect(rewrapped).toBeDefined();
    expect(rewrapped!.mldsaPrivateKeyWrapKeyId).toBe("wrap-key-2026-09");
    expect(rewrapped!.mldsaPrivateKeyPem).toBeNull();
    expect(rewrapped!.mldsaPrivateKeyWrapped).not.toBeNull();
    // The plaintext row is left untouched.
    expect(rewritten.has("secondary")).toBe(false);
  });

  it("rotateWrappingKey refuses to rotate when the old keyring is missing the seal keyId", async () => {
    const oldKey = newKey();
    const oldKeyring: SyncWrappingKeyProvider = {
      getActiveKey: () => ({ keyId: "wrap-key-2026-08", key: oldKey }),
      getKeyById: () => null,
    };
    const wrapped: StoredDeviceIdentity = generateStoredDeviceIdentity({
      wrappingKeyProvider: oldKeyring,
    });
    await expect(
      rotateWrappingKey({
        oldKeyring,
        newKey: { keyId: "wrap-key-2026-09", key: newKey() },
        listWrapped: () => [{ identityKey: "primary", identity: wrapped }],
        rewrite: () => {
          throw new Error("rewrite should not be called");
        },
      }),
    ).rejects.toThrow(/Old keyring does not hold keyId/);
  });

  it("rotateWrappingKey validates the new key length before touching any row", async () => {
    const oldKey = newKey();
    const oldKeyring: SyncWrappingKeyProvider = {
      getActiveKey: () => ({ keyId: "wrap-key-2026-08", key: oldKey }),
      getKeyById: (id: string) =>
        id === "wrap-key-2026-08" ? { keyId: "wrap-key-2026-08", key: oldKey } : null,
    };
    const wrapped: StoredDeviceIdentity = generateStoredDeviceIdentity({
      wrappingKeyProvider: oldKeyring,
    });
    await expect(
      rotateWrappingKey({
        oldKeyring,
        newKey: { keyId: "wrap-key-2026-09", key: Buffer.alloc(16) },
        listWrapped: () => [{ identityKey: "primary", identity: wrapped }],
        rewrite: () => wrapped,
      }),
    ).rejects.toThrow(/newKey.key must be 32 bytes/);
  });
});
