import type {
  StoredDeviceIdentity,
  SyncWrappingKeyProvider,
} from "../infra/device-identity-store.js";
// M8 (PQC migration, whitepaper 2.2.7 + 2.2.8): wrap-key health check and CLI
// alias helpers.
//
// `wrapKeyHealthCheck` returns a JSON-friendly status document for the
// running device-identity store. Each row is classified as
//   - plaintext           : mldsa_private_key_pem is non-null
//   - wrapped-active      : envelope is sealed under the keyring's active keyId
//   - wrapped-stale       : envelope is sealed under a non-active keyId
// Plus a `notes` field that surfaces Doctor guidance strings.
//
// `parseWrapEnvelope` is a defensive probe used by both the CLI and
// Doctor when a row's BLOB looks suspicious.
//
// `wrapKeyStatusCommand`, `wrapKeyExportCommand`, `wrapKeyImportCommand`
// are the CLI entry aliases. The actual CLI registration is left for a
// later milestone; the aliases are wired to the same shared helpers so a
// future `openclaw wrap-key status|export|import` invocation lands on the
// right code path.
import { deserializeWrappedSecret, type WrappedSecret } from "./secret-wrapping.js";

export interface WrapKeyRowHealth {
  identityKey: string;
  deviceId: string;
  status: "plaintext" | "wrapped-active" | "wrapped-stale" | "invalid";
  wrapKeyId: string | null;
  activeKeyId: string | null;
  notes: string[];
}

export interface WrapKeyStatus {
  activeKeyId: string | null;
  plaintextCount: number;
  wrappedActiveCount: number;
  wrappedStaleCount: number;
  invalidCount: number;
  notes: string[];
  rows: WrapKeyRowHealth[];
}

export interface WrapKeyHealthCheckOptions {
  /** Enumerator for the device-identity rows (test-friendly). */
  list: () => Array<{ identityKey: string; identity: StoredDeviceIdentity }>;
  /** Active keyId. If null, every wrapped row counts as `wrapped-stale`. */
  activeKeyId: string | null;
}

export function wrapKeyHealthCheck(options: WrapKeyHealthCheckOptions): WrapKeyStatus {
  if (!options || typeof options !== "object") {
    throw new TypeError("wrapKeyHealthCheck requires an options object");
  }
  if (typeof options.list !== "function") {
    throw new TypeError("wrapKeyHealthCheck requires a list() function");
  }
  const rows: WrapKeyRowHealth[] = [];
  let plaintextCount = 0;
  let wrappedActiveCount = 0;
  let wrappedStaleCount = 0;
  let invalidCount = 0;
  const notes: string[] = [];

  for (const { identityKey, identity } of options.list()) {
    const row: WrapKeyRowHealth = {
      identityKey,
      deviceId: identity.deviceId,
      status: "invalid",
      wrapKeyId: identity.mldsaPrivateKeyWrapKeyId,
      activeKeyId: options.activeKeyId,
      notes: [],
    };
    if (identity.mldsaPrivateKeyWrapped && identity.mldsaPrivateKeyWrapKeyId) {
      const envelope = parseWrapEnvelope(
        Buffer.from(identity.mldsaPrivateKeyWrapped).toString("utf8"),
      );
      if (!envelope) {
        row.status = "invalid";
        row.notes.push("malformed wrap envelope");
        invalidCount += 1;
        notes.push(`Identity "${identityKey}" has a malformed wrap envelope`);
      } else if (envelope.keyId !== options.activeKeyId) {
        row.status = "wrapped-stale";
        row.notes.push(`sealed under non-active keyId "${envelope.keyId}"`);
        wrappedStaleCount += 1;
        notes.push(
          `Identity "${identityKey}" is sealed under non-active keyId "${envelope.keyId}"`,
        );
      } else {
        row.status = "wrapped-active";
        wrappedActiveCount += 1;
      }
    } else if (identity.mldsaPrivateKeyPem) {
      row.status = "plaintext";
      row.notes.push(
        "plaintext row — rewrap with " + "`openclaw wrap-key import` or wait for Doctor refresh",
      );
      plaintextCount += 1;
      notes.push(`Identity "${identityKey}" is stored as plaintext (M1/M2 legacy)`);
    } else {
      row.status = "invalid";
      row.notes.push("row carries neither wrap envelope nor plaintext");
      invalidCount += 1;
      notes.push(`Identity "${identityKey}" is in an invalid state (no wrap, no plaintext)`);
    }
    rows.push(row);
  }

  if (plaintextCount > 0) {
    notes.unshift(`${plaintextCount} plaintext row(s) — schedule a keyring refresh`);
  }
  if (wrappedStaleCount > 0) {
    notes.unshift(
      `${wrappedStaleCount} row(s) sealed under a non-active keyId — run "openclaw wrap-key rotate"`,
    );
  }
  if (invalidCount > 0) {
    notes.unshift(`${invalidCount} invalid row(s) — Doctor repair required`);
  }

  return {
    activeKeyId: options.activeKeyId,
    plaintextCount,
    wrappedActiveCount,
    wrappedStaleCount,
    invalidCount,
    notes,
    rows,
  };
}

/**
 * Defensive probe. Returns the deserialized envelope on success and
 * `null` for any malformed input — never throws, because the caller is a
 * health check and must surface the bad row rather than abort the run.
 */
export function parseWrapEnvelope(serialized: string | null | undefined): WrappedSecret | null {
  if (typeof serialized !== "string" || serialized.length === 0) return null;
  try {
    return deserializeWrappedSecret(serialized);
  } catch {
    return null;
  }
}

// --- CLI aliases (M8 ships the helper code, registration is later) ---

export interface WrapKeyStatusCommandOptions {
  list: WrapKeyHealthCheckOptions["list"];
  activeKeyId: string | null;
}

export function wrapKeyStatusCommand(options: WrapKeyStatusCommandOptions): WrapKeyStatus {
  return wrapKeyHealthCheck(options);
}

export interface WrapKeyExportCommandOptions {
  rawKey: Buffer;
  passphrase: string;
  keyId: string;
  now?: number;
}

/** Re-export from M7 for the future `openclaw wrap-key export` command. */
export async function wrapKeyExportCommand(options: WrapKeyExportCommandOptions): Promise<string> {
  const { exportWrapKey } = await import("./wrap-key-rotation.js");
  return exportWrapKey(options.rawKey, options.passphrase, options.keyId, options.now);
}

export interface WrapKeyImportCommandOptions {
  envelope: string;
  passphrase: string;
}

export async function wrapKeyImportCommand(
  options: WrapKeyImportCommandOptions,
): Promise<{ key: Buffer; keyId: string }> {
  const { importWrapKey } = await import("./wrap-key-rotation.js");
  return importWrapKey(options.envelope, options.passphrase);
}

// Suppress unused-symbol lint for the SyncWrappingKeyProvider type — it
// is intentionally re-exported so future CLI consumers can take the
// provider as a parameter without re-importing from device-identity-store.
export type { SyncWrappingKeyProvider };
