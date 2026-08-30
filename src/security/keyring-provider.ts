// M6 (PQC migration, whitepaper 2.2.5 + 2.2.5.A): SyncWrappingKeyProvider
// implementations — File, Env, Composite. Plus a fail-closed OsKeyring stub
// reserved for the future `@napi-rs/keyring` native dep (M6.B).
//
// File format: a JSON document on disk
//   { "activeKeyId": "wrap-key-2026-08",
//     "keys": { "wrap-key-2026-08": "base64url-32-bytes" } }
// saved with mode 0600. The constructor refuses anything other than 0600 or
// 0400 (POSIX) — the only way to load the keyring in production is for the
// admin to have chmod'd the file. Symlinks and relative paths are rejected.

import { randomBytes } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import type { SyncWrappingKeyProvider } from "../infra/device-identity-store.js";

const WRAP_KEY_BYTES = 32;
const FILE_ACCEPTED_MODES = new Set([0o600, 0o400]);
const FILE_BLOCKED_MODES_MESSAGE =
  "File keyring must be mode 0600 or 0400 (POSIX); other modes are refused to keep the wrapping key out of group/world-readable storage.";

export class KeyringError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "KeyringError";
  }
}

export function encodeBase64UrlKey(raw: Buffer): string {
  if (!(raw instanceof Buffer)) {
    throw new KeyringError("Wrapping key must be a Buffer");
  }
  if (raw.length !== WRAP_KEY_BYTES) {
    throw new KeyringError(`Wrapping key must be ${WRAP_KEY_BYTES} bytes; got ${raw.length}`);
  }
  return raw.toString("base64url");
}

export function decodeBase64UrlKey(s: string): Buffer {
  if (typeof s !== "string" || s.length === 0) {
    throw new KeyringError("base64url key must be a non-empty string");
  }
  const raw = Buffer.from(s, "base64url");
  if (raw.length !== WRAP_KEY_BYTES) {
    throw new KeyringError(
      `Decoded base64url key must be ${WRAP_KEY_BYTES} bytes; got ${raw.length}`,
    );
  }
  return raw;
}

export function generateWrappingKey(): string {
  return encodeBase64UrlKey(Buffer.from(randomBytes(WRAP_KEY_BYTES)));
}

interface FileKeyringShape {
  activeKeyId: string;
  keys: Record<string, string>;
}

function parseFileKeyringShape(parsed: unknown): FileKeyringShape {
  if (!parsed || typeof parsed !== "object") {
    throw new KeyringError("File keyring JSON must decode to an object");
  }
  const obj = parsed as Record<string, unknown>;
  if (typeof obj.activeKeyId !== "string" || obj.activeKeyId.length === 0) {
    throw new KeyringError("File keyring is missing an activeKeyId string");
  }
  if (!obj.keys || typeof obj.keys !== "object") {
    throw new KeyringError("File keyring is missing a keys object");
  }
  const keys: Record<string, string> = {};
  for (const [k, v] of Object.entries(obj.keys as Record<string, unknown>)) {
    if (typeof v !== "string") {
      throw new KeyringError(`File keyring entry "${k}" is not a base64url string`);
    }
    keys[k] = v;
  }
  return { activeKeyId: obj.activeKeyId, keys };
}

function readFileKeyringShape(filePath: string): FileKeyringShape {
  let raw: string;
  try {
    raw = fs.readFileSync(filePath, "utf8");
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      throw new KeyringError(`File keyring does not exist: ${filePath}`, { cause: error });
    }
    throw new KeyringError(`Cannot read file keyring at ${filePath}`, { cause: error });
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch (error) {
    throw new KeyringError(`File keyring at ${filePath} is not valid JSON`, { cause: error });
  }
  return parseFileKeyringShape(parsed);
}

function writeFileKeyringShape(
  filePath: string,
  shape: FileKeyringShape,
  mode: 0o600 | 0o400,
): void {
  const data = JSON.stringify(shape, null, 2);
  fs.writeFileSync(filePath, data, { mode, encoding: "utf8" });
  // Re-assert the mode in case the file already existed with a wider mask.
  fs.chmodSync(filePath, mode);
}

function assertAcceptableFileMode(filePath: string): void {
  let stat: fs.Stats;
  try {
    stat = fs.lstatSync(filePath);
  } catch (error) {
    throw new KeyringError(`Cannot stat file keyring at ${filePath}`, { cause: error });
  }
  if (stat.isSymbolicLink()) {
    throw new KeyringError(
      `Refusing to follow symbolic link at ${filePath}; file keyring must be a real file (per output-root-guard)`,
    );
  }
  if (!stat.isFile()) {
    throw new KeyringError(`${filePath} is not a regular file`);
  }
  const mode = stat.mode & 0o777;
  if (!FILE_ACCEPTED_MODES.has(mode)) {
    throw new KeyringError(
      `${FILE_BLOCKED_MODES_MESSAGE} Got 0o${mode.toString(8).padStart(3, "0")}.`,
    );
  }
}

export interface FileKeyringOptions {
  path: string;
  primaryKeyId?: string;
  mode?: 0o600 | 0o400;
}

interface FileKeyringCache {
  shape: FileKeyringShape;
  mtimeMs: number;
}

/**
 * File-backed keyring. The constructor chmod-asserts 0600/0400 — anything
 * looser is refused. A read cache is keyed off mtime, so writes from
 * another process invalidate on the next call (no internal cache TTL).
 */
export class FileKeyring implements SyncWrappingKeyProvider {
  private readonly filePath: string;
  private readonly mode: 0o600 | 0o400;
  private readonly explicitPrimaryKeyId: string | undefined;
  private cache: FileKeyringCache | null = null;

  constructor(options: FileKeyringOptions) {
    if (typeof options.path !== "string" || options.path.length === 0) {
      throw new KeyringError("FileKeyring requires a non-empty path");
    }
    if (!path.isAbsolute(options.path)) {
      throw new KeyringError(`FileKeyring path must be absolute; got ${options.path}`);
    }
    this.mode = options.mode ?? 0o600;
    if (!FILE_ACCEPTED_MODES.has(this.mode)) {
      throw new KeyringError(FILE_BLOCKED_MODES_MESSAGE);
    }
    this.filePath = options.path;
    this.explicitPrimaryKeyId = options.primaryKeyId;
  }

  getActiveKey(): { keyId: string; key: Buffer } {
    const shape = this.loadShape();
    if (this.explicitPrimaryKeyId) {
      if (!shape.keys[this.explicitPrimaryKeyId]) {
        throw new KeyringError(
          `File keyring at ${this.filePath} is missing the explicit primary keyId "${this.explicitPrimaryKeyId}"`,
        );
      }
      return {
        keyId: this.explicitPrimaryKeyId,
        key: decodeBase64UrlKey(shape.keys[this.explicitPrimaryKeyId]),
      };
    }
    if (!shape.keys[shape.activeKeyId]) {
      throw new KeyringError(
        `File keyring at ${this.filePath} has no entry for the active keyId "${shape.activeKeyId}"`,
      );
    }
    return {
      keyId: shape.activeKeyId,
      key: decodeBase64UrlKey(shape.keys[shape.activeKeyId]),
    };
  }

  getKeyById(keyId: string): { keyId: string; key: Buffer } | null {
    if (typeof keyId !== "string" || keyId.length === 0) return null;
    const shape = this.loadShape();
    const entry = shape.keys[keyId];
    if (!entry) return null;
    return { keyId, key: decodeBase64UrlKey(entry) };
  }

  /** Replace the on-disk keyring shape; useful for tests and rotation flows. */
  setShape(shape: FileKeyringShape): void {
    writeFileKeyringShape(this.filePath, shape, this.mode);
    this.cache = null;
  }

  private loadShape(): FileKeyringShape {
    assertAcceptableFileMode(this.filePath);
    const stat = fs.statSync(this.filePath);
    if (this.cache && this.cache.mtimeMs === stat.mtimeMs) {
      return this.cache.shape;
    }
    const shape = readFileKeyringShape(this.filePath);
    this.cache = { shape, mtimeMs: stat.mtimeMs };
    return shape;
  }
}

export interface EnvKeyringOptions {
  /** Name of the env var that holds the active base64url key. */
  activeVar: string;
  /**
   * Optional per-keyId env var resolver. The default pattern is
   * `${activeVar}__<keyId>`. Set to a function to use a different naming
   * convention (e.g. looking up an env-var table).
   */
  resolveVar?: (keyId: string) => string;
}

function defaultResolveVar(activeVar: string): (keyId: string) => string {
  return (keyId) => `${activeVar}__${keyId}`;
}

/**
 * Env-backed keyring. Every call re-reads the environment so rotation
 * (process restart, or another process mutating the env table) takes
 * effect immediately. There is no internal cache.
 */
export class EnvKeyring implements SyncWrappingKeyProvider {
  private readonly activeVar: string;
  private readonly resolveVar: (keyId: string) => string;

  constructor(options: EnvKeyringOptions) {
    if (typeof options.activeVar !== "string" || options.activeVar.length === 0) {
      throw new KeyringError("EnvKeyring requires a non-empty activeVar");
    }
    this.activeVar = options.activeVar;
    this.resolveVar = options.resolveVar ?? defaultResolveVar(this.activeVar);
  }

  getActiveKey(): { keyId: string; key: Buffer } {
    const raw = process.env[this.activeVar];
    if (typeof raw !== "string" || raw.length === 0) {
      throw new KeyringError(`Env keyring is missing active key in env var "${this.activeVar}"`);
    }
    // EnvKeyring does not know the keyId; the caller is expected to pass a
    // known keyId or to use it through CompositeKeyring. We default to the
    // env var name as the synthetic keyId so the store can carry the wrap
    // envelope with a stable identifier.
    return { keyId: this.activeVar, key: decodeBase64UrlKey(raw) };
  }

  getKeyById(keyId: string): { keyId: string; key: Buffer } | null {
    if (typeof keyId !== "string" || keyId.length === 0) return null;
    const raw = process.env[this.resolveVar(keyId)];
    if (typeof raw !== "string" || raw.length === 0) return null;
    return { keyId, key: decodeBase64UrlKey(raw) };
  }
}

export interface CompositeKeyringOptions {
  providers: SyncWrappingKeyProvider[];
}

/**
 * Composite keyring. `getActiveKey` walks the providers in order and returns
 * the first successful resolution. `getKeyById` walks the providers and
 * returns the first provider that holds the keyId.
 */
export class CompositeKeyring implements SyncWrappingKeyProvider {
  private readonly providers: SyncWrappingKeyProvider[];

  constructor(options: CompositeKeyringOptions) {
    if (!Array.isArray(options.providers) || options.providers.length === 0) {
      throw new KeyringError("CompositeKeyring requires at least one provider");
    }
    this.providers = options.providers.slice();
  }

  getActiveKey(): { keyId: string; key: Buffer } {
    let lastError: unknown = null;
    for (const provider of this.providers) {
      try {
        return provider.getActiveKey();
      } catch (error) {
        lastError = error;
      }
    }
    throw new KeyringError(
      `Composite keyring could not resolve an active key from ${this.providers.length} provider(s)`,
      { cause: lastError ?? undefined },
    );
  }

  getKeyById(keyId: string): { keyId: string; key: Buffer } | null {
    for (const provider of this.providers) {
      try {
        const result = provider.getKeyById(keyId);
        if (result) return result;
      } catch {
        // ignore — try the next provider
      }
    }
    return null;
  }
}

// --- Future M6.B: OsKeyring stub (fail-closed until @napi-rs/keyring ships) ---

export class OsKeyring {
  constructor(_options: { service: string; account?: string } = { service: "openclaw" }) {
    throw new KeyringError(
      "OsKeyring is not implemented in this build (M6.B). Install @napi-rs/keyring or use FileKeyring / EnvKeyring / CompositeKeyring.",
    );
  }
}

// --- Factory: a discriminated union that maps a config object to a provider ---

export type KeyringConfig =
  | { kind: "file"; path: string; primaryKeyId?: string; mode?: 0o600 | 0o400 }
  | { kind: "env"; activeVar: string; resolveVar?: (keyId: string) => string }
  | { kind: "composite"; providers: KeyringConfig[] };

/** Recursively materialise a KeyringConfig into a SyncWrappingKeyProvider. */
export function createKeyring(config: KeyringConfig): SyncWrappingKeyProvider {
  switch (config.kind) {
    case "file":
      return new FileKeyring({
        path: config.path,
        primaryKeyId: config.primaryKeyId,
        mode: config.mode,
      });
    case "env":
      return new EnvKeyring({
        activeVar: config.activeVar,
        resolveVar: config.resolveVar,
      });
    case "composite":
      return new CompositeKeyring({
        providers: config.providers.map(createKeyring),
      });
    default: {
      const _exhaustive: never = config;
      throw new KeyringError(`Unknown keyring config: ${JSON.stringify(_exhaustive)}`);
    }
  }
}

// Suppress unused import warning when the platform doesn't pull `os` in.
void os;
