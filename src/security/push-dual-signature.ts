import { createHash, randomBytes } from "node:crypto";
import {
  ed25519PrivateKeyPemFromRaw,
  ed25519PublicKeyPemFromRaw,
  signEd25519Payload,
  verifyEd25519SignatureBytes,
} from "../infra/ed25519-signature.js";
import {
  encodeMlDsa65PublicKey,
  encodeMlDsa65SecretKey,
  MLDSA65_PUBLIC_KEY_BYTES,
  MLDSA65_SECRET_KEY_BYTES,
  MLDSA65_SIGNATURE_BYTES,
  signMlDsa65Payload,
  verifyMlDsa65Signature,
} from "../infra/mldsa65-key-storage.js";

const ED25519_RAW_SECRET_KEY = 32;
const ED25519_RAW_PUBLIC_KEY = 32;
const ED25519_SIGNATURE_BYTES = 64;
const EXPECTED_ALGORITHMS = ["ed25519", "ml-dsa-65"] as const;
const MAX_KEY_ID_LENGTH = 128;
const MAX_ID_LENGTH = 256;
const MAX_ENVELOPE_BYTES = 16 * 1024;
const DEFAULT_MAX_AGE_MS = 5 * 60_000;
const NONCE_BYTES = 24;

export const PUSH_DUAL_SIG_CONSTANTS = {
  ED25519_RAW_SECRET_KEY,
  ED25519_RAW_PUBLIC_KEY,
  ED25519_SIGNATURE_BYTES,
  MLDSA65_PUBLIC_KEY_BYTES,
  MLDSA65_SECRET_KEY_BYTES,
  MLDSA65_SIGNATURE_BYTES,
  EXPECTED_ALGORITHMS,
  MAX_KEY_ID_LENGTH,
  MAX_ENVELOPE_BYTES,
  DEFAULT_MAX_AGE_MS,
  NONCE_BYTES,
} as const;

export class PushDualSignatureError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "PushDualSignatureError";
  }
}

export interface PushDualEnvelope {
  version: 2;
  algorithms: ["ed25519", "ml-dsa-65"];
  sender_id: string;
  recipient_id: string;
  key_id_ed25519: string;
  key_id_mldsa65: string;
  created_at_ms: number;
  sequence: number;
  nonce: string;
  payload_type: string;
  payload_sha256: string;
  ed25519_sig: string;
  mldsa65_sig: string;
}

export type PushSignatureAlgorithm = (typeof EXPECTED_ALGORITHMS)[number];

export interface TrustedPushKey {
  algorithm: PushSignatureAlgorithm;
  keyId: string;
  senderId: string;
  publicKeyRaw: Uint8Array;
  validFromMs?: number;
  validUntilMs?: number;
  revokedAtMs?: number;
}

export interface PushTrustedKeyRegistry {
  resolve(algorithm: PushSignatureAlgorithm, keyId: string): TrustedPushKey | undefined;
}

export interface PushReplayGuard {
  accept(input: {
    senderId: string;
    recipientId: string;
    sequence: number;
    nonce: string;
    createdAtMs: number;
  }): boolean;
}

/** Bounded process-local replay guard. Durable receivers should implement the same interface with SQLite. */
export class InMemoryPushReplayGuard implements PushReplayGuard {
  readonly #seen = new Map<string, number>();
  readonly #highestSequence = new Map<string, number>();
  constructor(private readonly maxEntries = 10_000) {
    if (!Number.isSafeInteger(maxEntries) || maxEntries < 1) {
      throw new PushDualSignatureError("replay capacity must be a positive safe integer");
    }
  }

  accept(input: Parameters<PushReplayGuard["accept"]>[0]): boolean {
    const peer = JSON.stringify([input.senderId, input.recipientId]);
    const replayKey = JSON.stringify([input.senderId, input.recipientId, input.nonce]);
    const highest = this.#highestSequence.get(peer);
    if (highest === undefined && this.#highestSequence.size >= this.maxEntries) {
      return false;
    }
    if (this.#seen.has(replayKey) || (highest !== undefined && input.sequence <= highest)) {
      return false;
    }
    this.#seen.set(replayKey, input.createdAtMs);
    this.#highestSequence.set(peer, input.sequence);
    while (this.#seen.size > this.maxEntries) {
      const oldest = this.#seen.keys().next().value as string | undefined;
      if (oldest === undefined) {
        break;
      }
      this.#seen.delete(oldest);
    }
    return true;
  }
}

function assertText(value: string, label: string, max = MAX_ID_LENGTH): void {
  if (typeof value !== "string" || value.length === 0) {
    throw new PushDualSignatureError(`${label} must be a non-empty string`);
  }
  if (value !== value.normalize("NFC")) {
    throw new PushDualSignatureError(`${label} must use Unicode NFC normalization`);
  }
  // A UTF-8 round trip also works for SDK consumers targeting pre-ES2024 libs.
  if (value !== Buffer.from(value, "utf8").toString("utf8")) {
    throw new PushDualSignatureError(`${label} contains an unpaired Unicode surrogate`);
  }
  if (Buffer.byteLength(value, "utf8") > max) {
    throw new PushDualSignatureError(`${label} exceeds ${max} UTF-8 bytes`);
  }
}

function assertRawKey(raw: Uint8Array, expectedLength: number, label: string): void {
  if (!(raw instanceof Uint8Array) || raw.length !== expectedLength) {
    throw new PushDualSignatureError(`${label} must be a ${expectedLength}-byte Uint8Array`);
  }
}

function decodeBase64UrlStrict(value: string, expectedLength: number, label: string): Buffer {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new PushDualSignatureError(`${label} is not canonical base64url`);
  }
  const decoded = Buffer.from(value, "base64url");
  if (decoded.length !== expectedLength || decoded.toString("base64url") !== value) {
    throw new PushDualSignatureError(`${label} must decode to ${expectedLength} bytes`);
  }
  return decoded;
}

function payloadHash(payload: string): string {
  return createHash("sha256").update(payload, "utf8").digest("base64url");
}

const TRANSCRIPT_DOMAIN = Buffer.from("OpenClaw-PQC/Push/V2\0", "ascii");

function encodeTaggedBytes(tag: number, value: Uint8Array): Buffer {
  const header = Buffer.allocUnsafe(5);
  header.writeUInt8(tag, 0);
  header.writeUInt32BE(value.length, 1);
  return Buffer.concat([header, value]);
}

function encodeTaggedText(tag: number, value: string): Buffer {
  assertText(value, `transcript field ${tag}`, [6, 7, 11].includes(tag) ? 128 : MAX_ID_LENGTH);
  return encodeTaggedBytes(tag, Buffer.from(value, "utf8"));
}

function encodeTaggedUint64(tag: number, value: number): Buffer {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new PushDualSignatureError("transcript integer must be a non-negative safe integer");
  }
  const encoded = Buffer.allocUnsafe(9);
  encoded.writeUInt8(tag, 0);
  encoded.writeBigUInt64BE(BigInt(value), 1);
  return encoded;
}

/**
 * Cross-language signed bytes, represented as canonical unpadded base64url for
 * the existing string signing APIs. Tags are fixed and lengths are uint32 BE.
 */
export function encodePushSigningTranscript(
  envelope: Omit<PushDualEnvelope, "ed25519_sig" | "mldsa65_sig">,
): string {
  const bytes = Buffer.concat([
    TRANSCRIPT_DOMAIN,
    encodeTaggedUint64(1, envelope.version),
    encodeTaggedText(2, envelope.algorithms[0]),
    encodeTaggedText(3, envelope.algorithms[1]),
    encodeTaggedText(4, envelope.sender_id),
    encodeTaggedText(5, envelope.recipient_id),
    encodeTaggedText(6, envelope.key_id_ed25519),
    encodeTaggedText(7, envelope.key_id_mldsa65),
    encodeTaggedUint64(8, envelope.created_at_ms),
    encodeTaggedUint64(9, envelope.sequence),
    encodeTaggedBytes(10, decodeBase64UrlStrict(envelope.nonce, NONCE_BYTES, "nonce")),
    encodeTaggedText(11, envelope.payload_type),
    encodeTaggedBytes(12, decodeBase64UrlStrict(envelope.payload_sha256, 32, "payload_sha256")),
  ]);
  return `openclaw-push-v2-binary:${bytes.toString("base64url")}`;
}

export interface SignPushPayloadDualOptions {
  payload: string;
  ed25519SecretKeyRaw: Uint8Array;
  mldsa65SecretKeyRaw: Uint8Array;
  keyIdEd25519: string;
  keyIdMldsa65: string;
  senderId?: string;
  recipientId?: string;
  createdAtMs?: number;
  sequence?: number;
  nonce?: string;
  payloadType?: string;
}

export function signPushPayloadDual(options: SignPushPayloadDualOptions): {
  payload: string;
  envelope: PushDualEnvelope;
} {
  if (typeof options.payload !== "string") {
    throw new PushDualSignatureError("payload must be a UTF-8 string");
  }
  assertRawKey(options.ed25519SecretKeyRaw, ED25519_RAW_SECRET_KEY, "ed25519SecretKeyRaw");
  assertRawKey(options.mldsa65SecretKeyRaw, MLDSA65_SECRET_KEY_BYTES, "mldsa65SecretKeyRaw");
  assertText(options.keyIdEd25519, "keyIdEd25519", MAX_KEY_ID_LENGTH);
  assertText(options.keyIdMldsa65, "keyIdMldsa65", MAX_KEY_ID_LENGTH);
  const unsigned = {
    version: 2 as const,
    algorithms: ["ed25519", "ml-dsa-65"] as ["ed25519", "ml-dsa-65"],
    sender_id: options.senderId ?? "local-gateway",
    recipient_id: options.recipientId ?? "local-recipient",
    key_id_ed25519: options.keyIdEd25519,
    key_id_mldsa65: options.keyIdMldsa65,
    created_at_ms: options.createdAtMs ?? Date.now(),
    sequence: options.sequence ?? 0,
    nonce: options.nonce ?? randomBytes(NONCE_BYTES).toString("base64url"),
    payload_type: options.payloadType ?? "application/json",
    payload_sha256: payloadHash(options.payload),
  };
  assertText(unsigned.sender_id, "senderId");
  assertText(unsigned.recipient_id, "recipientId");
  assertText(unsigned.payload_type, "payloadType", 128);
  if (!Number.isSafeInteger(unsigned.created_at_ms) || unsigned.created_at_ms < 0) {
    throw new PushDualSignatureError("createdAtMs must be a non-negative safe integer");
  }
  if (!Number.isSafeInteger(unsigned.sequence) || unsigned.sequence < 0) {
    throw new PushDualSignatureError("sequence must be a non-negative safe integer");
  }
  decodeBase64UrlStrict(unsigned.nonce, NONCE_BYTES, "nonce");
  const transcript = encodePushSigningTranscript(unsigned);
  const ed25519_sig = signEd25519Payload(
    ed25519PrivateKeyPemFromRaw(Buffer.from(options.ed25519SecretKeyRaw)),
    transcript,
  );
  const mldsa65_sig = signMlDsa65Payload(
    encodeMlDsa65SecretKey(options.mldsa65SecretKeyRaw),
    transcript,
  );
  decodeBase64UrlStrict(ed25519_sig, ED25519_SIGNATURE_BYTES, "ed25519_sig");
  decodeBase64UrlStrict(mldsa65_sig, MLDSA65_SIGNATURE_BYTES, "mldsa65_sig");
  return { payload: options.payload, envelope: { ...unsigned, ed25519_sig, mldsa65_sig } };
}

function parseEnvelope(value: PushDualEnvelope | string): PushDualEnvelope {
  let parsed: unknown = value;
  if (typeof value === "string") {
    if (!value || Buffer.byteLength(value, "utf8") > MAX_ENVELOPE_BYTES) {
      throw new PushDualSignatureError("envelope string has an invalid length");
    }
    try {
      parsed = JSON.parse(value);
    } catch (error) {
      throw new PushDualSignatureError("envelope is not valid JSON", { cause: error });
    }
  }
  if (!parsed || typeof parsed !== "object") {
    throw new PushDualSignatureError("envelope must decode to an object");
  }
  const o = parsed as Record<string, unknown>;
  if (o.version !== 2) {
    throw new PushDualSignatureError("envelope.version must be 2");
  }
  if (
    !Array.isArray(o.algorithms) ||
    o.algorithms.length !== 2 ||
    o.algorithms[0] !== "ed25519" ||
    o.algorithms[1] !== "ml-dsa-65"
  ) {
    throw new PushDualSignatureError(
      'envelope.algorithms must be exactly ["ed25519", "ml-dsa-65"]',
    );
  }
  for (const field of [
    "sender_id",
    "recipient_id",
    "key_id_ed25519",
    "key_id_mldsa65",
    "nonce",
    "payload_type",
    "payload_sha256",
  ] as const) {
    assertText(
      o[field] as string,
      `envelope.${field}`,
      field === "payload_type"
        ? 128
        : field.startsWith("key_id")
          ? MAX_KEY_ID_LENGTH
          : MAX_ID_LENGTH,
    );
  }
  assertText(o.ed25519_sig as string, "envelope.ed25519_sig", 128);
  assertText(o.mldsa65_sig as string, "envelope.mldsa65_sig", 8_192);
  if (
    !Number.isSafeInteger(o.created_at_ms) ||
    (o.created_at_ms as number) < 0 ||
    !Number.isSafeInteger(o.sequence) ||
    (o.sequence as number) < 0
  ) {
    throw new PushDualSignatureError("envelope timestamp and sequence must be safe integers");
  }
  return o as unknown as PushDualEnvelope;
}

function resolveTrustedKey(params: {
  algorithm: PushSignatureAlgorithm;
  keyId: string;
  senderId: string;
  registry: PushTrustedKeyRegistry;
  nowMs: number;
}): Uint8Array {
  const key = params.registry.resolve(params.algorithm, params.keyId);
  if (!key) {
    throw new PushDualSignatureError(`unknown ${params.algorithm} key id`);
  }
  if (
    key.algorithm !== params.algorithm ||
    key.keyId !== params.keyId ||
    key.senderId !== params.senderId
  ) {
    throw new PushDualSignatureError("trusted key subject binding failed");
  }
  if (key.validFromMs !== undefined && params.nowMs < key.validFromMs) {
    throw new PushDualSignatureError("trusted key is not yet valid");
  }
  // Both receivers use [validFrom, validUntil); the expiry instant is not valid.
  if (key.validUntilMs !== undefined && params.nowMs >= key.validUntilMs) {
    throw new PushDualSignatureError("trusted key has expired");
  }
  if (key.revokedAtMs !== undefined && params.nowMs >= key.revokedAtMs) {
    throw new PushDualSignatureError("trusted key is revoked");
  }
  return key.publicKeyRaw;
}

export interface VerifyPushPayloadDualOptions {
  payload: string;
  envelope: PushDualEnvelope | string;
  registry: PushTrustedKeyRegistry;
  expectedRecipientId?: string;
  nowMs?: number;
  maxAgeMs?: number;
  replayGuard?: PushReplayGuard;
}

export interface VerifyPushPayloadDualStrictOptions extends VerifyPushPayloadDualOptions {
  expectedRecipientId: string;
  replayGuard: PushReplayGuard;
}

/** Receiver entry point: require local identity and a guard reused across messages. */
export function verifyPushPayloadDualStrict(options: VerifyPushPayloadDualStrictOptions): boolean {
  assertText(options.expectedRecipientId, "expectedRecipientId");
  if (!options.replayGuard || typeof options.replayGuard.accept !== "function") {
    throw new PushDualSignatureError("replayGuard is required for strict verification");
  }
  return verifyPushPayloadDual(options);
}

export function verifyPushPayloadDual(options: VerifyPushPayloadDualOptions): boolean {
  if (typeof options.payload !== "string") {
    throw new PushDualSignatureError("payload must be a UTF-8 string");
  }
  const envelope = parseEnvelope(options.envelope);
  const nowMs = options.nowMs ?? Date.now();
  const maxAgeMs = options.maxAgeMs ?? DEFAULT_MAX_AGE_MS;
  if (
    !Number.isSafeInteger(nowMs) ||
    nowMs < 0 ||
    !Number.isSafeInteger(maxAgeMs) ||
    maxAgeMs < 1
  ) {
    throw new PushDualSignatureError("verification clock and age must be safe integers");
  }
  if (
    options.expectedRecipientId !== undefined &&
    envelope.recipient_id !== options.expectedRecipientId
  ) {
    throw new PushDualSignatureError("recipient binding failed");
  }
  if (envelope.created_at_ms > nowMs + 30_000 || nowMs - envelope.created_at_ms > maxAgeMs) {
    throw new PushDualSignatureError("envelope timestamp is stale or in the future");
  }
  if (payloadHash(options.payload) !== envelope.payload_sha256) {
    throw new PushDualSignatureError("payload hash mismatch");
  }
  decodeBase64UrlStrict(envelope.nonce, NONCE_BYTES, "nonce");
  decodeBase64UrlStrict(envelope.payload_sha256, 32, "payload_sha256");
  const edPublic = resolveTrustedKey({
    algorithm: "ed25519",
    keyId: envelope.key_id_ed25519,
    senderId: envelope.sender_id,
    registry: options.registry,
    nowMs,
  });
  const mlPublic = resolveTrustedKey({
    algorithm: "ml-dsa-65",
    keyId: envelope.key_id_mldsa65,
    senderId: envelope.sender_id,
    registry: options.registry,
    nowMs,
  });
  assertRawKey(edPublic, ED25519_RAW_PUBLIC_KEY, "ed25519 public key");
  assertRawKey(mlPublic, MLDSA65_PUBLIC_KEY_BYTES, "ML-DSA-65 public key");
  const { ed25519_sig: _ed, mldsa65_sig: _ml, ...unsigned } = envelope;
  const transcript = encodePushSigningTranscript(unsigned);
  const edOk = verifyEd25519SignatureBytes({
    publicKey: ed25519PublicKeyPemFromRaw(Buffer.from(edPublic)),
    payload: Buffer.from(transcript, "utf8"),
    signatureBase64Url: decodeBase64UrlStrict(
      envelope.ed25519_sig,
      ED25519_SIGNATURE_BYTES,
      "ed25519_sig",
    ).toString("base64url"),
  });
  if (!edOk) {
    throw new PushDualSignatureError("Ed25519 signature verification failed");
  }
  const mlOk = verifyMlDsa65Signature({
    publicKey: encodeMlDsa65PublicKey(mlPublic),
    payload: transcript,
    sigBase64Url: decodeBase64UrlStrict(
      envelope.mldsa65_sig,
      MLDSA65_SIGNATURE_BYTES,
      "mldsa65_sig",
    ).toString("base64url"),
  });
  if (!mlOk) {
    throw new PushDualSignatureError("ML-DSA-65 signature verification failed");
  }
  if (
    options.replayGuard &&
    !options.replayGuard.accept({
      senderId: envelope.sender_id,
      recipientId: envelope.recipient_id,
      sequence: envelope.sequence,
      nonce: envelope.nonce,
      createdAtMs: envelope.created_at_ms,
    })
  ) {
    throw new PushDualSignatureError("replayed or out-of-order envelope");
  }
  return true;
}
