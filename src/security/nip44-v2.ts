// M10 (PQC migration, whitepaper 1.1): Nostr NIP-44 v2 + ML-KEM-768 hybrid
// envelope.
//
// NIP-44 v2 (https://github.com/nostr-protocol/nips/blob/master/44.md)
// upgrades the v1 ECDH conversation-key derivation to use HKDF-SHA256 over
// a 32-byte shared secret, ChaCha20 + HMAC-SHA256 for the payload, and a
// precise padding scheme. We replace the ECDH shared secret with an
// ML-KEM-768 shared secret — the new "pqc2:" prefix marks the wire
// format as the hybrid layer so a relay that only knows v1 can refuse to
// forward it cleanly.
//
// The on-disk / on-wire envelope format is:
//   pqc2:<base64url(ml-kem ciphertext)>.<base64url(chacha ciphertext)>.<base64url(hmac)>
import { createCipheriv, createDecipheriv, createHmac, hkdfSync } from "node:crypto";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";

const PREFIX = "pqc2:";
const HKDF_INFO = new TextEncoder().encode("nip44-v2");
const HKDF_SALT = new Uint8Array(0);
const HMAC_KEY_LEN = 32;
const CHACHA_KEY_LEN = 32;
const CHACHA_IV_LEN = 12;
const PAD_ALIGNMENT = 32;
const LENGTH_PREFIX_BYTES = 2;
const MIN_PADDED_PLAINTEXT = 1; // NIP-44 v2 forbids the zero-length plaintext path
const MIN_PLAINTEXT_LEN = 1;
const MAX_PLAINTEXT_LEN = 0xffff; // NIP-44 v2: max plaintext is 65535 bytes
const ML_KEM_768_CT_BYTES = 1088;
const ML_KEM_768_SS_BYTES = 32;
const ML_KEM_768_PK_BYTES = 1184;
const ML_KEM_768_SK_BYTES = 2400;
const HMAC_TAG_LEN = 32;

export const NIP44_V2_PQC = {
  PREFIX,
  HKDF_INFO,
  CHACHA_KEY_LEN,
  CHACHA_IV_LEN,
  HMAC_KEY_LEN,
  PAD_ALIGNMENT,
  LENGTH_PREFIX_BYTES,
  MAX_PLAINTEXT_LEN,
  ML_KEM_768_CT_BYTES,
  ML_KEM_768_SS_BYTES,
  ML_KEM_768_PK_BYTES,
  ML_KEM_768_SK_BYTES,
  HMAC_TAG_LEN,
} as const;

export class Nip44V2Error extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "Nip44V2Error";
  }
}

function toBase64Url(buf: Uint8Array): string {
  return Buffer.from(buf).toString("base64url");
}

function fromBase64Url(s: string, label: string): Buffer {
  try {
    return Buffer.from(s, "base64url");
  } catch (error) {
    throw new Nip44V2Error(`${label} is not valid base64url`, { cause: error });
  }
}

/**
 * Derive the 32-byte conversation key from a 32-byte shared secret using
 * HKDF-SHA256. Matches the NIP-44 v2 reference ("hkdf_sha256(shared_x, salt, info)").
 */
export function deriveConversationKey(sharedSecret: Uint8Array): Uint8Array {
  if (!(sharedSecret instanceof Uint8Array) || sharedSecret.length !== 32) {
    throw new Nip44V2Error("sharedSecret must be a 32-byte Uint8Array");
  }
  const okm = hkdfSync(
    "sha256",
    Buffer.from(sharedSecret),
    HKDF_SALT,
    HKDF_INFO,
    HMAC_KEY_LEN + CHACHA_KEY_LEN + CHACHA_IV_LEN,
  );
  return new Uint8Array(okm);
}

function conversationKeys(sharedSecret: Uint8Array): {
  chachaKey: Buffer;
  chachaNonce: Buffer;
  hmacKey: Buffer;
} {
  const okm = deriveConversationKey(sharedSecret);
  return {
    hmacKey: Buffer.from(okm.subarray(0, HMAC_KEY_LEN)),
    chachaKey: Buffer.from(okm.subarray(HMAC_KEY_LEN, HMAC_KEY_LEN + CHACHA_KEY_LEN)),
    chachaNonce: Buffer.from(
      okm.subarray(HMAC_KEY_LEN + CHACHA_KEY_LEN, HMAC_KEY_LEN + CHACHA_KEY_LEN + CHACHA_IV_LEN),
    ),
  };
}

/**
 * NIP-44 v2 padding: 2-byte big-endian length prefix, then zero-padded
 * plaintext to the next multiple of 32 bytes. Minimum padded length is 32
 * (one length byte + 30 zero bytes after a single byte of plaintext).
 */
export function pad(plaintext: Uint8Array): Uint8Array {
  if (!(plaintext instanceof Uint8Array)) {
    throw new Nip44V2Error("plaintext must be a Uint8Array");
  }
  if (plaintext.length < MIN_PLAINTEXT_LEN || plaintext.length > MAX_PLAINTEXT_LEN) {
    throw new Nip44V2Error(
      `plaintext length must be in [${MIN_PLAINTEXT_LEN}, ${MAX_PLAINTEXT_LEN}]; got ${plaintext.length}`,
    );
  }
  const paddedLen = Math.max(
    32,
    Math.ceil((plaintext.length + LENGTH_PREFIX_BYTES) / PAD_ALIGNMENT) * PAD_ALIGNMENT,
  );
  const out = new Uint8Array(paddedLen);
  // 2-byte big-endian length
  out[0] = (plaintext.length >>> 8) & 0xff;
  out[1] = plaintext.length & 0xff;
  out.set(plaintext, LENGTH_PREFIX_BYTES);
  // The remainder is already zero (Uint8Array initialises to zero).
  return out;
}

/**
 * Strip the NIP-44 v2 padding. The padded length must satisfy
 * `padded.length % PAD_ALIGNMENT === 0`; this is the exact modulus that
 * NIP-44 v2 specifies — the total length (2-byte length prefix + data +
 * zero pad) is padded to a multiple of 32 bytes.
 */
export function unpad(padded: Uint8Array): Uint8Array {
  if (
    !(padded instanceof Uint8Array) ||
    padded.length < LENGTH_PREFIX_BYTES + MIN_PADDED_PLAINTEXT
  ) {
    throw new Nip44V2Error("padded payload is too short");
  }
  if (padded.length % PAD_ALIGNMENT !== 0) {
    throw new Nip44V2Error(
      `padded length modulus check failed: padded.length % ${PAD_ALIGNMENT} must be 0`,
    );
  }
  const length = (padded[0]! << 8) | padded[1]!;
  // Range check first so callers get the more specific error before the
  // structural "exceeds padded payload" check.
  if (length < MIN_PLAINTEXT_LEN || length > MAX_PLAINTEXT_LEN) {
    throw new Nip44V2Error(`padded length field out of range: ${length}`);
  }
  if (LENGTH_PREFIX_BYTES + length > padded.length) {
    throw new Nip44V2Error("padded length field exceeds the padded payload");
  }
  return padded.subarray(LENGTH_PREFIX_BYTES, LENGTH_PREFIX_BYTES + length);
}

function chacha20Encrypt(key: Buffer, nonce: Buffer, plaintext: Uint8Array): Buffer {
  // NIP-44 v2 uses the IETF ChaCha20 variant (12-byte nonce). Node's
  // `chacha20` cipher takes a 16-byte IV (4-byte counter || 12-byte
  // nonce), so we synthesize the IV with counter = 0 and the supplied
  // 12-byte nonce in the tail. This matches RFC 8439 §2.4.
  if (nonce.length !== CHACHA_IV_LEN) {
    throw new Nip44V2Error(
      `ChaCha20 nonce must be ${CHACHA_IV_LEN} bytes (IETF variant); got ${nonce.length}`,
    );
  }
  const iv = Buffer.alloc(16);
  iv.set(nonce, 4);
  try {
    const cipher = createCipheriv("chacha20", key, iv, { authTagLength: 0 });
    return Buffer.concat([cipher.update(plaintext), cipher.final()]);
  } catch (error) {
    throw new Nip44V2Error(
      "ChaCha20 is unavailable in this Node build; the hybrid envelope requires Node 18+ with OpenSSL 3",
      { cause: error },
    );
  }
}

function chacha20Decrypt(key: Buffer, nonce: Buffer, ciphertext: Uint8Array): Buffer {
  if (nonce.length !== CHACHA_IV_LEN) {
    throw new Nip44V2Error(
      `ChaCha20 nonce must be ${CHACHA_IV_LEN} bytes (IETF variant); got ${nonce.length}`,
    );
  }
  const iv = Buffer.alloc(16);
  iv.set(nonce, 4);
  try {
    const decipher = createDecipheriv("chacha20", key, iv, { authTagLength: 0 });
    return Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch (error) {
    throw new Nip44V2Error(
      "ChaCha20 is unavailable in this Node build; the hybrid envelope requires Node 18+ with OpenSSL 3",
      { cause: error },
    );
  }
}

function hmacSha256(key: Buffer, message: Uint8Array): Buffer {
  const h = createHmac("sha256", key);
  h.update(message);
  // Node 16+: h.digest() returns a Buffer; older fallbacks use h.read().
  // `digest()` is the canonical name across all supported Node versions.
  return h.digest();
}

function constantTimeEqual(a: Buffer, b: Buffer): boolean {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) {
    diff |= a[i]! ^ b[i]!;
  }
  return diff === 0;
}

/** Auto-detect a "pqc2:" envelope by prefix. */
export function isPqcNip44Envelope(s: string): boolean {
  return typeof s === "string" && s.startsWith(PREFIX);
}

/** Validate a length-prefix byte string is well-formed. */
function assertMlKemCiphertext(blob: Buffer): void {
  if (blob.length !== ML_KEM_768_CT_BYTES) {
    throw new Nip44V2Error(
      `ML-KEM-768 ciphertext must be ${ML_KEM_768_CT_BYTES} bytes; got ${blob.length}`,
    );
  }
}

function assertMlKemPublicKey(blob: Buffer): void {
  if (blob.length !== ML_KEM_768_PK_BYTES) {
    throw new Nip44V2Error(
      `ML-KEM-768 public key must be ${ML_KEM_768_PK_BYTES} bytes; got ${blob.length}`,
    );
  }
}

function assertMlKemSecretKey(blob: Buffer): void {
  if (blob.length !== ML_KEM_768_SK_BYTES) {
    throw new Nip44V2Error(
      `ML-KEM-768 secret key must be ${ML_KEM_768_SK_BYTES} bytes; got ${blob.length}`,
    );
  }
}

/**
 * Encrypt a UTF-8 plaintext for `recipientPubMlKem` and return the
 * `pqc2:` envelope. The ML-KEM-768 encapsulation produces a 32-byte
 * shared secret that feeds the HKDF conversation-key derivation.
 */
export function encryptNip44V2(recipientPubMlKem: Uint8Array, plaintext: Uint8Array): string {
  if (!(plaintext instanceof Uint8Array)) {
    throw new Nip44V2Error("plaintext must be a Uint8Array");
  }
  assertMlKemPublicKey(Buffer.from(recipientPubMlKem));
  const { sharedSecret, cipherText: kemCt } = ml_kem768.encapsulate(
    new Uint8Array(recipientPubMlKem),
  );
  if (sharedSecret.length !== ML_KEM_768_SS_BYTES) {
    throw new Nip44V2Error(
      `ML-KEM-768 shared secret must be ${ML_KEM_768_SS_BYTES} bytes; got ${sharedSecret.length}`,
    );
  }
  assertMlKemCiphertext(Buffer.from(kemCt));
  const keys = conversationKeys(sharedSecret);
  const padded = pad(plaintext);
  const chachaCt = chacha20Encrypt(keys.chachaKey, keys.chachaNonce, padded);
  const mac = hmacSha256(keys.hmacKey, Buffer.concat([Buffer.from(kemCt), Buffer.from(chachaCt)]));
  return PREFIX + toBase64Url(kemCt) + "." + toBase64Url(chachaCt) + "." + toBase64Url(mac);
}

/** Decrypt a `pqc2:` envelope using the recipient's ML-KEM-768 secret key. */
export function decryptNip44V2(recipientPrivMlKem: Uint8Array, envelope: string): Uint8Array {
  if (typeof envelope !== "string" || !isPqcNip44Envelope(envelope)) {
    throw new Nip44V2Error("envelope must be a pqc2: NIP-44 v2 hybrid envelope");
  }
  assertMlKemSecretKey(Buffer.from(recipientPrivMlKem));
  const body = envelope.slice(PREFIX.length);
  const parts = body.split(".");
  if (parts.length !== 3) {
    throw new Nip44V2Error("envelope must have exactly 3 dot-separated parts");
  }
  const [kemCtB64, chachaCtB64, macB64] = parts as [string, string, string];
  const kemCt = fromBase64Url(kemCtB64, "kemCt");
  const chachaCt = fromBase64Url(chachaCtB64, "chachaCt");
  const mac = fromBase64Url(macB64, "mac");
  assertMlKemCiphertext(kemCt);
  if (mac.length !== HMAC_TAG_LEN) {
    throw new Nip44V2Error(`MAC must be ${HMAC_TAG_LEN} bytes; got ${mac.length}`);
  }
  const sharedSecret = ml_kem768.decapsulate(
    new Uint8Array(kemCt),
    new Uint8Array(recipientPrivMlKem),
  );
  if (sharedSecret.length !== ML_KEM_768_SS_BYTES) {
    throw new Nip44V2Error(
      `ML-KEM-768 shared secret must be ${ML_KEM_768_SS_BYTES} bytes; got ${sharedSecret.length}`,
    );
  }
  const keys = conversationKeys(sharedSecret);
  const expectedMac = hmacSha256(keys.hmacKey, Buffer.concat([kemCt, chachaCt]));
  if (!constantTimeEqual(mac, expectedMac)) {
    throw new Nip44V2Error(
      "HMAC-SHA256 authentication failed — wrong key, tampered ciphertext, or wrong ML-KEM ciphertext",
    );
  }
  const padded = chacha20Decrypt(keys.chachaKey, keys.chachaNonce, chachaCt);
  return unpad(padded);
}
