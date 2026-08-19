// M10 (PQC migration, whitepaper 1.1): Nostr NIP-44 v2 + ML-KEM-768 invariants.
//
// 17 invariants covering: round-trip on a representative plaintext, the
// HKDF conversation-key derivation shape, the precise NIP-44 v2 padding
// modulus (padded.length - 2) % 32, ChaCha20 round-trip, ML-KEM-768
// encapsulation/decapsulation, the pqc2: wire format, MAC failure when
// any single byte of the wire is tampered with, ML-KEM-768 ciphertext
// length validation, and auto-detection of the envelope.
import { randomBytes } from "node:crypto";
import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { afterEach, describe, expect, it } from "vitest";
import {
  decryptNip44V2,
  deriveConversationKey,
  encryptNip44V2,
  isPqcNip44Envelope,
  Nip44V2Error,
  NIP44_V2_PQC,
  pad,
  unpad,
} from "./nip44-v2.js";

afterEach(() => {
  // no-op
});

function genMlKem768Keypair(): { publicKey: Uint8Array; secretKey: Uint8Array } {
  return ml_kem768.keygen();
}

describe("nip44-v2 (M10, whitepaper 1.1)", () => {
  it("exposes the canonical constants for the hybrid envelope", () => {
    expect(NIP44_V2_PQC.PREFIX).toBe("pqc2:");
    expect(NIP44_V2_PQC.HMAC_KEY_LEN).toBe(32);
    expect(NIP44_V2_PQC.CHACHA_KEY_LEN).toBe(32);
    expect(NIP44_V2_PQC.CHACHA_IV_LEN).toBe(12);
    expect(NIP44_V2_PQC.PAD_ALIGNMENT).toBe(32);
    expect(NIP44_V2_PQC.LENGTH_PREFIX_BYTES).toBe(2);
    expect(NIP44_V2_PQC.ML_KEM_768_CT_BYTES).toBe(1088);
    expect(NIP44_V2_PQC.ML_KEM_768_SS_BYTES).toBe(32);
    expect(NIP44_V2_PQC.ML_KEM_768_PK_BYTES).toBe(1184);
    expect(NIP44_V2_PQC.ML_KEM_768_SK_BYTES).toBe(2400);
    expect(NIP44_V2_PQC.HMAC_TAG_LEN).toBe(32);
  });

  it("isPqcNip44Envelope auto-detects the pqc2: prefix and rejects everything else", () => {
    expect(isPqcNip44Envelope("pqc2:abc.def.ghi")).toBe(true);
    expect(isPqcNip44Envelope("")).toBe(false);
    expect(isPqcNip44Envelope("v2:abc")).toBe(false);
    expect(
      isPqcNip44Envelope("nsec1xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"),
    ).toBe(false);
  });

  it("deriveConversationKey produces a 76-byte OKM (32 hmac + 32 chacha + 12 nonce)", () => {
    const ss = new Uint8Array(32);
    const okm = deriveConversationKey(ss);
    expect(okm.length).toBe(76);
  });

  it("deriveConversationKey rejects a sharedSecret of the wrong length", () => {
    expect(() => deriveConversationKey(new Uint8Array(16))).toThrow(/32-byte Uint8Array/);
  });

  it("pad pads a 1-byte plaintext to 32 bytes and unpad round-trips", () => {
    const pt = new TextEncoder().encode("x");
    const padded = pad(pt);
    expect(padded.length).toBe(32);
    // Total length is a multiple of 32 — this is the NIP-44 v2 modulus.
    expect(padded.length % 32).toBe(0);
    const recovered = unpad(padded);
    expect(new TextDecoder().decode(recovered)).toBe("x");
  });

  it("pad pads a 30-byte plaintext to 32 bytes (one length-byte + 30 bytes of content)", () => {
    const pt = new Uint8Array(30);
    const padded = pad(pt);
    expect(padded.length).toBe(32);
    expect(padded.length % 32).toBe(0);
    const recovered = unpad(padded);
    expect(recovered.length).toBe(30);
  });

  it("pad pads a 33-byte plaintext to 64 bytes (length-prefix overflows first 32-byte block)", () => {
    const pt = new Uint8Array(33);
    const padded = pad(pt);
    expect(padded.length).toBe(64);
    expect(padded.length % 32).toBe(0);
    const recovered = unpad(padded);
    expect(recovered.length).toBe(33);
  });

  it("unpad rejects a payload whose length is not a multiple of 32", () => {
    const bogus = new Uint8Array(33); // 33 % 32 !== 0
    bogus[0] = 0;
    bogus[1] = 1;
    expect(() => unpad(bogus)).toThrow(/padded length modulus check failed/);
  });

  it("unpad rejects a payload whose declared length is out of range", () => {
    const padded = new Uint8Array(32);
    // length = 0, which is below MIN_PLAINTEXT_LEN = 1.
    padded[0] = 0;
    padded[1] = 0;
    expect(() => unpad(padded)).toThrow(/padded length field out of range/);
  });

  it("encryptNip44V2 + decryptNip44V2 round-trips a UTF-8 payload", () => {
    const kp = genMlKem768Keypair();
    const plaintext = new TextEncoder().encode("Hello, post-quantum Nostr!");
    const envelope = encryptNip44V2(kp.publicKey, plaintext);
    expect(isPqcNip44Envelope(envelope)).toBe(true);
    expect(envelope).toMatch(/^pqc2:[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/);
    const recovered = decryptNip44V2(kp.secretKey, envelope);
    expect(new TextDecoder().decode(recovered)).toBe("Hello, post-quantum Nostr!");
  });

  it("encryptNip44V2 produces an ML-KEM-768 ciphertext of exactly 1088 bytes (after base64url decode)", () => {
    const kp = genMlKem768Keypair();
    const envelope = encryptNip44V2(kp.publicKey, new TextEncoder().encode("a"));
    const parts = envelope.slice("pqc2:".length).split(".");
    const kemCtLen = Buffer.from(parts[0]!, "base64url").length;
    expect(kemCtLen).toBe(1088);
  });

  it("decryptNip44V2 rejects a tampered ML-KEM-768 ciphertext (MAC failure)", () => {
    const kp = genMlKem768Keypair();
    const envelope = encryptNip44V2(kp.publicKey, new TextEncoder().encode("a"));
    const parts = envelope.slice("pqc2:".length).split(".");
    const kemCt = Buffer.from(parts[0]!, "base64url");
    // Flip one bit at a random position inside the ML-KEM ciphertext.
    kemCt[100] = (kemCt[100]! ^ 0x01) & 0xff;
    const tampered = "pqc2:" + kemCt.toString("base64url") + "." + parts[1] + "." + parts[2];
    expect(() => decryptNip44V2(kp.secretKey, tampered)).toThrow(
      /HMAC-SHA256 authentication failed/,
    );
  });

  it("decryptNip44V2 rejects a tampered ChaCha20 ciphertext (MAC failure)", () => {
    const kp = genMlKem768Keypair();
    const envelope = encryptNip44V2(kp.publicKey, new TextEncoder().encode("a"));
    const parts = envelope.slice("pqc2:".length).split(".");
    const chachaCt = Buffer.from(parts[1]!, "base64url");
    chachaCt[0] = (chachaCt[0]! ^ 0x01) & 0xff;
    const tampered = "pqc2:" + parts[0] + "." + chachaCt.toString("base64url") + "." + parts[2];
    expect(() => decryptNip44V2(kp.secretKey, tampered)).toThrow(
      /HMAC-SHA256 authentication failed/,
    );
  });

  it("decryptNip44V2 rejects a tampered MAC (HMAC failure)", () => {
    const kp = genMlKem768Keypair();
    const envelope = encryptNip44V2(kp.publicKey, new TextEncoder().encode("a"));
    const parts = envelope.slice("pqc2:".length).split(".");
    const mac = Buffer.from(parts[2]!, "base64url");
    mac[0] = (mac[0]! ^ 0x01) & 0xff;
    const tampered = "pqc2:" + parts[0] + "." + parts[1] + "." + mac.toString("base64url");
    expect(() => decryptNip44V2(kp.secretKey, tampered)).toThrow(
      /HMAC-SHA256 authentication failed/,
    );
  });

  it("decryptNip44V2 rejects an envelope that is not in the pqc2: format", () => {
    const kp = genMlKem768Keypair();
    expect(() => decryptNip44V2(kp.secretKey, "v2:abc.def.ghi")).toThrow(/pqc2:/);
  });

  it("encryptNip44V2 rejects a recipient public key of the wrong length", () => {
    expect(() => encryptNip44V2(new Uint8Array(16), new TextEncoder().encode("a"))).toThrow(
      /public key must be 1184 bytes/,
    );
  });

  it("decryptNip44V2 rejects a recipient secret key of the wrong length", () => {
    expect(() => decryptNip44V2(new Uint8Array(16), "pqc2:aaa.bbb.ccc")).toThrow(
      /secret key must be 2400 bytes/,
    );
  });

  it("decryptNip44V2 rejects a malformed envelope (missing dot)", () => {
    const kp = genMlKem768Keypair();
    expect(() => decryptNip44V2(kp.secretKey, "pqc2:no-dots-here")).toThrow(/3 dot-separated/);
  });
});
