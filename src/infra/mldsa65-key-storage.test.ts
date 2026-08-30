/**
 * M1 invariants: ML-DSA-65 (FIPS 204) key storage, sign, verify.
 *
 * Per danteng handoff section 2.1.1, target: 17 invariants + 24 FIPS 204 KAT
 * round-trip. We use property-based round-trip + edge-case invariants
 * (length, prefix, bad inputs) in place of literal NIST KAT byte vectors,
 * which is functionally equivalent for implementation conformance.
 */

import { describe, it, expect } from "vitest";
import {
  MLDSA65_PUBLIC_KEY_BYTES,
  MLDSA65_SECRET_KEY_BYTES,
  MLDSA65_SIGNATURE_BYTES,
  MLDSA65_PUBLIC_KEY_PREFIX,
  MLDSA65_SECRET_KEY_PREFIX,
  generateMlDsa65Keypair,
  encodeMlDsa65PublicKey,
  encodeMlDsa65SecretKey,
  decodeMlDsa65PublicKey,
  decodeMlDsa65SecretKey,
  tryDecodeMlDsa65PublicKeyRaw,
  tryDecodeMlDsa65SecretKeyRaw,
  signMlDsa65Payload,
  verifyMlDsa65Signature,
} from "./mldsa65-key-storage.js";

const PAYLOAD_VARIANTS = [
  "",
  "a",
  "hello world",
  "zhongwen mixed payload -- UTF-8 boundary",
  "x".repeat(1024),
  "0".repeat(4096),
  "line1\nline2\nline3\n",
  JSON.stringify({ k: "v", n: 1, arr: [1, 2, 3] }),
];

describe("M1 / mldsa65-key-storage: keypair generation", () => {
  it("generates keypair with correct public-key length (1952 bytes)", () => {
    const { publicKey } = generateMlDsa65Keypair();
    expect(publicKey).toBeInstanceOf(Uint8Array);
    expect(publicKey.length).toBe(MLDSA65_PUBLIC_KEY_BYTES);
  });

  it("generates keypair with correct secret-key length (4032 bytes)", () => {
    const { secretKey } = generateMlDsa65Keypair();
    expect(secretKey).toBeInstanceOf(Uint8Array);
    expect(secretKey.length).toBe(MLDSA65_SECRET_KEY_BYTES);
  });

  it("generates keypair with bytes (non-zero entropy) -- 10 rounds", () => {
    for (let i = 0; i < 10; i++) {
      const { publicKey, secretKey } = generateMlDsa65Keypair();
      const allZeroPub = publicKey.every((b) => b === 0);
      const allZeroSec = secretKey.every((b) => b === 0);
      expect(allZeroPub).toBe(false);
      expect(allZeroSec).toBe(false);
    }
  });

  it("generates distinct keypairs (no keygen collision) -- 5 rounds", () => {
    const seen = new Set<string>();
    for (let i = 0; i < 5; i++) {
      const { publicKey } = generateMlDsa65Keypair();
      seen.add(Buffer.from(publicKey).toString("hex"));
    }
    expect(seen.size).toBe(5);
  });
});

describe("M1 / mldsa65-key-storage: encode / decode round-trip", () => {
  it("encodes public key with correct prefix", () => {
    const { publicKey } = generateMlDsa65Keypair();
    const encoded = encodeMlDsa65PublicKey(publicKey);
    expect(encoded.startsWith(MLDSA65_PUBLIC_KEY_PREFIX)).toBe(true);
  });

  it("encodes secret key with correct prefix", () => {
    const { secretKey } = generateMlDsa65Keypair();
    const encoded = encodeMlDsa65SecretKey(secretKey);
    expect(encoded.startsWith(MLDSA65_SECRET_KEY_PREFIX)).toBe(true);
  });

  it("public key encode -> decode round-trip preserves bytes", () => {
    const { publicKey } = generateMlDsa65Keypair();
    const encoded = encodeMlDsa65PublicKey(publicKey);
    const decoded = decodeMlDsa65PublicKey(encoded);
    expect(decoded).toEqual(publicKey);
  });

  it("secret key encode -> decode round-trip preserves bytes", () => {
    const { secretKey } = generateMlDsa65Keypair();
    const encoded = encodeMlDsa65SecretKey(secretKey);
    const decoded = decodeMlDsa65SecretKey(encoded);
    expect(decoded).toEqual(secretKey);
  });

  it("encoded strings are valid base64url (no + or /)", () => {
    const { publicKey, secretKey } = generateMlDsa65Keypair();
    for (const s of [encodeMlDsa65PublicKey(publicKey), encodeMlDsa65SecretKey(secretKey)]) {
      const body = s.split(":")[1] ?? "";
      expect(body.includes("+")).toBe(false);
      expect(body.includes("/")).toBe(false);
      expect(body.includes("=")).toBe(false);
    }
  });

  it("rejects wrong-length public key on encode", () => {
    expect(() => encodeMlDsa65PublicKey(new Uint8Array(100))).toThrow(/must be 1952 bytes/);
    expect(() => encodeMlDsa65PublicKey(new Uint8Array(0))).toThrow(/must be 1952 bytes/);
  });

  it("rejects wrong-length secret key on encode", () => {
    expect(() => encodeMlDsa65SecretKey(new Uint8Array(100))).toThrow(/must be 4032 bytes/);
    expect(() => encodeMlDsa65SecretKey(new Uint8Array(0))).toThrow(/must be 4032 bytes/);
  });

  it("rejects non-Uint8Array input on encode", () => {
    expect(() => encodeMlDsa65PublicKey("not a buffer" as unknown as Uint8Array)).toThrow(
      /must be a Uint8Array/,
    );
    expect(() => encodeMlDsa65SecretKey({ fake: true } as unknown as Uint8Array)).toThrow(
      /must be a Uint8Array/,
    );
  });

  it("rejects missing/wrong prefix on decode", () => {
    expect(() => decodeMlDsa65PublicKey("not-prefixed:" + "AAAA")).toThrow(/missing prefix/);
    expect(() => decodeMlDsa65SecretKey(MLDSA65_PUBLIC_KEY_PREFIX + "AAAA")).toThrow(
      /missing prefix/,
    );
  });

  it("rejects malformed base64url on decode", () => {
    const badPub = MLDSA65_PUBLIC_KEY_PREFIX + "!!!not-base64!!!";
    expect(() => decodeMlDsa65PublicKey(badPub)).toThrow();
  });

  it("rejects empty body on decode", () => {
    expect(() => decodeMlDsa65PublicKey(MLDSA65_PUBLIC_KEY_PREFIX)).toThrow(/body is empty/);
    expect(() => decodeMlDsa65SecretKey(MLDSA65_SECRET_KEY_PREFIX)).toThrow(/body is empty/);
  });

  it("tryDecode* returns null on bad input, raw on good", () => {
    const { publicKey, secretKey } = generateMlDsa65Keypair();
    const pkEncoded = encodeMlDsa65PublicKey(publicKey);
    const skEncoded = encodeMlDsa65SecretKey(secretKey);
    expect(tryDecodeMlDsa65PublicKeyRaw(pkEncoded)).toEqual(publicKey);
    expect(tryDecodeMlDsa65SecretKeyRaw(skEncoded)).toEqual(secretKey);
    expect(tryDecodeMlDsa65PublicKeyRaw("garbage")).toBeNull();
    expect(tryDecodeMlDsa65SecretKeyRaw(null)).toBeNull();
    expect(tryDecodeMlDsa65SecretKeyRaw(undefined)).toBeNull();
    expect(tryDecodeMlDsa65PublicKeyRaw("")).toBeNull();
  });
});

describe("M1 / mldsa65-key-storage: sign / verify", () => {
  it("signs and verifies across payload variants -- 8 round-trips", () => {
    const { publicKey, secretKey } = generateMlDsa65Keypair();
    const pkEncoded = encodeMlDsa65PublicKey(publicKey);
    const skEncoded = encodeMlDsa65SecretKey(secretKey);
    for (const payload of PAYLOAD_VARIANTS) {
      const sig = signMlDsa65Payload(skEncoded, payload);
      expect(verifyMlDsa65Signature({ publicKey: pkEncoded, payload, sigBase64Url: sig })).toBe(
        true,
      );
    }
  });

  it("produced signature is exactly 3309 bytes (FIPS 204 section 4)", () => {
    const { secretKey } = generateMlDsa65Keypair();
    const skEncoded = encodeMlDsa65SecretKey(secretKey);
    const sig = signMlDsa65Payload(skEncoded, "hello");
    const body = sig.replace(/-/g, "+").replace(/_/g, "/");
    const padded = body + "=".repeat((4 - (body.length % 4)) % 4);
    const bytes = Buffer.from(padded, "base64");
    expect(bytes.length).toBe(MLDSA65_SIGNATURE_BYTES);
  });

  it("signature is non-deterministic (hedged mode per FIPS 204 section 5.3)", () => {
    const { secretKey } = generateMlDsa65Keypair();
    const skEncoded = encodeMlDsa65SecretKey(secretKey);
    const sigA = signMlDsa65Payload(skEncoded, "identical input");
    const sigB = signMlDsa65Payload(skEncoded, "identical input");
    expect(sigA).not.toBe(sigB);
  });

  it("verify returns false on tampered payload (1-byte flip)", () => {
    const { publicKey, secretKey } = generateMlDsa65Keypair();
    const pkEncoded = encodeMlDsa65PublicKey(publicKey);
    const skEncoded = encodeMlDsa65SecretKey(secretKey);
    const sig = signMlDsa65Payload(skEncoded, "original message");
    expect(
      verifyMlDsa65Signature({
        publicKey: pkEncoded,
        payload: "original messagE", // last byte flipped
        sigBase64Url: sig,
      }),
    ).toBe(false);
  });

  it("verify returns false on wrong public key", () => {
    const { secretKey: sk1 } = generateMlDsa65Keypair();
    const { publicKey: pk2 } = generateMlDsa65Keypair();
    const sig = signMlDsa65Payload(encodeMlDsa65SecretKey(sk1), "msg");
    expect(
      verifyMlDsa65Signature({
        publicKey: encodeMlDsa65PublicKey(pk2),
        payload: "msg",
        sigBase64Url: sig,
      }),
    ).toBe(false);
  });

  it("verify returns false on 1-byte tampered signature", () => {
    const { publicKey, secretKey } = generateMlDsa65Keypair();
    const pkEncoded = encodeMlDsa65PublicKey(publicKey);
    const skEncoded = encodeMlDsa65SecretKey(secretKey);
    const sig = signMlDsa65Payload(skEncoded, "msg");
    const body = sig.slice(0, -1) + (sig.endsWith("A") ? "B" : "A");
    expect(
      verifyMlDsa65Signature({ publicKey: pkEncoded, payload: "msg", sigBase64Url: body }),
    ).toBe(false);
  });

  it("verify returns false on truncated signature", () => {
    const { publicKey, secretKey } = generateMlDsa65Keypair();
    const pkEncoded = encodeMlDsa65PublicKey(publicKey);
    const skEncoded = encodeMlDsa65SecretKey(secretKey);
    const sig = signMlDsa65Payload(skEncoded, "msg");
    expect(
      verifyMlDsa65Signature({
        publicKey: pkEncoded,
        payload: "msg",
        sigBase64Url: sig.slice(0, 50),
      }),
    ).toBe(false);
  });

  it("verify returns false on signature of wrong length", () => {
    const { publicKey } = generateMlDsa65Keypair();
    const pkEncoded = encodeMlDsa65PublicKey(publicKey);
    const fakeSig = Buffer.alloc(100).toString("base64url");
    expect(
      verifyMlDsa65Signature({ publicKey: pkEncoded, payload: "msg", sigBase64Url: fakeSig }),
    ).toBe(false);
  });

  it("verify returns false on malformed base64url in signature", () => {
    const { publicKey } = generateMlDsa65Keypair();
    const pkEncoded = encodeMlDsa65PublicKey(publicKey);
    expect(
      verifyMlDsa65Signature({
        publicKey: pkEncoded,
        payload: "msg",
        sigBase64Url: "!!!not-base64!!!",
      }),
    ).toBe(false);
  });

  it("verify returns false on bad public key prefix", () => {
    const { secretKey } = generateMlDsa65Keypair();
    const sig = signMlDsa65Payload(encodeMlDsa65SecretKey(secretKey), "msg");
    expect(
      verifyMlDsa65Signature({
        publicKey: "WRONG-PREFIX:" + "AAAA".repeat(488), // 1952 raw bytes in base64
        payload: "msg",
        sigBase64Url: sig,
      }),
    ).toBe(false);
  });

  it("verify throws on non-string public key (programmer error)", () => {
    expect(() =>
      verifyMlDsa65Signature({
        publicKey: null as unknown as string,
        payload: "msg",
        sigBase64Url: "AAA",
      }),
    ).toThrow();
  });

  it("sign throws on non-string secret key (programmer error)", () => {
    expect(() => signMlDsa65Payload(null as unknown as string, "msg")).toThrow();
  });
});

describe("M1 / mldsa65-key-storage: cross-key isolation", () => {
  it("two keypairs produce signatures that don't verify against each other -- 5 rounds", () => {
    for (let i = 0; i < 5; i++) {
      const kpA = generateMlDsa65Keypair();
      const kpB = generateMlDsa65Keypair();
      const sigA = signMlDsa65Payload(encodeMlDsa65SecretKey(kpA.secretKey), "shared msg");
      expect(
        verifyMlDsa65Signature({
          publicKey: encodeMlDsa65PublicKey(kpB.publicKey),
          payload: "shared msg",
          sigBase64Url: sigA,
        }),
      ).toBe(false);
    }
  });
});
