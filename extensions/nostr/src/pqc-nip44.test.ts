import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { describe, expect, it } from "vitest";
import {
  decodeMlKemPublicKey,
  decodeMlKemSecretKey,
  decryptNip44V2,
  deriveMlKemPublicKey,
  encryptNip44V2,
} from "./pqc-nip44.js";

describe("Nostr ML-KEM-768 envelopes", () => {
  it("round-trips a production pqc2 direct-message envelope", () => {
    const keyPair = ml_kem768.keygen();
    const envelope = encryptNip44V2(keyPair.publicKey, new TextEncoder().encode("hello PQC"));

    expect(envelope).toMatch(/^pqc2:/);
    expect(new TextDecoder().decode(decryptNip44V2(keyPair.secretKey, envelope))).toBe("hello PQC");
  });

  it("loads canonical base64url keys and derives the matching public key", () => {
    const keyPair = ml_kem768.keygen();
    const publicKey = decodeMlKemPublicKey(Buffer.from(keyPair.publicKey).toString("base64url"));
    const secretKey = decodeMlKemSecretKey(Buffer.from(keyPair.secretKey).toString("base64url"));

    expect(deriveMlKemPublicKey(secretKey)).toEqual(publicKey);
  });

  it("rejects malformed and wrong-sized configured keys", () => {
    expect(() => decodeMlKemPublicKey("not+a+base64url+key")).toThrow("not valid base64url");
    expect(() => decodeMlKemSecretKey(Buffer.alloc(32).toString("base64url"))).toThrow(
      "must be 2400 bytes",
    );
  });
});
