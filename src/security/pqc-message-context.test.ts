import { ml_kem768 } from "@noble/post-quantum/ml-kem.js";
import { describe, expect, it } from "vitest";
import { decryptNip44V2, encryptNip44V2, type PqcMessageContext } from "./nip44-v2.js";

describe("experimental context-bound PQC messages", () => {
  const pair = ml_kem768.keygen();
  const context: PqcMessageContext = {
    senderPubkey: "a".repeat(64),
    recipientPubkey: "b".repeat(64),
    purpose: "nostr-dm",
  };
  it("round-trips with the locally reconstructed outer-event identities", () => {
    const ciphertext = encryptNip44V2(
      pair.publicKey,
      new TextEncoder().encode("private message"),
      context,
    );
    expect(ciphertext.startsWith("pqc3:")).toBe(true);
    expect(new TextDecoder().decode(decryptNip44V2(pair.secretKey, ciphertext, context))).toBe(
      "private message",
    );
    expect(() => decryptNip44V2(pair.secretKey, ciphertext)).toThrow("context");
    expect(() =>
      decryptNip44V2(pair.secretKey, ciphertext, { ...context, senderPubkey: "c".repeat(64) }),
    ).toThrow("binding");
    expect(() =>
      decryptNip44V2(pair.secretKey, ciphertext, { ...context, recipientPubkey: "c".repeat(64) }),
    ).toThrow("binding");
    expect(() => decryptNip44V2(ml_kem768.keygen().secretKey, ciphertext, context)).toThrow(
      "binding",
    );
  });
  it("requires explicit legacy decoding and rejects tampering before plaintext release", () => {
    const ciphertext = encryptNip44V2(pair.publicKey, new TextEncoder().encode("hello"), context);
    const parts = ciphertext.slice(5).split(".");
    const mac = Buffer.from(parts[3]!, "base64url");
    mac[0] = mac[0]! ^ 1;
    parts[3] = mac.toString("base64url");
    expect(() => decryptNip44V2(pair.secretKey, "pqc3:" + parts.join("."), context)).toThrow(
      "authentication",
    );
    const legacy = encryptNip44V2(pair.publicKey, new TextEncoder().encode("legacy"));
    expect(() => decryptNip44V2(pair.secretKey, legacy, context)).toThrow("context");
    expect(() => decryptNip44V2(pair.secretKey, legacy + "=")).toThrow("base64url");
  });
});
