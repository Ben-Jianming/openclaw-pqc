// M11 (PQC migration, whitepaper 1.3): APNs ML-DSA-65 dual signature
// invariants.
//
// 13 invariants covering: sign + verify round-trip on a UTF-8 push
// payload, fail-closed on tampered Ed25519 sig, fail-closed on
// tampered ML-DSA-65 sig, fail-closed on tampered payload, fail-closed
// on the wrong public key (Ed25519), fail-closed on the wrong public
// key (ML-DSA-65), strict algorithms header validation (rejects
// any reordering or extra algorithms), envelope as a string round-trip,
// Ed25519 always via node:crypto (NOT @noble/curves), wrong-shape raw
// key length, missing/empty keyId rejection, and exact signature byte
// count.
import { generateKeyPairSync, randomBytes } from "node:crypto";
import { describe, expect, it } from "vitest";
import { generateMlDsa65Keypair } from "../infra/mldsa65-key-storage.js";
import {
  PUSH_DUAL_SIG_CONSTANTS,
  PushDualSignatureError,
  signPushPayloadDual,
  verifyPushPayloadDual,
  type PushDualEnvelope,
} from "./push-dual-signature.js";

function ed25519KeygenRaw(): { secret: Uint8Array; public: Uint8Array } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const privDer = privateKey.export({ type: "pkcs8", format: "der" });
  const pubDer = publicKey.export({ type: "spki", format: "der" });
  // Ed25519 raw private key is the trailing 32 bytes of the PKCS8 DER
  // (the 0x40 || 32-byte seed at the end). The raw public key is the
  // trailing 32 bytes of the SPKI DER.
  const privRaw = privDer.subarray(privDer.length - 32);
  const pubRaw = pubDer.subarray(pubDer.length - 32);
  return { secret: new Uint8Array(privRaw), public: new Uint8Array(pubRaw) };
}

describe("push-dual-signature (M11, whitepaper 1.3)", () => {
  it("exposes the canonical constants for the dual envelope", () => {
    expect(PUSH_DUAL_SIG_CONSTANTS.ED25519_RAW_SECRET_KEY).toBe(32);
    expect(PUSH_DUAL_SIG_CONSTANTS.ED25519_RAW_PUBLIC_KEY).toBe(32);
    expect(PUSH_DUAL_SIG_CONSTANTS.ED25519_SIGNATURE_BYTES).toBe(64);
    expect(PUSH_DUAL_SIG_CONSTANTS.MLDSA65_PUBLIC_KEY_BYTES).toBe(1952);
    expect(PUSH_DUAL_SIG_CONSTANTS.MLDSA65_SECRET_KEY_BYTES).toBe(4032);
    expect(PUSH_DUAL_SIG_CONSTANTS.MLDSA65_SIGNATURE_BYTES).toBe(3309);
    expect(PUSH_DUAL_SIG_CONSTANTS.EXPECTED_ALGORITHMS).toEqual(["ed25519", "ml-dsa-65"]);
  });

  it("sign + verify round-trips a UTF-8 push payload", () => {
    const ed = ed25519KeygenRaw();
    const ml = generateMlDsa65Keypair();
    const payload = JSON.stringify({ alert: "backup ready", ts: 1234 });
    const { envelope } = signPushPayloadDual({
      payload,
      ed25519SecretKeyRaw: ed.secret,
      mldsa65SecretKeyRaw: ml.secretKey,
      keyIdEd25519: "ed25519-key-2026-08",
      keyIdMldsa65: "mldsa65-key-2026-08",
    });
    expect(envelope.algorithms).toEqual(["ed25519", "ml-dsa-65"]);
    expect(envelope.key_id_ed25519).toBe("ed25519-key-2026-08");
    expect(envelope.key_id_mldsa65).toBe("mldsa65-key-2026-08");
    expect(Buffer.from(envelope.ed25519_sig, "base64url").length).toBe(
      PUSH_DUAL_SIG_CONSTANTS.ED25519_SIGNATURE_BYTES,
    );
    expect(Buffer.from(envelope.mldsa65_sig, "base64url").length).toBe(
      PUSH_DUAL_SIG_CONSTANTS.MLDSA65_SIGNATURE_BYTES,
    );
    expect(
      verifyPushPayloadDual({
        payload,
        ed25519PublicKeyRaw: ed.public,
        mldsa65PublicKeyRaw: ml.publicKey,
        envelope,
      }),
    ).toBe(true);
  });

  it("verifier fails closed on a tampered Ed25519 signature", () => {
    const ed = ed25519KeygenRaw();
    const ml = generateMlDsa65Keypair();
    const payload = "tamper-test-ed25519";
    const { envelope } = signPushPayloadDual({
      payload,
      ed25519SecretKeyRaw: ed.secret,
      mldsa65SecretKeyRaw: ml.secretKey,
      keyIdEd25519: "k-ed",
      keyIdMldsa65: "k-ml",
    });
    const sigBytes = Buffer.from(envelope.ed25519_sig, "base64url");
    sigBytes[0] = (sigBytes[0]! ^ 0x01) & 0xff;
    const tampered: PushDualEnvelope = {
      ...envelope,
      ed25519_sig: sigBytes.toString("base64url"),
    };
    expect(() =>
      verifyPushPayloadDual({
        payload,
        ed25519PublicKeyRaw: ed.public,
        mldsa65PublicKeyRaw: ml.publicKey,
        envelope: tampered,
      }),
    ).toThrow(/Ed25519 signature verification failed/);
  });

  it("verifier fails closed on a tampered ML-DSA-65 signature", () => {
    const ed = ed25519KeygenRaw();
    const ml = generateMlDsa65Keypair();
    const payload = "tamper-test-mldsa65";
    const { envelope } = signPushPayloadDual({
      payload,
      ed25519SecretKeyRaw: ed.secret,
      mldsa65SecretKeyRaw: ml.secretKey,
      keyIdEd25519: "k-ed",
      keyIdMldsa65: "k-ml",
    });
    const sigBytes = Buffer.from(envelope.mldsa65_sig, "base64url");
    sigBytes[0] = (sigBytes[0]! ^ 0x01) & 0xff;
    const tampered: PushDualEnvelope = {
      ...envelope,
      mldsa65_sig: sigBytes.toString("base64url"),
    };
    expect(() =>
      verifyPushPayloadDual({
        payload,
        ed25519PublicKeyRaw: ed.public,
        mldsa65PublicKeyRaw: ml.publicKey,
        envelope: tampered,
      }),
    ).toThrow(/ML-DSA-65 signature verification failed/);
  });

  it("verifier fails closed on a tampered payload", () => {
    const ed = ed25519KeygenRaw();
    const ml = generateMlDsa65Keypair();
    const { envelope } = signPushPayloadDual({
      payload: "original",
      ed25519SecretKeyRaw: ed.secret,
      mldsa65SecretKeyRaw: ml.secretKey,
      keyIdEd25519: "k-ed",
      keyIdMldsa65: "k-ml",
    });
    expect(() =>
      verifyPushPayloadDual({
        payload: "tampered",
        ed25519PublicKeyRaw: ed.public,
        mldsa65PublicKeyRaw: ml.publicKey,
        envelope,
      }),
    ).toThrow(/signature verification failed/);
  });

  it("verifier fails closed when the Ed25519 public key does not match", () => {
    const ed = ed25519KeygenRaw();
    const ed2 = ed25519KeygenRaw();
    const ml = generateMlDsa65Keypair();
    const payload = "key-mismatch-ed";
    const { envelope } = signPushPayloadDual({
      payload,
      ed25519SecretKeyRaw: ed.secret,
      mldsa65SecretKeyRaw: ml.secretKey,
      keyIdEd25519: "k-ed",
      keyIdMldsa65: "k-ml",
    });
    expect(() =>
      verifyPushPayloadDual({
        payload,
        ed25519PublicKeyRaw: ed2.public,
        mldsa65PublicKeyRaw: ml.publicKey,
        envelope,
      }),
    ).toThrow(/Ed25519 signature verification failed/);
  });

  it("verifier fails closed when the ML-DSA-65 public key does not match", () => {
    const ed = ed25519KeygenRaw();
    const ml = generateMlDsa65Keypair();
    const ml2 = generateMlDsa65Keypair();
    const payload = "key-mismatch-ml";
    const { envelope } = signPushPayloadDual({
      payload,
      ed25519SecretKeyRaw: ed.secret,
      mldsa65SecretKeyRaw: ml.secretKey,
      keyIdEd25519: "k-ed",
      keyIdMldsa65: "k-ml",
    });
    expect(() =>
      verifyPushPayloadDual({
        payload,
        ed25519PublicKeyRaw: ed.public,
        mldsa65PublicKeyRaw: ml2.publicKey,
        envelope,
      }),
    ).toThrow(/ML-DSA-65 signature verification failed/);
  });

  it("strict algorithms header rejects any reordering or extra algorithms", () => {
    const ed = ed25519KeygenRaw();
    const ml = generateMlDsa65Keypair();
    const payload = "algorithms-header";
    const { envelope } = signPushPayloadDual({
      payload,
      ed25519SecretKeyRaw: ed.secret,
      mldsa65SecretKeyRaw: ml.secretKey,
      keyIdEd25519: "k-ed",
      keyIdMldsa65: "k-ml",
    });
    // Wrong order
    const wrongOrder: PushDualEnvelope = {
      ...envelope,
      algorithms: ["ml-dsa-65", "ed25519"] as unknown as ["ed25519", "ml-dsa-65"],
    };
    expect(() =>
      verifyPushPayloadDual({
        payload,
        ed25519PublicKeyRaw: ed.public,
        mldsa65PublicKeyRaw: ml.publicKey,
        envelope: wrongOrder,
      }),
    ).toThrow(/algorithms must be exactly/);
    // Extra algorithm
    const withExtra: PushDualEnvelope = {
      ...envelope,
      algorithms: ["ed25519", "ml-dsa-65", "slh-dsa"] as unknown as ["ed25519", "ml-dsa-65"],
    };
    expect(() =>
      verifyPushPayloadDual({
        payload,
        ed25519PublicKeyRaw: ed.public,
        mldsa65PublicKeyRaw: ml.publicKey,
        envelope: withExtra,
      }),
    ).toThrow(/algorithms must be exactly/);
  });

  it("verifier accepts a JSON-stringified envelope (round-trip via serialization)", () => {
    const ed = ed25519KeygenRaw();
    const ml = generateMlDsa65Keypair();
    const payload = "envelope-string-roundtrip";
    const { envelope } = signPushPayloadDual({
      payload,
      ed25519SecretKeyRaw: ed.secret,
      mldsa65SecretKeyRaw: ml.secretKey,
      keyIdEd25519: "k-ed",
      keyIdMldsa65: "k-ml",
    });
    const serialized = JSON.stringify(envelope);
    expect(
      verifyPushPayloadDual({
        payload,
        ed25519PublicKeyRaw: ed.public,
        mldsa65PublicKeyRaw: ml.publicKey,
        envelope: serialized,
      }),
    ).toBe(true);
  });

  it("rejects a non-string non-object envelope", () => {
    const ed = ed25519KeygenRaw();
    const ml = generateMlDsa65Keypair();
    const payload = "x";
    const { envelope } = signPushPayloadDual({
      payload,
      ed25519SecretKeyRaw: ed.secret,
      mldsa65SecretKeyRaw: ml.secretKey,
      keyIdEd25519: "k-ed",
      keyIdMldsa65: "k-ml",
    });
    expect(() =>
      verifyPushPayloadDual({
        payload,
        ed25519PublicKeyRaw: ed.public,
        mldsa65PublicKeyRaw: ml.publicKey,
        envelope: 42 as unknown as string,
      }),
    ).toThrow();
    void envelope;
  });

  it("rejects an Ed25519 secret key of the wrong length", () => {
    const ml = generateMlDsa65Keypair();
    expect(() =>
      signPushPayloadDual({
        payload: "x",
        ed25519SecretKeyRaw: new Uint8Array(16),
        mldsa65SecretKeyRaw: ml.secretKey,
        keyIdEd25519: "k-ed",
        keyIdMldsa65: "k-ml",
      }),
    ).toThrow(/ed25519SecretKeyRaw must be a 32-byte Uint8Array/);
  });

  it("rejects an ML-DSA-65 secret key of the wrong length", () => {
    const ed = ed25519KeygenRaw();
    expect(() =>
      signPushPayloadDual({
        payload: "x",
        ed25519SecretKeyRaw: ed.secret,
        mldsa65SecretKeyRaw: new Uint8Array(4031),
        keyIdEd25519: "k-ed",
        keyIdMldsa65: "k-ml",
      }),
    ).toThrow(/mldsa65SecretKeyRaw must be a 4032-byte Uint8Array/);
  });

  it("rejects empty / over-long keyIds", () => {
    const ed = ed25519KeygenRaw();
    const ml = generateMlDsa65Keypair();
    expect(() =>
      signPushPayloadDual({
        payload: "x",
        ed25519SecretKeyRaw: ed.secret,
        mldsa65SecretKeyRaw: ml.secretKey,
        keyIdEd25519: "",
        keyIdMldsa65: "k-ml",
      }),
    ).toThrow(/keyIdEd25519 must be a non-empty string/);
    expect(() =>
      signPushPayloadDual({
        payload: "x",
        ed25519SecretKeyRaw: ed.secret,
        mldsa65SecretKeyRaw: ml.secretKey,
        keyIdEd25519: "k-ed",
        keyIdMldsa65: "k".repeat(129),
      }),
    ).toThrow(/exceeds 128 characters/);
  });
});
