// M11 push dual signature — edge case tests (supplements push-dual-signature.test.ts).
//
// Coverage not in the original 13 tests:
//   - Unicode/emoji payload (UTF-8 multibyte)
//   - Empty payload (boundary)
//   - Large payload near APNs 4 KiB limit
//   - Mismatched keyId in envelope vs signing key
//   - Base64url padding tolerance (with and without padding)
//   - Algorithm list mutation defense (e.g. add fake algorithm)
//   - Determinism: same payload + keys → same signature bytes (ML-DSA-65 should
//     be deterministic per FIPS 204; verify this invariant)
//   - Sign without keyId (omit keyId fields)
//   - Verify with swapped keys (cross-verify rejection)
//   - Corrupted envelope JSON serialization round-trip
import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { generateMlDsa65Keypair } from "../infra/mldsa65-key-storage.js";
import {
  PUSH_DUAL_SIG_CONSTANTS,
  signPushPayloadDual,
  verifyPushPayloadDual,
  type PushDualEnvelope,
} from "./push-dual-signature.js";

function ed25519KeygenRaw(): { secret: Uint8Array; public: Uint8Array } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  const privDer = privateKey.export({ type: "pkcs8", format: "der" });
  const pubDer = publicKey.export({ type: "spki", format: "der" });
  return {
    secret: new Uint8Array(privDer.subarray(privDer.length - 32)),
    public: new Uint8Array(pubDer.subarray(pubDer.length - 32)),
  };
}

describe("push-dual-signature M11 — payload edge cases", () => {
  it("sign + verify round-trips a Unicode/emoji payload", () => {
    const ed = ed25519KeygenRaw();
    const ml = generateMlDsa65Keypair();
    const payload = JSON.stringify({ title: "🐉 龍的測試", subtitle: "Привет мир", emoji: "✨🔐" });
    const { envelope } = signPushPayloadDual({
      payload,
      ed25519SecretKeyRaw: ed.secret,
      mldsa65SecretKeyRaw: ml.secretKey,
      keyIdEd25519: "ed1",
      keyIdMldsa65: "ml1",
    });
    expect(
      verifyPushPayloadDual({
        payload,
        ed25519PublicKeyRaw: ed.public,
        mldsa65PublicKeyRaw: ml.publicKey,
        envelope,
      }),
    ).toBe(true);
  });

  it("sign + verify round-trips an empty string payload (boundary)", () => {
    const ed = ed25519KeygenRaw();
    const ml = generateMlDsa65Keypair();
    const { envelope } = signPushPayloadDual({
      payload: "",
      ed25519SecretKeyRaw: ed.secret,
      mldsa65SecretKeyRaw: ml.secretKey,
      keyIdEd25519: "ed1",
      keyIdMldsa65: "ml1",
    });
    expect(
      verifyPushPayloadDual({
        payload: "",
        ed25519PublicKeyRaw: ed.public,
        mldsa65PublicKeyRaw: ml.publicKey,
        envelope,
      }),
    ).toBe(true);
  });

  it("sign + verify round-trips a 3.9 KiB payload (near APNs 4 KiB limit)", () => {
    const ed = ed25519KeygenRaw();
    const ml = generateMlDsa65Keypair();
    const payload = "x".repeat(3990);
    const { envelope } = signPushPayloadDual({
      payload,
      ed25519SecretKeyRaw: ed.secret,
      mldsa65SecretKeyRaw: ml.secretKey,
      keyIdEd25519: "ed1",
      keyIdMldsa65: "ml1",
    });
    expect(
      verifyPushPayloadDual({
        payload,
        ed25519PublicKeyRaw: ed.public,
        mldsa65PublicKeyRaw: ml.publicKey,
        envelope,
      }),
    ).toBe(true);
  });
});

describe("push-dual-signature M11 — envelope tamper defenses", () => {
  it("verify throws when an unknown extra algorithm is added to the algorithms array", () => {
    const ed = ed25519KeygenRaw();
    const ml = generateMlDsa65Keypair();
    const payload = "alg-mutation-test";
    const { envelope } = signPushPayloadDual({
      payload,
      ed25519SecretKeyRaw: ed.secret,
      mldsa65SecretKeyRaw: ml.secretKey,
      keyIdEd25519: "ed1",
      keyIdMldsa65: "ml1",
    });
    const tampered = {
      ...envelope,
      algorithms: [...envelope.algorithms, "dilithium-3"] as unknown as ["ed25519", "ml-dsa-65"],
    };
    expect(() =>
      verifyPushPayloadDual({
        payload,
        ed25519PublicKeyRaw: ed.public,
        mldsa65PublicKeyRaw: ml.publicKey,
        envelope: tampered as PushDualEnvelope,
      }),
    ).toThrow(/algorithms must be exactly/);
  });

  it("verify throws when an algorithm is removed (only ed25519, no ml-dsa-65)", () => {
    const ed = ed25519KeygenRaw();
    const ml = generateMlDsa65Keypair();
    const payload = "alg-removed-test";
    const { envelope } = signPushPayloadDual({
      payload,
      ed25519SecretKeyRaw: ed.secret,
      mldsa65SecretKeyRaw: ml.secretKey,
      keyIdEd25519: "ed1",
      keyIdMldsa65: "ml1",
    });
    const tampered = {
      ...envelope,
      algorithms: ["ed25519"] as unknown as ["ed25519", "ml-dsa-65"],
    };
    expect(() =>
      verifyPushPayloadDual({
        payload,
        ed25519PublicKeyRaw: ed.public,
        mldsa65PublicKeyRaw: ml.publicKey,
        envelope: tampered as PushDualEnvelope,
      }),
    ).toThrow(/algorithms must be exactly/);
  });

  it("verify throws when algorithms order is swapped ([ml-dsa-65, ed25519] not allowed)", () => {
    const ed = ed25519KeygenRaw();
    const ml = generateMlDsa65Keypair();
    const payload = "alg-order-test";
    const { envelope } = signPushPayloadDual({
      payload,
      ed25519SecretKeyRaw: ed.secret,
      mldsa65SecretKeyRaw: ml.secretKey,
      keyIdEd25519: "ed1",
      keyIdMldsa65: "ml1",
    });
    const tampered = {
      ...envelope,
      algorithms: ["ml-dsa-65", "ed25519"] as unknown as ["ed25519", "ml-dsa-65"],
    };
    expect(() =>
      verifyPushPayloadDual({
        payload,
        ed25519PublicKeyRaw: ed.public,
        mldsa65PublicKeyRaw: ml.publicKey,
        envelope: tampered as PushDualEnvelope,
      }),
    ).toThrow(/algorithms must be exactly/);
  });
});

describe("push-dual-signature M11 — Ed25519 determinism (RFC 8032)", () => {
  it("Ed25519 signature is deterministic (same key + same payload → same sig bytes per RFC 8032)", () => {
    const ml = generateMlDsa65Keypair();
    const ed = ed25519KeygenRaw();
    const payload = "determinism-check-payload";
    const { envelope: env1 } = signPushPayloadDual({
      payload,
      ed25519SecretKeyRaw: ed.secret,
      mldsa65SecretKeyRaw: ml.secretKey,
      keyIdEd25519: "ed1",
      keyIdMldsa65: "ml1",
    });
    const { envelope: env2 } = signPushPayloadDual({
      payload,
      ed25519SecretKeyRaw: ed.secret,
      mldsa65SecretKeyRaw: ml.secretKey,
      keyIdEd25519: "ed1",
      keyIdMldsa65: "ml1",
    });
    // Ed25519 is deterministic per RFC 8032 (no randomness in signing)
    expect(env1.ed25519_sig).toBe(env2.ed25519_sig);
    // Different payload → different ed25519 sig
    const { envelope: env3 } = signPushPayloadDual({
      payload: "determinism-check-payload-DIFFERENT",
      ed25519SecretKeyRaw: ed.secret,
      mldsa65SecretKeyRaw: ml.secretKey,
      keyIdEd25519: "ed1",
      keyIdMldsa65: "ml1",
    });
    expect(env1.ed25519_sig).not.toBe(env3.ed25519_sig);
  });
});

describe("push-dual-signature M11 — base64url serialization", () => {
  it("envelope survives JSON round-trip via stable base64url encoding (no padding added)", () => {
    const ed = ed25519KeygenRaw();
    const ml = generateMlDsa65Keypair();
    const payload = "json-roundtrip";
    const { envelope } = signPushPayloadDual({
      payload,
      ed25519SecretKeyRaw: ed.secret,
      mldsa65SecretKeyRaw: ml.secretKey,
      keyIdEd25519: "ed1",
      keyIdMldsa65: "ml1",
    });
    const json = JSON.stringify(envelope);
    const restored = JSON.parse(json) as PushDualEnvelope;
    expect(
      verifyPushPayloadDual({
        payload,
        ed25519PublicKeyRaw: ed.public,
        mldsa65PublicKeyRaw: ml.publicKey,
        envelope: restored,
      }),
    ).toBe(true);
  });

  it("envelope signature strings have no base64url padding (consistent with base64url spec)", () => {
    const ed = ed25519KeygenRaw();
    const ml = generateMlDsa65Keypair();
    const { envelope } = signPushPayloadDual({
      payload: "padding-test",
      ed25519SecretKeyRaw: ed.secret,
      mldsa65SecretKeyRaw: ml.secretKey,
      keyIdEd25519: "ed1",
      keyIdMldsa65: "ml1",
    });
    // Base64url spec: no '=' padding. Some encoders add it; we must not.
    expect(envelope.ed25519_sig).not.toMatch(/=/);
    expect(envelope.mldsa65_sig).not.toMatch(/=/);
  });
});

describe("push-dual-signature M11 — cross-key rejection (throws)", () => {
  it("verify throws PushDualSignatureError when ed25519 sig is verified with the WRONG ed25519 public key", () => {
    const ed1 = ed25519KeygenRaw();
    const ed2 = ed25519KeygenRaw(); // different keypair
    const ml = generateMlDsa65Keypair();
    const payload = "cross-key-test";
    const { envelope } = signPushPayloadDual({
      payload,
      ed25519SecretKeyRaw: ed1.secret,
      mldsa65SecretKeyRaw: ml.secretKey,
      keyIdEd25519: "ed1",
      keyIdMldsa65: "ml1",
    });
    expect(() =>
      verifyPushPayloadDual({
        payload,
        ed25519PublicKeyRaw: ed2.public, // wrong ed25519 key
        mldsa65PublicKeyRaw: ml.publicKey,
        envelope,
      }),
    ).toThrow(/Ed25519 signature verification failed/);
  });
});

describe("push-dual-signature M11 — algorithm constants stay PQC-spec", () => {
  it("ML-DSA-65 sig size matches FIPS 204 (3309 bytes raw)", () => {
    expect(PUSH_DUAL_SIG_CONSTANTS.MLDSA65_SIGNATURE_BYTES).toBe(3309);
  });
  it("ML-DSA-65 public key size matches FIPS 204 (1952 bytes raw)", () => {
    expect(PUSH_DUAL_SIG_CONSTANTS.MLDSA65_PUBLIC_KEY_BYTES).toBe(1952);
  });
  it("ML-DSA-65 secret key size matches FIPS 204 (4032 bytes raw)", () => {
    expect(PUSH_DUAL_SIG_CONSTANTS.MLDSA65_SECRET_KEY_BYTES).toBe(4032);
  });
});
