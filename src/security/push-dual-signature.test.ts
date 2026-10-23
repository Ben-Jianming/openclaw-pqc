import { generateKeyPairSync } from "node:crypto";
import { beforeAll, describe, expect, it } from "vitest";
import { generateMlDsa65Keypair } from "../infra/mldsa65-key-storage.js";
import {
  InMemoryPushReplayGuard,
  encodePushSigningTranscript,
  signPushPayloadDual,
  verifyPushPayloadDual,
  verifyPushPayloadDualStrict,
  type PushDualEnvelope,
  type PushTrustedKeyRegistry,
  type TrustedPushKey,
} from "./push-dual-signature.js";

function ed25519KeygenRaw() {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    secret: new Uint8Array(privateKey.export({ type: "pkcs8", format: "der" }).subarray(-32)),
    public: new Uint8Array(publicKey.export({ type: "spki", format: "der" }).subarray(-32)),
  };
}

describe("push dual-signature protocol v2", () => {
  const now = 2_000_000;
  const payload = JSON.stringify({ title: "🐉", body: "approved" });
  const ed = ed25519KeygenRaw();
  let ml: ReturnType<typeof generateMlDsa65Keypair>;
  let envelope: PushDualEnvelope;
  let keys: TrustedPushKey[];
  let registry: PushTrustedKeyRegistry;

  beforeAll(() => {
    ml = generateMlDsa65Keypair();
    envelope = signPushPayloadDual({
      payload,
      ed25519SecretKeyRaw: ed.secret,
      mldsa65SecretKeyRaw: ml.secretKey,
      keyIdEd25519: "ed-2026",
      keyIdMldsa65: "ml-2026",
      senderId: "gateway-a",
      recipientId: "device-b",
      createdAtMs: now,
      sequence: 7,
      nonce: Buffer.alloc(24, 1).toString("base64url"),
      payloadType: "application/openclaw-push+json",
    }).envelope;
    keys = [
      {
        algorithm: "ed25519",
        keyId: "ed-2026",
        senderId: "gateway-a",
        publicKeyRaw: ed.public,
        validFromMs: 1,
        validUntilMs: now + 1_000,
      },
      {
        algorithm: "ml-dsa-65",
        keyId: "ml-2026",
        senderId: "gateway-a",
        publicKeyRaw: ml.publicKey,
        validFromMs: 1,
        validUntilMs: now + 1_000,
      },
    ];
    registry = {
      resolve: (algorithm, keyId) =>
        keys.find((key) => key.algorithm === algorithm && key.keyId === keyId),
    };
  });

  it("binds protocol metadata and verifies both signatures through the trusted registry", () => {
    expect(envelope).toMatchObject({
      version: 2,
      sender_id: "gateway-a",
      recipient_id: "device-b",
      sequence: 7,
    });
    expect(
      verifyPushPayloadDual({
        payload,
        envelope,
        registry,
        expectedRecipientId: "device-b",
        nowMs: now,
      }),
    ).toBe(true);
  });

  it("T28 requires both strict options and jointly rejects wrong recipients and replays", () => {
    const replayGuard = new InMemoryPushReplayGuard();
    const options = { payload, envelope, registry, nowMs: now, replayGuard };

    // A rejected recipient must not consume the valid envelope's replay state.
    expect(() =>
      verifyPushPayloadDualStrict({ ...options, expectedRecipientId: "device-x" }),
    ).toThrow(/recipient binding/);
    expect(verifyPushPayloadDualStrict({ ...options, expectedRecipientId: "device-b" })).toBe(true);
    expect(() =>
      verifyPushPayloadDualStrict({ ...options, expectedRecipientId: "device-b" }),
    ).toThrow(/replayed/);

    // JavaScript callers can omit fields despite the required TypeScript type.
    expect(() => Reflect.apply(verifyPushPayloadDualStrict, undefined, [options])).toThrow(
      /expectedRecipientId/,
    );
    const { replayGuard: _guard, ...withoutGuard } = options;
    expect(() =>
      Reflect.apply(verifyPushPayloadDualStrict, undefined, [
        { ...withoutGuard, expectedRecipientId: "device-b" },
      ]),
    ).toThrow(/replayGuard/);
  });

  it("matches the published cross-language transcript vector", () => {
    expect(
      encodePushSigningTranscript({
        version: 2,
        algorithms: ["ed25519", "ml-dsa-65"],
        sender_id: "sender",
        recipient_id: "receiver",
        key_id_ed25519: "ed",
        key_id_mldsa65: "ml",
        created_at_ms: 1,
        sequence: 2,
        nonce: Buffer.alloc(24, 1).toString("base64url"),
        payload_type: "text/plain",
        payload_sha256: Buffer.alloc(32, 2).toString("base64url"),
      }),
    ).toBe(
      "openclaw-push-v2-binary:T3BlbkNsYXctUFFDL1B1c2gvVjIAAQAAAAAAAAACAgAAAAdlZDI1NTE5AwAAAAltbC1kc2EtNjUEAAAABnNlbmRlcgUAAAAIcmVjZWl2ZXIGAAAAAmVkBwAAAAJtbAgAAAAAAAAAAQkAAAAAAAAAAgoAAAAYAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBCwAAAAp0ZXh0L3BsYWluDAAAACACAgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAg",
    );
  });

  it("rejects non-NFC metadata before signing", () => {
    expect(() =>
      signPushPayloadDual({
        payload,
        ed25519SecretKeyRaw: ed.secret,
        mldsa65SecretKeyRaw: ml.secretKey,
        keyIdEd25519: "ed-2026",
        keyIdMldsa65: "ml-2026",
        senderId: "e\u0301",
      }),
    ).toThrow(/NFC/);
  });

  it.each([
    ["sender_id", "gateway-x"],
    ["recipient_id", "device-x"],
    ["key_id_ed25519", "ed-x"],
    ["created_at_ms", now - 1],
    ["sequence", 8],
    ["payload_type", "text/plain"],
  ] as const)("rejects tampering with %s", (field, value) => {
    expect(() =>
      verifyPushPayloadDual({
        payload,
        envelope: { ...envelope, [field]: value },
        registry,
        nowMs: now,
      }),
    ).toThrow();
  });

  it("rejects payload tampering and noncanonical signature encodings", () => {
    expect(() =>
      verifyPushPayloadDual({ payload: `${payload}x`, envelope, registry, nowMs: now }),
    ).toThrow(/payload hash/);
    expect(() =>
      verifyPushPayloadDual({
        payload,
        envelope: { ...envelope, ed25519_sig: `${envelope.ed25519_sig}=` },
        registry,
        nowMs: now,
      }),
    ).toThrow(/canonical base64url/);
  });

  it("rejects unknown, expired, revoked, and wrong-subject keys", () => {
    expect(() =>
      verifyPushPayloadDual({
        payload,
        envelope,
        registry: { resolve: () => undefined },
        nowMs: now,
      }),
    ).toThrow(/unknown/);
    const base = keys[0]!;
    for (const changed of [
      { ...base, validUntilMs: now - 1 },
      { ...base, revokedAtMs: now },
      { ...base, senderId: "other-gateway" },
    ]) {
      const badRegistry: PushTrustedKeyRegistry = {
        resolve: (algorithm) => (algorithm === "ed25519" ? changed : keys[1]),
      };
      expect(() =>
        verifyPushPayloadDual({ payload, envelope, registry: badRegistry, nowMs: now }),
      ).toThrow();
    }
  });

  it.each(["ed25519", "ml-dsa-65"] as const)(
    "uses inclusive activation and exclusive expiry for %s without consuming replay state",
    (algorithm) => {
      const replayGuard = new InMemoryPushReplayGuard();
      const policyRegistry = (
        validFromMs: number,
        validUntilMs: number,
      ): PushTrustedKeyRegistry => ({
        resolve: (requested, keyId) => {
          const key = registry.resolve(requested, keyId);
          return key && requested === algorithm ? { ...key, validFromMs, validUntilMs } : key;
        },
      });
      const verify = (validFromMs: number, validUntilMs: number) =>
        verifyPushPayloadDualStrict({
          payload,
          envelope,
          nowMs: now,
          expectedRecipientId: "device-b",
          replayGuard,
          registry: policyRegistry(validFromMs, validUntilMs),
        });
      expect(() => verify(now + 1, now + 1000)).toThrow(/not yet valid/);
      expect(() => verify(now - 1000, now)).toThrow(/expired/);
      expect(() => verify(now - 1000, now - 1)).toThrow(/expired/);
      expect(verify(now, now + 1)).toBe(true);
      expect(() => verify(now, now + 1)).toThrow(/replayed/);
    },
  );

  it("rejects stale envelopes and replayed sequence/nonce pairs", () => {
    expect(() =>
      verifyPushPayloadDual({ payload, envelope, registry, nowMs: now + 301_000 }),
    ).toThrow(/stale/);
    const replayGuard = new InMemoryPushReplayGuard();
    expect(verifyPushPayloadDual({ payload, envelope, registry, nowMs: now, replayGuard })).toBe(
      true,
    );
    expect(() =>
      verifyPushPayloadDual({ payload, envelope, registry, nowMs: now, replayGuard }),
    ).toThrow(/replayed/);
  });

  it("rejects an unseen nonce when its sequence is below the accepted high-water mark", () => {
    const replayGuard = new InMemoryPushReplayGuard();
    const laterEnvelope = signPushPayloadDual({
      payload,
      ed25519SecretKeyRaw: ed.secret,
      mldsa65SecretKeyRaw: ml.secretKey,
      keyIdEd25519: "ed-2026",
      keyIdMldsa65: "ml-2026",
      senderId: "gateway-a",
      recipientId: "device-b",
      createdAtMs: now,
      sequence: 8,
      nonce: Buffer.alloc(24, 2).toString("base64url"),
      payloadType: "application/openclaw-push+json",
    }).envelope;

    expect(
      verifyPushPayloadDual({
        payload,
        envelope: laterEnvelope,
        registry,
        nowMs: now,
        replayGuard,
      }),
    ).toBe(true);
    expect(() =>
      verifyPushPayloadDual({ payload, envelope, registry, nowMs: now, replayGuard }),
    ).toThrow(/out-of-order/);
  });

  it("rejects invalid verification clocks instead of bypassing expiry", () => {
    for (const nowMs of [Number.NaN, Infinity, -1, 0.5]) {
      expect(() => verifyPushPayloadDual({ payload, envelope, registry, nowMs })).toThrow(/clock/);
    }
    expect(() =>
      verifyPushPayloadDual({ payload, envelope, registry, nowMs: now, maxAgeMs: Number.NaN }),
    ).toThrow(/clock/);
    expect(verifyPushPayloadDual({ payload, envelope, registry, nowMs: now })).toBe(true);
  });

  it("keeps peer namespaces separate and refuses capacity growth without erasing replay state", () => {
    const guard = new InMemoryPushReplayGuard(2);
    const first = { senderId: "a\0b", recipientId: "c", nonce: "n", sequence: 1, createdAtMs: now };
    expect(guard.accept(first)).toBe(true);
    expect(guard.accept({ ...first, senderId: "a", recipientId: "b\0c" })).toBe(true);
    expect(guard.accept({ ...first, senderId: "third" })).toBe(false);
    expect(guard.accept(first)).toBe(false);
    expect(guard.accept({ ...first, nonce: "next", sequence: 2 })).toBe(true);
  });

  it("rejects legacy or stripped envelopes", () => {
    const stripped = {
      algorithms: envelope.algorithms,
      ed25519_sig: envelope.ed25519_sig,
      mldsa65_sig: envelope.mldsa65_sig,
    };
    expect(() =>
      verifyPushPayloadDual({
        payload,
        envelope: stripped as PushDualEnvelope,
        registry,
        nowMs: now,
      }),
    ).toThrow(/version/);
  });
});
