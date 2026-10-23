import { createHash, randomBytes } from "node:crypto";
import { readFileSync } from "node:fs";
import { ed25519 } from "@noble/curves/ed25519.js";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { describe, expect, it } from "vitest";
import {
  encodeBrowserPushTranscript,
  verifyBrowserPush,
  type PushV2Envelope,
} from "../../ui/src/app/pqc-push.js";
import {
  encodePushSigningTranscript,
  signPushPayloadDual,
  InMemoryPushReplayGuard,
} from "../security/push-dual-signature.js";

function withPolicies<
  T extends {
    senderId: string;
    keyIdEd25519: string;
    keyIdMldsa65: string;
    ed25519PublicKeyBase64Url: string;
    mldsa65PublicKeyBase64Url: string;
  },
>(keys: T, nowMs: number) {
  return {
    ...keys,
    keyPolicyVersion: 1 as const,
    keyPolicy: {
      ed25519: {
        algorithm: "ed25519" as const,
        keyId: keys.keyIdEd25519,
        senderId: keys.senderId,
        publicKeyBase64Url: keys.ed25519PublicKeyBase64Url,
        status: "active" as const,
        validFromMs: nowMs - 1000,
        validUntilMs: nowMs + 600000,
        revision: 1,
      },
      mldsa65: {
        algorithm: "ml-dsa-65" as const,
        keyId: keys.keyIdMldsa65,
        senderId: keys.senderId,
        publicKeyBase64Url: keys.mldsa65PublicKeyBase64Url,
        status: "active" as const,
        validFromMs: nowMs - 1000,
        validUntilMs: nowMs + 600000,
        revision: 1,
      },
    },
  };
}
describe("server/browser V2 interoperability", () => {
  it("accepts the same public-only fixed vector used by Swift", async () => {
    const fixture = JSON.parse(
      readFileSync(new URL("../../test/fixtures/pqc/push-v2.json", import.meta.url), "utf8"),
    );
    const { object, keys, nowMs, signedMessage } = fixture;
    expect(encodePushSigningTranscript(object.envelope)).toBe(signedMessage);
    expect(new TextDecoder().decode(encodeBrowserPushTranscript(object.envelope))).toBe(
      signedMessage,
    );
    await expect(
      verifyBrowserPush(
        object.payload,
        object.envelope,
        withPolicies(keys, nowMs),
        "alice",
        async () => true,
        nowMs,
      ),
    ).resolves.toBeUndefined();
  });
  const secret = randomBytes(32);
  const ml = ml_dsa65.keygen();
  const keys = withPolicies(
    {
      senderId: "gateway",
      keyIdEd25519: "ed",
      keyIdMldsa65: "ml",
      ed25519PublicKeyBase64Url: Buffer.from(ed25519.getPublicKey(secret)).toString("base64url"),
      mldsa65PublicKeyBase64Url: Buffer.from(ml.publicKey).toString("base64url"),
    },
    Date.now(),
  );
  function signed() {
    return signPushPayloadDual({
      payload: '{"title":"Verified title","body":"private body"}',
      ed25519SecretKeyRaw: secret,
      mldsa65SecretKeyRaw: ml.secretKey,
      keyIdEd25519: "ed",
      keyIdMldsa65: "ml",
      senderId: "gateway",
      recipientId: "alice",
      sequence: 1,
    });
  }
  function guard() {
    const g = new InMemoryPushReplayGuard();
    return async (e: PushV2Envelope) =>
      g.accept({
        senderId: e.sender_id,
        recipientId: e.recipient_id,
        nonce: e.nonce,
        sequence: e.sequence,
        createdAtMs: e.created_at_ms,
      });
  }
  it("encodes a fixed Unicode transcript identically", () => {
    const e = {
      version: 2 as const,
      algorithms: ["ed25519", "ml-dsa-65"] as ["ed25519", "ml-dsa-65"],
      sender_id: "网关",
      recipient_id: "alice",
      key_id_ed25519: "ed",
      key_id_mldsa65: "ml",
      created_at_ms: 1700000000000,
      sequence: 9007199254740991,
      nonce: Buffer.alloc(24, 1).toString("base64url"),
      payload_type: "application/json",
      payload_sha256: createHash("sha256").update("hello").digest("base64url"),
      ed25519_sig: "",
      mldsa65_sig: "",
    };
    expect(new TextDecoder().decode(encodeBrowserPushTranscript(e))).toBe(
      encodePushSigningTranscript(e),
    );
  });
  it("verifies real server signatures then rejects replay", async () => {
    const s = signed();
    const accept = guard();
    await expect(
      verifyBrowserPush(s.payload, s.envelope, keys, "alice", accept, Number.NaN),
    ).rejects.toThrow("integer");
    await expect(
      verifyBrowserPush(s.payload, s.envelope, keys, "alice", accept),
    ).resolves.toBeUndefined();
    await expect(verifyBrowserPush(s.payload, s.envelope, keys, "alice", accept)).rejects.toThrow(
      "replayed",
    );
  });
  it("rejects unpaired UTF-16 identifiers before either encoder can replace their bytes", () => {
    const { envelope } = signed();
    for (const sender_id of ["\ud800", "\udc00", "gateway\ud800"]) {
      const invalid = { ...envelope, sender_id };
      expect(() => encodePushSigningTranscript(invalid)).toThrow(/surrogate/);
      expect(() => encodeBrowserPushTranscript(invalid)).toThrow(/field/);
    }
  });
  it("rejects content, recipient, key, time and signature tampering before consuming replay state", async () => {
    const s = signed();
    const accept = guard();
    await expect(
      verifyBrowserPush(s.payload + "x", s.envelope, keys, "alice", accept),
    ).rejects.toThrow("content mismatch");
    await expect(verifyBrowserPush(s.payload, s.envelope, keys, "bob", accept)).rejects.toThrow(
      "identity",
    );
    await expect(
      verifyBrowserPush(s.payload, s.envelope, { ...keys, senderId: "other" }, "alice", accept),
    ).rejects.toThrow(/identity|policy/);
    await expect(
      verifyBrowserPush(
        s.payload,
        s.envelope,
        keys,
        "alice",
        accept,
        s.envelope.created_at_ms + 300001,
      ),
    ).rejects.toThrow("expired");
    const bad = { ...s.envelope, mldsa65_sig: Buffer.alloc(3309).toString("base64url") };
    await expect(verifyBrowserPush(s.payload, bad, keys, "alice", accept)).rejects.toThrow(
      "signature",
    );
    await expect(
      verifyBrowserPush(s.payload, s.envelope, keys, "alice", accept),
    ).resolves.toBeUndefined();
  });
});
