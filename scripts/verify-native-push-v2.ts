import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  encodePushSigningTranscript,
  InMemoryPushReplayGuard,
  verifyPushPayloadDualStrict,
  type PushDualEnvelope,
  type PushTrustedKeyRegistry,
} from "../src/security/push-dual-signature.js";

const input = process.argv[2];
assert.ok(input, "provide the public-only native signature artifact");
const fixture = JSON.parse(readFileSync(input, "utf8")) as {
  object: { payload: string; envelope: PushDualEnvelope };
  keys: {
    senderId: string;
    recipientId: string;
    ed25519PublicKeyBase64Url: string;
    mldsa65PublicKeyBase64Url: string;
  };
  signedMessage: string;
  nowMs: number;
};
const { object, keys } = fixture;
const registry: PushTrustedKeyRegistry = {
  resolve: (algorithm, keyId) => ({
    algorithm,
    keyId,
    senderId: keys.senderId,
    publicKeyRaw: Buffer.from(
      algorithm === "ed25519" ? keys.ed25519PublicKeyBase64Url : keys.mldsa65PublicKeyBase64Url,
      "base64url",
    ),
  }),
};
assert.equal(encodePushSigningTranscript(object.envelope), fixture.signedMessage);
const options = {
  ...object,
  registry,
  expectedRecipientId: keys.recipientId,
  nowMs: fixture.nowMs,
  replayGuard: new InMemoryPushReplayGuard(),
};
assert.throws(() =>
  verifyPushPayloadDualStrict({ ...options, payload: object.payload + "tampered" }),
);
assert.throws(() =>
  verifyPushPayloadDualStrict({ ...options, expectedRecipientId: "wrong-device" }),
);
assert.equal(verifyPushPayloadDualStrict(options), true);
assert.throws(() => verifyPushPayloadDualStrict(options));
process.stdout.write(
  "Native-generated Ed25519/ML-DSA-65 push accepted by the server; transcript, binding and replay verified.\n",
);
