import { createHash } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import type { ConnectParams } from "../../../../packages/gateway-protocol/src/index.js";
import { buildDeviceAuthPayloadV3 } from "../../device-auth.js";
import { resolveDeviceSignaturePayloadVersion } from "./handshake-auth-helpers.js";

describe("gateway device proof algorithm interoperability", () => {
  it("accepts an explicitly versioned Ed25519 native-client proof", () => {
    const secretKey = new Uint8Array(32).fill(7);
    const publicKeyBytes = ed25519.getPublicKey(secretKey);
    const publicKey = Buffer.from(publicKeyBytes).toString("base64url");
    const deviceId = createHash("sha256").update(publicKeyBytes).digest("hex");
    const connectParams = {
      client: {
        id: "openclaw-ios",
        mode: "operator",
        platform: "ios",
        deviceFamily: "iPhone",
      },
      auth: { token: "shared-token" },
    } as unknown as ConnectParams;
    const basePayload = {
      deviceId,
      clientId: connectParams.client.id,
      clientMode: connectParams.client.mode,
      role: "operator",
      scopes: ["operator.read"],
      signedAtMs: 1_700_000_000_000,
      token: "shared-token",
      nonce: "fixed-nonce",
    };
    const payload = buildDeviceAuthPayloadV3({
      ...basePayload,
      platform: connectParams.client.platform,
      deviceFamily: connectParams.client.deviceFamily,
    });
    const signature = Buffer.from(
      ed25519.sign(new TextEncoder().encode(payload), secretKey),
    ).toString("base64url");

    expect(
      resolveDeviceSignaturePayloadVersion({
        device: { id: deviceId, algorithm: "ed25519", publicKey, signature },
        connectParams,
        role: basePayload.role,
        scopes: basePayload.scopes,
        signedAtMs: basePayload.signedAtMs,
        nonce: basePayload.nonce,
      }),
    ).toBe("v3");
  });

  it("rejects a declared algorithm that does not match the key", () => {
    const publicKey = Buffer.alloc(32, 3).toString("base64url");
    const connectParams = {
      client: { id: "openclaw-ios", mode: "operator", platform: "ios" },
      auth: { token: "shared-token" },
    } as unknown as ConnectParams;

    expect(
      resolveDeviceSignaturePayloadVersion({
        device: {
          id: createHash("sha256").update(Buffer.alloc(32, 3)).digest("hex"),
          algorithm: "ml-dsa-65",
          publicKey,
          signature: Buffer.alloc(64).toString("base64url"),
        },
        connectParams,
        role: "operator",
        scopes: ["operator.read"],
        signedAtMs: 1_700_000_000_000,
        nonce: "fixed-nonce",
      }),
    ).toBeNull();
  });
});
