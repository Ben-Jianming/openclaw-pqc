import fs from "node:fs";
import path from "node:path";
import { ed25519 } from "@noble/curves/ed25519.js";
import { describe, expect, it } from "vitest";
import {
  deriveDeviceIdFromPublicKey,
  verifyDeviceSignature,
} from "./device-identity.js";

const repoRoot = path.resolve(import.meta.dirname, "../..");

describe("installed PQC production contract", () => {
  it("accepts a fixed Ed25519 compatibility proof only under its declared algorithm", () => {
    const secret = new Uint8Array(32).fill(7);
    const publicKey = Buffer.from(ed25519.getPublicKey(secret)).toString("base64url");
    const payload = "openclaw-cross-language-device-proof-v1";
    const signature = Buffer.from(ed25519.sign(new TextEncoder().encode(payload), secret)).toString(
      "base64url",
    );

    expect(publicKey).toBe("6kpsY-KcUgq-9VB7Ey7F-ZVHdq6-vnuSQh7qaRRG0iw");
    expect(deriveDeviceIdFromPublicKey(publicKey, "ed25519")).toBe(
      "fe812c12f3ab4ce6ac5db69ac352f906cb1b11ef43fb33e252ef7ff552263889",
    );
    expect(verifyDeviceSignature(publicKey, payload, signature, "ed25519")).toBe(true);
    expect(verifyDeviceSignature(publicKey, payload, signature, "ml-dsa-65")).toBe(false);
  });

  it("keeps every shipping client explicit about its device-proof algorithm", () => {
    const contracts = [
      ["packages/gateway-client/src/client.ts", 'algorithm: "ml-dsa-65"'],
      ["packages/gateway-client/src/browser-device-auth.ts", 'algorithm: "ed25519"'],
      ["ui/src/api/gateway.ts", 'algorithm: "ed25519"'],
      ["apps/shared/OpenClawKit/Sources/OpenClawKit/DeviceAuthPayload.swift", '"algorithm"'],
      ["apps/android/app/src/main/java/ai/openclaw/app/gateway/GatewaySession.kt", '"algorithm"'],
      ["apps/linux/src-tauri/src/gateway_device_identity.rs", '"algorithm"'],
    ] as const;
    for (const [relativePath, marker] of contracts) {
      expect(fs.readFileSync(path.join(repoRoot, relativePath), "utf8"), relativePath).toContain(
        marker,
      );
    }
  });

  it("keeps the gateway verification and pairing path wired to signed proofs", () => {
    const verifier = fs.readFileSync(
      path.join(repoRoot, "src/gateway/server/ws-connection/connect-device-proof.ts"),
      "utf8",
    );
    const auth = fs.readFileSync(
      path.join(repoRoot, "src/gateway/server/ws-connection/connect-auth.ts"),
      "utf8",
    );
    expect(verifier).toContain("deriveDeviceIdFromPublicKey(device.publicKey, device.algorithm)");
    expect(verifier).toContain("resolveDeviceSignaturePayloadVersion");
    expect(auth).toContain("verifyGatewayConnectDeviceProof");
  });
});
