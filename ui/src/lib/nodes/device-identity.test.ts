import { readFileSync } from "node:fs";
/** @vitest-environment node */
import { getPublicKeyAsync, utils } from "@noble/ed25519";
import { ml_dsa65 } from "@noble/post-quantum/ml-dsa.js";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { createStorageMock } from "../../test-helpers/storage.ts";
import { loadOrCreateDeviceIdentity, signDevicePayload } from "./index.ts";

const STORAGE_KEY = "openclaw-device-identity-v1";

function base64UrlEncode(bytes: Uint8Array): string {
  return Buffer.from(bytes).toString("base64url");
}

function base64UrlDecode(value: string): Uint8Array {
  return new Uint8Array(Buffer.from(value, "base64url"));
}

describe("Control UI device identity", () => {
  beforeEach(() => {
    vi.stubGlobal("localStorage", createStorageMock());
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("creates an ML-DSA-65 identity and signs a gateway payload", async () => {
    const identity = await loadOrCreateDeviceIdentity();
    const payload = "v3|device|browser|ui|operator|operator.read|1||nonce|web|desktop";
    const signature = await signDevicePayload(identity.privateKey, payload, identity.algorithm);

    expect(identity.algorithm).toBe("ml-dsa-65");
    expect(base64UrlDecode(identity.publicKey)).toHaveLength(1952);
    expect(base64UrlDecode(identity.privateKey)).toHaveLength(4032);
    expect(
      ml_dsa65.verify(
        base64UrlDecode(signature),
        new TextEncoder().encode(payload),
        base64UrlDecode(identity.publicKey),
      ),
    ).toBe(true);
    expect(JSON.parse(localStorage.getItem(STORAGE_KEY) ?? "null")).toMatchObject({
      version: 2,
      algorithm: "ml-dsa-65",
      deviceId: identity.deviceId,
    });
  });

  it("preserves an existing Ed25519 identity until its issued token is re-paired", async () => {
    const privateKey = utils.randomSecretKey();
    const publicKey = await getPublicKeyAsync(privateKey);
    const deviceId = Buffer.from(
      await crypto.subtle.digest("SHA-256", publicKey.slice().buffer),
    ).toString("hex");
    localStorage.setItem(
      STORAGE_KEY,
      JSON.stringify({
        version: 1,
        deviceId,
        publicKey: base64UrlEncode(publicKey),
        privateKey: base64UrlEncode(privateKey),
        createdAtMs: 1,
      }),
    );

    const identity = await loadOrCreateDeviceIdentity();

    expect(identity.algorithm).toBe("ed25519");
    expect(identity.deviceId).toBe(deviceId);
    expect(JSON.parse(localStorage.getItem(STORAGE_KEY) ?? "null").version).toBe(1);
  });

  it("matches the shared FIPS 204 interoperability vector", () => {
    const vector = JSON.parse(
      readFileSync(
        new URL("../../../../test/fixtures/pqc/ml-dsa-65-fips204.json", import.meta.url),
        "utf8",
      ),
    ) as {
      seedBase64Url: string;
      messageUtf8: string;
      publicKeyBase64Url: string;
      deterministicSignatureBase64Url: string;
    };
    const keyPair = ml_dsa65.keygen(base64UrlDecode(vector.seedBase64Url));

    expect(base64UrlEncode(keyPair.publicKey)).toBe(vector.publicKeyBase64Url);
    expect(
      ml_dsa65.verify(
        base64UrlDecode(vector.deterministicSignatureBase64Url),
        new TextEncoder().encode(vector.messageUtf8),
        keyPair.publicKey,
      ),
    ).toBe(true);
  });
});
