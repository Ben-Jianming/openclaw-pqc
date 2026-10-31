import { generateKeyPairSync } from "node:crypto";
import { EventEmitter } from "node:events";
import { mkdtempSync, rmSync } from "node:fs";
import http2 from "node:http2";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { closeOpenClawStateDatabase } from "../state/openclaw-state-db.js";
import { captureEnv, deleteTestEnvValue } from "../test-utils/env.js";
import { APNS_HTTP2_CANCEL_CODE } from "./push-apns-http2.js";
import { sendApnsBackgroundWake } from "./push-apns.js";
import { initializePushKeySetup } from "./push-key-setup.js";

const testAuthPrivateKey = generateKeyPairSync("ec", {
  namedCurve: "prime256v1",
}).privateKey.export({ format: "pem", type: "pkcs8" });

describe("APNs cancellation", () => {
  let stateDir: string;
  let signingEnv: ReturnType<typeof captureEnv>;
  beforeEach(() => {
    stateDir = mkdtempSync(join(tmpdir(), "push-apns-cancellation-"));
    vi.stubEnv("OPENCLAW_STATE_DIR", stateDir);
    signingEnv = captureEnv(["OPENCLAW_PUSH_SIGNING_KEY_FILE"]);
    deleteTestEnvValue("OPENCLAW_PUSH_SIGNING_KEY_FILE");
    const nowMs = Date.now();
    initializePushKeySetup({ validFromMs: nowMs - 1000, validUntilMs: nowMs + 600000 });
  });
  afterEach(() => {
    closeOpenClawStateDatabase();
    vi.unstubAllEnvs();
    signingEnv.restore();
    rmSync(stateDir, { recursive: true, force: true });
  });

  it("cancels the active stream when pairing ownership is revoked", async () => {
    const request = Object.assign(new EventEmitter(), {
      destroyed: false,
      setTimeout: vi.fn(),
      close: vi.fn(),
      end: vi.fn(),
    });
    request.close.mockImplementation(() => {
      request.destroyed = true;
      request.emit("close");
    });
    const session = Object.assign(new EventEmitter(), {
      close: vi.fn(),
      destroy: vi.fn(),
      request: vi.fn(() => request),
    });
    session.close.mockImplementation(() => session.emit("close"));
    const connect = vi
      .spyOn(http2, "connect")
      .mockReturnValue(session as unknown as http2.ClientHttp2Session);
    const controller = new AbortController();

    try {
      const sending = sendApnsBackgroundWake({
        registration: {
          nodeId: "ios-node-cancelled-stream",
          transport: "direct",
          token: "ABCD1234ABCD1234ABCD1234ABCD1234",
          topic: "ai.openclaw.ios",
          environment: "production",
          updatedAtMs: 1,
        },
        nodeId: "ios-node-cancelled-stream",
        wakeReason: "node.invoke",
        auth: {
          teamId: "TEAM123",
          keyId: "KEY123",
          privateKey: testAuthPrivateKey,
        },
        signal: controller.signal,
        isCurrent: vi.fn().mockResolvedValue(true),
      });
      await vi.waitFor(() => expect(request.end).toHaveBeenCalledTimes(1));

      controller.abort(new Error("pairing removed"));

      await expect(sending).rejects.toThrow("pairing removed");
      expect(request.close).toHaveBeenCalledWith(APNS_HTTP2_CANCEL_CODE);
      expect(session.close).toHaveBeenCalledTimes(1);
      expect(session.destroy).not.toHaveBeenCalled();
    } finally {
      connect.mockRestore();
    }
  });
});
