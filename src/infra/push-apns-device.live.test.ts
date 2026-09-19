// Sends a deliberately non-sensitive alert to a real APNs device token.
import { describe, expect, it } from "vitest";
import { isTruthyEnvValue } from "./env.js";
import type { ApnsEnvironment, DirectApnsRegistration } from "./push-apns-store.js";
import { resolveApnsAuthConfigFromEnv, sendApnsAlert } from "./push-apns.js";

const DEFAULT_TIMEOUT_MS = 30_000;
const LIVE =
  (isTruthyEnvValue(process.env.LIVE) || isTruthyEnvValue(process.env.OPENCLAW_LIVE_TEST)) &&
  isTruthyEnvValue(process.env.OPENCLAW_LIVE_APNS_DEVICE);
const describeLive = LIVE ? describe : describe.skip;

function requireEnvironment(name: string): string {
  const value = process.env[name]?.trim();
  if (!value) {
    throw new Error(`${name} is required for the real-device APNs acceptance test`);
  }
  return value;
}

function resolveEnvironment(): ApnsEnvironment {
  const value = requireEnvironment("OPENCLAW_APNS_ENVIRONMENT");
  if (value !== "sandbox" && value !== "production") {
    throw new Error("OPENCLAW_APNS_ENVIRONMENT must be sandbox or production");
  }
  return value;
}

function resolveConfirmationCode(): string {
  const value = requireEnvironment("OPENCLAW_APNS_CONFIRMATION_CODE");
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{3,31}$/u.test(value)) {
    throw new Error(
      "OPENCLAW_APNS_CONFIRMATION_CODE must be 4-32 ASCII letters, digits, dots, underscores, or hyphens",
    );
  }
  return value;
}

describeLive("APNs real-device acceptance", () => {
  it(
    "is accepted by APNs for the enrolled physical device",
    async () => {
      const auth = await resolveApnsAuthConfigFromEnv();
      if (!auth.ok) {
        throw new Error(auth.error);
      }
      const confirmationCode = resolveConfirmationCode();
      const registration: DirectApnsRegistration = {
        nodeId: "apns-physical-device-acceptance",
        transport: "direct",
        token: requireEnvironment("OPENCLAW_APNS_DEVICE_TOKEN"),
        topic: requireEnvironment("OPENCLAW_APNS_TOPIC"),
        environment: resolveEnvironment(),
        updatedAtMs: Date.now(),
      };

      const result = await sendApnsAlert({
        auth: auth.value,
        registration,
        nodeId: registration.nodeId,
        title: "OpenClaw delivery check",
        body: `Confirmation code: ${confirmationCode}`,
        timeoutMs: DEFAULT_TIMEOUT_MS,
      });

      console.info(
        JSON.stringify({
          event: "apns-physical-device-acceptance",
          accepted: result.ok,
          status: result.status,
          apnsId: result.apnsId ?? null,
          environment: result.environment,
          topic: result.topic,
          tokenSuffix: result.tokenSuffix,
          confirmationCode,
        }),
      );
      expect(result.ok).toBe(true);
      expect(result.status).toBe(200);
      expect(result.apnsId).toBeTruthy();
    },
    DEFAULT_TIMEOUT_MS + 10_000,
  );
});
