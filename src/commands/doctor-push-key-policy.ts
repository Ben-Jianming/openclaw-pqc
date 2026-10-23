import type { HealthFinding } from "../flows/health-checks.js";
import { inspectPushKeySetup } from "../infra/push-key-setup.js";

export function collectPushKeyPolicyHealthFindings(
  env: NodeJS.ProcessEnv = process.env,
): HealthFinding[] {
  const checkId = "core/doctor/push-key-policy";
  try {
    const status = inspectPushKeySetup(env);
    if (status.ready) {
      return [];
    }
    return [
      {
        checkId,
        severity: "warning",
        source: "doctor",
        message: `Dual-signature push key policy is ${status.state}; secure push is not ready.`,
        fixHint:
          status.state === "uninitialized"
            ? "Run openclaw security push-key init with explicit --valid-from-ms and --valid-until-ms."
            : status.state === "unenrolled"
              ? "Run openclaw security push-key enroll with the intended explicit validity. Existing keys will be preserved."
              : "Inspect openclaw security push-key status --json. For intact, unrevoked enrolled keys, use renew with the original --valid-from-ms and an extended future --valid-until-ms. Otherwise restore missing keys or perform reviewed key rotation; do not replace identities or reactivate revoked keys.",
      },
    ];
  } catch {
    return [
      {
        checkId,
        severity: "error",
        source: "doctor",
        message: "Push key policy inspection failed; secure push is not ready.",
        fixHint:
          "Check local key permissions, identity recovery and database integrity. Doctor does not generate replacement keys or enroll a policy.",
      },
    ];
  }
}
