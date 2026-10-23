import type { Command } from "commander";
import {
  enrollExistingPushKeys,
  renewExistingPushKeys,
  revokePushKeyPolicy,
} from "../infra/push-key-policy-store.js";
import {
  initializePushKeySetup,
  inspectPushKeySetup,
  validatePushKeyValidity,
} from "../infra/push-key-setup.js";
import { defaultRuntime, writeRuntimeJson } from "../runtime.js";
import { closeOpenClawStateDatabase } from "../state/openclaw-state-db.js";

type ValidityOptions = { validFromMs: string; validUntilMs: string; json?: boolean };
function parseValidity(options: ValidityOptions) {
  if (!/^\d+$/.test(options.validFromMs) || !/^\d+$/.test(options.validUntilMs)) {
    throw new Error("validity values must be integer milliseconds since the Unix epoch");
  }
  const validity = {
    validFromMs: Number(options.validFromMs),
    validUntilMs: Number(options.validUntilMs),
  };
  validatePushKeyValidity(validity);
  return validity;
}

function runPushKeyCommand(operation: () => void, options: { json?: boolean }, statusOnly = false) {
  try {
    operation();
    const status = inspectPushKeySetup();
    if (options.json) {
      writeRuntimeJson(defaultRuntime, status);
    } else {
      defaultRuntime.log(`Push key policy: ${status.state}; ready=${status.ready}`);
    }
    if (statusOnly && !status.ready) {
      process.exitCode = 1;
    }
  } catch (error) {
    defaultRuntime.error(error instanceof Error ? error.message : "Push key operation failed.");
    defaultRuntime.error("[push-key] FAILED (exit 1)");
    process.exitCode = 1;
  } finally {
    closeOpenClawStateDatabase();
  }
}

export function registerPushKeyCli(security: Command): void {
  const pushKey = security
    .command("push-key")
    .description(
      "Explicitly provision, enroll, renew, inspect, or revoke local dual-signature push keys",
    );
  pushKey
    .command("status")
    .description("Inspect policy without generating or enrolling keys")
    .option("--json", "Emit machine-readable status")
    .action((options: { json?: boolean }) => runPushKeyCommand(() => {}, options, true));
  for (const operation of ["init", "enroll", "renew"] as const) {
    pushKey
      .command(operation)
      .description(
        operation === "init"
          ? "Initialize push keys in a new profile only"
          : operation === "renew"
            ? "Extend unrevoked policies with the same keys and original validity start"
            : "Enroll existing keys without replacing identities or renewing policies",
      )
      .requiredOption("--valid-from-ms <ms>", "Explicit inclusive validity start")
      .requiredOption("--valid-until-ms <ms>", "Explicit exclusive validity end")
      .option("--json", "Emit machine-readable status")
      .action((options: ValidityOptions) =>
        runPushKeyCommand(() => {
          const validity = parseValidity(options);
          if (operation === "init") {
            initializePushKeySetup(validity);
          } else if (operation === "renew") {
            renewExistingPushKeys(validity);
          } else {
            enrollExistingPushKeys(validity);
          }
        }, options),
      );
  }
  pushKey
    .command("revoke")
    .description("Persist revocation; never re-enable a revoked key")
    .requiredOption("--sender-id <id>", "Existing sender identity")
    .requiredOption("--algorithm <algorithm>", "ed25519 or ml-dsa-65")
    .requiredOption("--key-id <id>", "Existing key identifier")
    .option("--json", "Emit machine-readable status")
    .action((options: { senderId: string; algorithm: string; keyId: string; json?: boolean }) =>
      runPushKeyCommand(() => {
        if (options.algorithm !== "ed25519" && options.algorithm !== "ml-dsa-65") {
          throw new Error("algorithm must be ed25519 or ml-dsa-65");
        }
        revokePushKeyPolicy({
          senderId: options.senderId,
          algorithm: options.algorithm,
          keyId: options.keyId,
        });
      }, options),
    );
}
