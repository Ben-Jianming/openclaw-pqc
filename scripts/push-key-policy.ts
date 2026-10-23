import { isAbsolute } from "node:path";
// Local administration only; no key contents are printed or exposed over recipient RPCs.
import { parseArgs } from "node:util";
import { enrollExistingPushKeys, revokePushKeyPolicy } from "../src/infra/push-key-policy-store.js";
import { closeOpenClawStateDatabase } from "../src/state/openclaw-state-db.js";

try {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    strict: true,
    options: {
      "state-dir": { type: "string" },
      "valid-from-ms": { type: "string" },
      "valid-until-ms": { type: "string" },
      "sender-id": { type: "string" },
      algorithm: { type: "string" },
      "key-id": { type: "string" },
    },
  });
  if (positionals.length !== 1 || !values["state-dir"] || !isAbsolute(values["state-dir"])) {
    throw new Error("supply enroll|revoke and an explicit --state-dir");
  }
  const options = { env: { ...process.env, OPENCLAW_STATE_DIR: values["state-dir"] } };
  if (positionals[0] === "enroll") {
    const from = values["valid-from-ms"],
      until = values["valid-until-ms"];
    if (
      !from ||
      !until ||
      !/^\d+$/.test(from) ||
      !/^\d+$/.test(until) ||
      values["sender-id"] ||
      values.algorithm ||
      values["key-id"]
    ) {
      throw new Error("enroll requires explicit --valid-from-ms and --valid-until-ms only");
    }
    enrollExistingPushKeys({ validFromMs: Number(from), validUntilMs: Number(until) }, options);
  } else if (positionals[0] === "revoke") {
    const senderId = values["sender-id"],
      keyId = values["key-id"],
      algorithm = values.algorithm;
    if (
      !senderId ||
      !keyId ||
      (algorithm !== "ed25519" && algorithm !== "ml-dsa-65") ||
      values["valid-from-ms"] ||
      values["valid-until-ms"]
    ) {
      throw new Error("revoke requires --sender-id, --algorithm and --key-id only");
    }
    revokePushKeyPolicy({ senderId, algorithm, keyId }, options);
  } else {
    throw new Error("unknown push key policy command");
  }
  console.log("Push key policy operation completed.");
} catch (error) {
  console.error(error instanceof Error ? error.message : "Push key policy operation failed.");
  console.error("[push-key-policy] FAILED (exit 1)");
  process.exitCode = 1;
} finally {
  closeOpenClawStateDatabase();
}
