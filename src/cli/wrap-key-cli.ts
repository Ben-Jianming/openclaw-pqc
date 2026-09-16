import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import type { Command } from "commander";
import {
  listStoredDeviceIdentityWrapHealth,
  rotateStoredDeviceIdentityWrappingKey,
} from "../infra/device-identity-wrap-operations.js";
import { resolveDeviceIdentityKeyring } from "../infra/device-identity.js";
import { defaultRuntime } from "../runtime.js";
import {
  wrapKeyExportCommand,
  wrapKeyHealthCheck,
  wrapKeyImportCommand,
} from "../security/wrap-key-cli.js";

function readRequiredTextFile(filePath: string, label: string): string {
  const absolute = path.resolve(filePath);
  const value = fs.readFileSync(absolute, "utf8").replace(/\r?\n$/, "");
  if (!value) {
    throw new Error(`${label} file is empty: ${absolute}`);
  }
  return value;
}

function writePrivateFile(filePath: string, contents: string): string {
  const absolute = path.resolve(filePath);
  fs.mkdirSync(path.dirname(absolute), { recursive: true, mode: 0o700 });
  fs.writeFileSync(absolute, contents, { encoding: "utf8", flag: "wx", mode: 0o600 });
  if (process.platform !== "win32") {
    fs.chmodSync(absolute, 0o600);
  }
  return absolute;
}

export function registerWrapKeyCli(security: Command): void {
  const wrapKey = security
    .command("wrap-key")
    .description("Inspect, back up, restore, and rotate the device-identity wrapping key");

  wrapKey
    .command("status")
    .description("Show wrapping-key configuration and stored identity state")
    .option("--json", "Print JSON", false)
    .action((options: { json?: boolean }) => {
      let activeKeyId: string | null = null;
      let configurationError: string | null = null;
      try {
        activeKeyId = resolveDeviceIdentityKeyring(process.env)?.getActiveKey().keyId ?? null;
      } catch (error) {
        configurationError = error instanceof Error ? error.message : String(error);
      }
      const status = wrapKeyHealthCheck({
        list: () => listStoredDeviceIdentityWrapHealth({ env: process.env }),
        activeKeyId,
      });
      if (options.json) {
        defaultRuntime.writeJson({ ...status, configurationError });
        return;
      }
      defaultRuntime.log(
        [
          `Active key: ${status.activeKeyId ?? "not configured"}`,
          `Wrapped active: ${status.wrappedActiveCount}`,
          `Wrapped stale: ${status.wrappedStaleCount}`,
          `Plaintext: ${status.plaintextCount}`,
          `Invalid: ${status.invalidCount}`,
          ...(configurationError ? [`Configuration error: ${configurationError}`] : []),
          ...status.notes.map((note) => `- ${note}`),
        ].join("\n"),
      );
    });

  wrapKey
    .command("export")
    .description("Write a passphrase-protected backup of the configured wrapping key")
    .requiredOption("--output <path>", "New backup file (must not already exist)")
    .requiredOption("--passphrase-file <path>", "File containing the backup passphrase")
    .action(async (options: { output: string; passphraseFile: string }) => {
      const provider = resolveDeviceIdentityKeyring(process.env);
      if (!provider) {
        throw new Error("No wrapping key configured; set OPENCLAW_WRAP_KEY_FILE first.");
      }
      const active = provider.getActiveKey();
      const envelope = await wrapKeyExportCommand({
        rawKey: active.key,
        keyId: active.keyId,
        passphrase: readRequiredTextFile(options.passphraseFile, "Passphrase"),
      });
      const output = writePrivateFile(options.output, `${envelope}\n`);
      defaultRuntime.log(`Wrapping-key backup written to ${output}`);
    });

  wrapKey
    .command("import")
    .description("Restore a passphrase-protected backup to a new key file")
    .requiredOption("--input <path>", "Backup envelope file")
    .requiredOption("--output <path>", "New raw key file (must not already exist)")
    .requiredOption("--passphrase-file <path>", "File containing the backup passphrase")
    .action(async (options: { input: string; output: string; passphraseFile: string }) => {
      const restored = await wrapKeyImportCommand({
        envelope: readRequiredTextFile(options.input, "Backup"),
        passphrase: readRequiredTextFile(options.passphraseFile, "Passphrase"),
      });
      const output = writePrivateFile(options.output, `${restored.key.toString("base64url")}\n`);
      defaultRuntime.log(
        `Wrapping key restored to ${output}\nSet OPENCLAW_WRAP_KEY_FILE=${output}\nSet OPENCLAW_PQC_WRAP_KEY_ID=${restored.keyId}`,
      );
    });

  wrapKey
    .command("rotate")
    .description("Atomically re-wrap all stored identities under a new key")
    .requiredOption("--output <path>", "New raw key file (must not already exist)")
    .requiredOption("--key-id <id>", "Identifier for the new wrapping key")
    .action((options: { output: string; keyId: string }) => {
      const oldProvider = resolveDeviceIdentityKeyring(process.env);
      const newKey = crypto.randomBytes(32);
      const output = writePrivateFile(options.output, `${newKey.toString("base64url")}\n`);
      const result = rotateStoredDeviceIdentityWrappingKey({
        env: process.env,
        oldWrappingKeyProvider: oldProvider,
        newKey: { keyId: options.keyId, key: newKey },
      });
      defaultRuntime.log(
        `Rotated ${result.rotated} identity row(s).\nSet OPENCLAW_WRAP_KEY_FILE=${output}\nSet OPENCLAW_PQC_WRAP_KEY_ID=${options.keyId}`,
      );
    });
}
