#!/usr/bin/env node
// Runs only against built artifacts, in a throwaway state directory owned by this verifier.
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import { createHash, randomBytes, randomUUID } from "node:crypto";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync, unlinkSync } from "node:fs";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import path from "node:path";
import { DatabaseSync } from "node:sqlite";
import { fileURLToPath, pathToFileURL } from "node:url";
import WebSocket from "ws";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const cliPath = path.join(root, "openclaw.mjs");
const scriptPath = fileURLToPath(import.meta.url);
const proofPath = (dir) => path.join(dir, "proof.json");

function child(args, env, expectedSuccess = true) {
  const result = spawnSync(process.execPath, args, {
    cwd: root,
    env,
    encoding: "utf8",
    timeout: 60000,
    windowsHide: true,
  });
  if (result.error) {
    throw result.error;
  }
  if (expectedSuccess && result.status !== 0) {
    throw new Error(`Installed PQC behavior check failed: ${result.stderr || result.stdout}`);
  }
  if (!expectedSuccess) {
    assert.notEqual(result.status, 0, "unsafe recovery unexpectedly succeeded");
  }
  return result;
}

/** @param {import("ws").RawData} data */
function decodeGatewayFrame(data) {
  const bytes = Buffer.isBuffer(data)
    ? data
    : Array.isArray(data)
      ? Buffer.concat(data)
      : Buffer.from(data);
  return JSON.parse(bytes.toString("utf8"));
}

async function verifyGatewayHandshake(env, keys) {
  const reservation = createServer();
  await new Promise((resolve, reject) => {
    reservation.once("error", reject);
    reservation.listen(0, "127.0.0.1", resolve);
  });
  const port = reservation.address().port;
  await new Promise((resolve, reject) => {
    reservation.close((error) => (error ? reject(error) : resolve()));
  });
  const token = randomBytes(32).toString("base64url");
  const gatewayEnv = { ...env, OPENCLAW_GATEWAY_TOKEN: token };
  writeFileSync(
    env.OPENCLAW_CONFIG_PATH,
    JSON.stringify({
      gateway: { mode: "local", bind: "loopback", port, auth: { mode: "token" } },
      plugins: { enabled: false },
      discovery: { mdns: { mode: "off" } },
      cron: { enabled: false },
    }),
    { mode: 0o600 },
  );
  const server = spawn(process.execPath, [cliPath, "gateway", "run", "--port", String(port)], {
    cwd: root,
    env: gatewayEnv,
    windowsHide: true,
    stdio: ["ignore", "pipe", "pipe"],
  });
  let output = "";
  /** @type {Error | undefined} */
  let spawnError;
  server.once("error", (error) => {
    spawnError = error;
  });
  for (const stream of [server.stdout, server.stderr]) {
    stream.on("data", (chunk) => {
      output = (output + chunk.toString("utf8")).slice(-8000);
    });
  }
  const exited = new Promise((resolve) => {
    server.once("close", resolve);
  });
  const url = `ws://127.0.0.1:${port}`;
  const challenge = () =>
    new Promise((resolve, reject) => {
      const socket = new WebSocket(url, { handshakeTimeout: 1000 });
      const timer = setTimeout(() => {
        socket.terminate();
        reject(new Error("gateway challenge timed out"));
      }, 1500);
      socket.on("error", (error) => {
        clearTimeout(timer);
        reject(error);
      });
      socket.on("message", (data) => {
        const frame = decodeGatewayFrame(data);
        if (frame.event === "connect.challenge") {
          clearTimeout(timer);
          socket.close();
          resolve();
        }
      });
    });
  try {
    const deadline = Date.now() + 60000;
    for (;;) {
      if (spawnError) {
        throw spawnError;
      }
      if (server.exitCode !== null || server.signalCode !== null) {
        throw new Error(`isolated gateway exited: ${output.replaceAll(token, "[redacted]")}`);
      }
      try {
        await challenge();
        break;
      } catch {
        if (Date.now() >= deadline) {
          throw new Error(
            `isolated gateway did not start: ${output.replaceAll(token, "[redacted]")}`,
          );
        }
        await new Promise((resolve) => {
          setTimeout(resolve, 250);
        });
      }
    }
    // The local CLI health call checks shared-token authentication. Device-bound
    // RPCs below use the built SDK client, which also supplies ML-DSA-65 proof.
    const result = child(
      [cliPath, "gateway", "health", "--port", String(port), "--timeout", "10000", "--json"],
      gatewayEnv,
    );
    assert.equal(JSON.parse(result.stdout).ok, true, "authenticated gateway health failed");
    child([scriptPath, "--probe", "gateway", url], gatewayEnv);
    await new Promise((resolve, reject) => {
      const socket = new WebSocket(url, { handshakeTimeout: 10000 });
      const timer = setTimeout(() => {
        socket.terminate();
        reject(new Error("invalid proof rejection timed out"));
      }, 10000);
      socket.on("error", (error) => {
        clearTimeout(timer);
        reject(error);
      });
      socket.on("message", (data) => {
        try {
          const frame = decodeGatewayFrame(data);
          if (frame.event === "connect.challenge") {
            socket.send(
              JSON.stringify({
                type: "req",
                id: "invalid-proof",
                method: "connect",
                params: {
                  minProtocol: 4,
                  maxProtocol: 4,
                  client: {
                    id: "cli",
                    version: "installation-test",
                    platform: process.platform,
                    mode: "cli",
                  },
                  role: "operator",
                  scopes: ["operator.read"],
                  auth: { token },
                  device: {
                    id: keys.senderId,
                    algorithm: "ml-dsa-65",
                    publicKey: keys.mldsa65PublicKeyBase64Url,
                    signature: Buffer.alloc(3309).toString("base64url"),
                    signedAt: Date.now(),
                    nonce: frame.payload.nonce,
                  },
                },
              }),
            );
          } else if (frame.type === "res" && frame.id === "invalid-proof") {
            assert.equal(frame.ok, false, "invalid device signature was accepted");
            assert.equal(frame.error?.details?.reason, "device-signature");
            clearTimeout(timer);
            socket.close();
            resolve();
          }
        } catch (error) {
          clearTimeout(timer);
          socket.terminate();
          reject(
            error instanceof Error
              ? error
              : new Error("invalid gateway response", { cause: error }),
          );
        }
      });
    });
  } finally {
    // Compile-cache respawning is disabled below, so this is exactly our owned process.
    if (server.exitCode === null && server.signalCode === null) {
      server.kill("SIGTERM");
    }
    const stopped = await Promise.race([
      exited.then(() => true),
      new Promise((resolve) => {
        setTimeout(() => resolve(false), 5000);
      }),
    ]);
    if (!stopped) {
      server.kill("SIGKILL");
      await exited;
    }
  }
}

if (process.argv[2] === "--probe") {
  const dir = process.env.OPENCLAW_STATE_DIR;
  assert.ok(dir);
  const sdk = await import(pathToFileURL(path.join(root, "dist/plugin-sdk/push-envelope.js")).href);
  const mode = process.argv[3];
  const keys = sdk.getPushEnvelopeVerificationKeys();
  const replayGuard = sdk.createPushReplayGuard();
  const verify = (signed, overrides = {}) =>
    sdk.verifySignedPushEnvelope({
      ...signed,
      trustedKeys: keys,
      expectedRecipientId: "installation-test",
      replayGuard,
      ...overrides,
    });
  const completionRegistry = {
    resolve: (algorithm, keyId) => {
      const expectedId = algorithm === "ed25519" ? keys.keyIdEd25519 : keys.keyIdMldsa65;
      if (keyId !== expectedId) {
        return undefined;
      }
      return {
        algorithm,
        keyId,
        senderId: keys.senderId,
        publicKeyRaw: Buffer.from(
          algorithm === "ed25519" ? keys.ed25519PublicKeyBase64Url : keys.mldsa65PublicKeyBase64Url,
          "base64url",
        ),
      };
    },
  };
  const consume = (signed, apply) =>
    sdk.consumePushPayloadDual(
      { ...signed, registry: completionRegistry, expectedRecipientId: "installation-test" },
      apply,
    );
  if (mode === "gateway") {
    const { GatewayClient } = await import(
      pathToFileURL(path.join(root, "dist/plugin-sdk/gateway-runtime.js")).href
    );
    let acceptHello;
    let rejectHello;
    const hello = new Promise((resolve, reject) => {
      acceptHello = resolve;
      rejectHello = reject;
    });
    const client = new GatewayClient({
      url: process.argv[4],
      token: process.env.OPENCLAW_GATEWAY_TOKEN,
      clientName: "cli",
      mode: "cli",
      role: "operator",
      scopes: ["operator.read"],
      caps: ["push-key-policy-v1"],
      requestTimeoutMs: 10000,
      onHelloOk: acceptHello,
      onConnectError: rejectHello,
    });
    const timer = setTimeout(() => rejectHello(new Error("device handshake timed out")), 20000);
    try {
      assert.equal(client.getConnectionMetadata().hasDeviceIdentity, true);
      client.start();
      await hello;
      // Exercise the installed dispatch table with a cryptographically bound device.
      const { recipientId, ...verificationKeys } = await client.request("push.pqc.keys", {});
      assert.equal(recipientId, keys.senderId, "push RPC authenticated another device");
      assert.deepEqual(verificationKeys, keys, "push RPC returned different verification keys");
      await assert.rejects(
        client.request("push.pqc.redeem", {
          version: 1,
          object_id: "installation-test-missing-object",
          token: randomBytes(32).toString("base64url"),
          expires_at_ms: Date.now() + 60_000,
        }),
        (error) => error.code === "UNAVAILABLE" && error.message === "push reference unavailable",
      );
      const signed = sdk.signPushEnvelope({
        payload: '{"title":"Retryable installed RPC"}',
        recipientId,
      });
      const descriptor = {
        version: 1,
        object_id: randomUUID(),
        token: randomBytes(32).toString("base64url"),
        expires_at_ms: Date.now() + 60_000,
      };
      // Seed a controlled signed object, then exercise the real installed
      // authenticated dispatch path rather than a handler or socket mock.
      const state = new DatabaseSync(path.join(dir, "state/openclaw.sqlite"));
      try {
        state
          .prepare(
            "INSERT INTO pqc_push_objects(object_id,token_hash,recipient_id,payload,envelope_json,expires_at_ms) VALUES (?,?,?,?,?,?)",
          )
          .run(
            descriptor.object_id,
            createHash("sha256").update(descriptor.token, "utf8").digest("hex"),
            recipientId,
            signed.payload,
            JSON.stringify(signed.envelope),
            descriptor.expires_at_ms,
          );
      } finally {
        state.close();
      }
      await client.request("push.pqc.redeem", descriptor); // Discard the first read response.
      const retried = await client.request("push.pqc.redeem", descriptor);
      assert.equal(retried.payload, signed.payload);
      assert.deepEqual(retried.envelope, signed.envelope);
      assert.equal(
        sdk.verifySignedPushEnvelope({
          ...retried,
          trustedKeys: keys,
          expectedRecipientId: recipientId,
          replayGuard: sdk.createPushReplayGuard(),
        }),
        true,
      );
      const acknowledgement = { ...descriptor, acknowledge: true };
      await client.request("push.pqc.redeem", acknowledgement); // Discard the first ACK response.
      assert.deepEqual(await client.request("push.pqc.redeem", acknowledgement), {
        acknowledged: true,
      });
      await assert.rejects(
        client.request("push.pqc.redeem", descriptor),
        (error) => error.code === "UNAVAILABLE" && error.message === "push reference unavailable",
      );
    } finally {
      clearTimeout(timer);
      await client.stopAndWait();
    }
  } else if (mode === "first") {
    const signed = sdk.signPushEnvelope({
      payload: '{"title":"Installation verification"}',
      recipientId: "installation-test",
    });
    assert.throws(() => verify(signed, { payload: "tampered" }));
    assert.throws(() => verify(signed, { expectedRecipientId: "another-device" }));
    assert.throws(() =>
      verify(signed, { envelope: { ...signed.envelope, mldsa65_sig: "A".repeat(4412) } }),
    );
    assert.throws(() => verify(signed, { nowMs: signed.envelope.created_at_ms + 300001 }));
    assert.equal(verify(signed), true);
    assert.throws(() => verify(signed));
    const db = new DatabaseSync(path.join(dir, "state/openclaw.sqlite"), { readOnly: true });
    try {
      const rows = db
        .prepare(
          "SELECT private_key_pem, mldsa_private_key_pem, mldsa_private_key_wrapped FROM device_identities",
        )
        .all();
      assert.ok(rows.length > 0);
      for (const row of rows) {
        assert.equal(row.private_key_pem, "");
        assert.ok(!row.mldsa_private_key_pem);
        assert.ok(row.mldsa_private_key_wrapped?.length > 0);
      }
    } finally {
      db.close();
    }
    const completionSigned = sdk.signPushEnvelope({
      payload: '{"operation":"installed-local-effect"}',
      recipientId: "installation-test",
    });
    const writable = new DatabaseSync(path.join(dir, "state/openclaw.sqlite"));
    writable.exec("CREATE TABLE installed_pqc_effects(value INTEGER NOT NULL) STRICT");
    writable.close();
    const effect = ({ db: effectDatabase }) => {
      effectDatabase.prepare("INSERT INTO installed_pqc_effects(value) VALUES (1)").run();
      return { result: "completed" };
    };
    assert.throws(
      () =>
        consume(completionSigned, (database) => {
          effect(database);
          throw new Error("controlled pre-commit failure");
        }),
      /controlled pre-commit failure/,
    );
    assert.deepEqual(consume(completionSigned, effect), {
      status: "fresh_completed",
      value: { result: "completed" },
    });
    assert.deepEqual(
      consume(completionSigned, () => {
        throw new Error("duplicate effect");
      }),
      { status: "already_completed", value: { result: "completed" } },
    );
    writeFileSync(proofPath(dir), JSON.stringify({ signed, keys, completionSigned }), {
      flag: "wx",
      mode: 0o600,
    });
  } else if (mode === "restart" || mode === "restored") {
    const proof = JSON.parse(readFileSync(proofPath(dir), "utf8"));
    assert.deepEqual(keys, proof.keys, "restored identity changed");
    assert.throws(() => verify(proof.signed), "restart lost replay state");
    assert.deepEqual(
      consume(proof.completionSigned, () => {
        throw new Error("restart repeated effect");
      }),
      { status: "already_completed", value: { result: "completed" } },
    );
    const effectState = new DatabaseSync(path.join(dir, "state/openclaw.sqlite"), {
      readOnly: true,
    });
    try {
      assert.equal(
        effectState.prepare("SELECT COUNT(*) AS count FROM installed_pqc_effects").get().count,
        1,
      );
    } finally {
      effectState.close();
    }
    const signed = sdk.signPushEnvelope({
      payload: '{"title":"After restart"}',
      recipientId: "installation-test",
    });
    assert.ok(signed.envelope.sequence > proof.signed.envelope.sequence);
    assert.equal(verify(signed), true);
  } else {
    throw new Error("invalid probe mode");
  }
} else {
  const directory = mkdtempSync(path.join(tmpdir(), "openclaw-installed-pqc-"));
  const home = path.join(directory, "home");
  mkdirSync(home);
  const env = Object.fromEntries(
    Object.entries(process.env).filter(([name]) => !/^(OPENCLAW_|MOLTBOT_|CLAWDBOT_)/i.test(name)),
  );
  Object.assign(env, {
    HOME: home,
    USERPROFILE: home,
    OPENCLAW_HOME: home,
    OPENCLAW_STATE_DIR: directory,
    OPENCLAW_CONFIG_PATH: path.join(directory, "openclaw.json"),
    OPENCLAW_NO_RESPAWN: "1",
    NODE_DISABLE_COMPILE_CACHE: "1",
    NODE_TLS_REJECT_UNAUTHORIZED: "1",
  });
  delete env.NODE_OPTIONS;
  delete env.NODE_COMPILE_CACHE;
  try {
    // Initialization is an explicit operator action, never a read-side effect.
    // Exercise that public CLI only inside this verifier's throwaway profile.
    const uninitialized = child([cliPath, "security", "push-key", "status", "--json"], env, false);
    assert.equal(JSON.parse(uninitialized.stdout).ready, false);
    const now = Date.now();
    const initialized = child(
      [
        cliPath,
        "security",
        "push-key",
        "init",
        "--valid-from-ms",
        String(now - 1000),
        "--valid-until-ms",
        String(now + 60 * 60_000),
        "--json",
      ],
      env,
    );
    assert.equal(JSON.parse(initialized.stdout).ready, true);
    child([scriptPath, "--probe", "first"], env);
    child([scriptPath, "--probe", "restart"], env);
    const initial = JSON.parse(readFileSync(proofPath(directory), "utf8"));
    await verifyGatewayHandshake(env, initial.keys);
    const passphrase = path.join(directory, "passphrase.txt");
    const backup = path.join(directory, "backup.txt");
    const restored = path.join(directory, "restored.key");
    writeFileSync(passphrase, "temporary installation verification passphrase", { mode: 0o600 });
    child(
      [
        cliPath,
        "security",
        "wrap-key",
        "export",
        "--output",
        backup,
        "--passphrase-file",
        passphrase,
      ],
      env,
    );
    unlinkSync(path.join(directory, "credentials/device-identity-wrap.key"));
    child([scriptPath, "--probe", "restored"], env, false);
    child(
      [
        cliPath,
        "security",
        "wrap-key",
        "import",
        "--input",
        backup,
        "--output",
        restored,
        "--passphrase-file",
        passphrase,
      ],
      env,
    );
    const proof = JSON.parse(readFileSync(proofPath(directory), "utf8"));
    const recovered = {
      ...env,
      OPENCLAW_WRAP_KEY_FILE: restored,
      OPENCLAW_PQC_WRAP_KEY_ID: "file-default",
    };
    // The backup records the automatic key's identifier; read it without exposing key bytes.
    recovered.OPENCLAW_PQC_WRAP_KEY_ID = JSON.parse(
      Buffer.from(readFileSync(backup, "utf8").trim(), "base64url").toString("utf8"),
    ).keyId;
    child([scriptPath, "--probe", "restored"], recovered);
    assert.ok(proof.keys.senderId);
    process.stdout.write(
      "Installed PQC behavior verified: encrypted identity, dual signatures, binding, expiry, persistent replay, atomic local completion, restart, authenticated gateway handshake, retryable read and ACK RPCs, invalid-proof rejection, lost-key refusal and backup recovery. Live services and physical devices are not covered.\n",
    );
  } finally {
    assert.equal(path.dirname(directory), path.resolve(tmpdir()));
    assert.ok(path.basename(directory).startsWith("openclaw-installed-pqc-"));
    rmSync(directory, { recursive: true, force: true });
  }
}
