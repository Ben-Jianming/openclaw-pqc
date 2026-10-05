import fs from "node:fs";
import os from "node:os";
import path from "node:path";
/**
 * M17: pqcLog wire-up for device-identity (Part 2 §3.1 success criteria).
 *
 * Verifies that loadOrCreateDeviceIdentity emits pqcLog events on:
 * - load existing identity (ok or warn depending on wrap state)
 * - generate new identity (ok)
 * - legacy plaintext fallback (warn)
 *
 * The pqcLog chokepoint writes to bindOpenClawLogger (pino) or defaultEmitter
 * (console). We intercept via setPqcEmit to capture events.
 */
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { setPqcEmit, resetPqcEmit, type PqcLogPayload } from "../logging/pqc-log.js";
import { closeOpenClawStateDatabaseForTest } from "../state/openclaw-state-db.js";
import type { DeviceIdentityStoreOptions } from "./device-identity-store.js";
import { loadOrCreateDeviceIdentity } from "./device-identity.js";

const WRAP_KEY = "XYU5RKqbBTfbrFvLrcSlgmMSyM5LnlLZk7vUUhKbEVg";
const WRAP_KEY_ID = "m17-test-wrap-2026-08";

let tempDir: string;
let capturedEvents: PqcLogPayload[];
let savedEnv: Record<string, string | undefined>;

beforeEach(() => {
  tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "pqc-m17-test-"));
  capturedEvents = [];
  setPqcEmit((record) => {
    capturedEvents.push(record);
  });
  savedEnv = {
    OPENCLAW_STATE_DIR: process.env.OPENCLAW_STATE_DIR,
    OPENCLAW_PQC_WRAP_KEY: process.env.OPENCLAW_PQC_WRAP_KEY,
    OPENCLAW_PQC_WRAP_KEY_ID: process.env.OPENCLAW_PQC_WRAP_KEY_ID,
    OPENCLAW_WRAP_KEY_FILE: process.env.OPENCLAW_WRAP_KEY_FILE,
  };
  process.env.OPENCLAW_STATE_DIR = tempDir;
  delete process.env.OPENCLAW_WRAP_KEY_FILE;
  delete process.env.OPENCLAW_PQC_WRAP_KEY;
  delete process.env.OPENCLAW_PQC_WRAP_KEY_ID;
});

afterEach(() => {
  for (const [k, v] of Object.entries(savedEnv)) {
    if (v === undefined) {
      delete process.env[k];
    } else {
      process.env[k] = v;
    }
  }
  resetPqcEmit();
  closeOpenClawStateDatabaseForTest();
  fs.rmSync(tempDir, { recursive: true, force: true });
});

function options(): DeviceIdentityStoreOptions {
  return { env: { ...process.env, OPENCLAW_STATE_DIR: tempDir } as NodeJS.ProcessEnv };
}

function deviceIdentityEvents(events: PqcLogPayload[]): PqcLogPayload[] {
  return events.filter((e) => e.event === "device-identity");
}

describe("M17: device-identity pqcLog wire-up", () => {
  it("emits device-identity event on first-time wrapped identity generation", () => {
    loadOrCreateDeviceIdentity(options());
    const devEvents = deviceIdentityEvents(capturedEvents);
    expect(devEvents.length).toBeGreaterThanOrEqual(1);
    // The LAST event is the "generated" event (load would be 0 because no row existed)
    const last = devEvents[devEvents.length - 1]!;
    expect(last.status).toBe("ok");
    expect(last.identityKey).toBe("primary");
    expect(String(last.detail)).toMatch(/generated and wrapped/);
  });

  it("reports automatic private wrapping-key provisioning", () => {
    loadOrCreateDeviceIdentity(options());
    expect(capturedEvents.some((e) => String(e.detail).includes("created private state-dir"))).toBe(
      true,
    );
    expect(capturedEvents.some((e) => String(e.detail).includes("plaintext"))).toBe(false);
  });

  it("emits ok event on reload (existing identity loaded as-is)", () => {
    // First load creates the identity (emits "generated" event)
    loadOrCreateDeviceIdentity(options());
    capturedEvents.length = 0; // reset capture
    // Second load should emit "loaded existing" event
    loadOrCreateDeviceIdentity(options());
    const devEvents = deviceIdentityEvents(capturedEvents);
    expect(devEvents.length).toBeGreaterThanOrEqual(1);
    const loadEvent = devEvents.find((e) => String(e.detail).includes("loaded existing"));
    expect(loadEvent).toBeDefined();
    expect(loadEvent!.status).toBe("ok");
  });

  it("emits ok event with 'wrapped' detail when wrap key is set", () => {
    process.env.OPENCLAW_PQC_WRAP_KEY = WRAP_KEY;
    process.env.OPENCLAW_PQC_WRAP_KEY_ID = WRAP_KEY_ID;
    loadOrCreateDeviceIdentity(options());
    const devEvents = deviceIdentityEvents(capturedEvents);
    expect(devEvents.length).toBeGreaterThanOrEqual(1);
    const last = devEvents[devEvents.length - 1]!;
    expect(last.status).toBe("ok");
    expect(String(last.detail)).toMatch(/wrapped/);
  });

  it("loads the same wrapped identity after automatic provisioning", () => {
    const before = loadOrCreateDeviceIdentity(options());
    capturedEvents.length = 0;
    closeOpenClawStateDatabaseForTest();
    const after = loadOrCreateDeviceIdentity(options());
    expect(after.deviceId).toBe(before.deviceId);
    expect(
      deviceIdentityEvents(capturedEvents).some((e) =>
        String(e.detail).includes("loaded existing wrapped"),
      ),
    ).toBe(true);
  });
});
