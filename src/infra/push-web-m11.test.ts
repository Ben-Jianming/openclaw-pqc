import { afterEach, describe, expect, it, vi } from "vitest";
import { InMemoryPushReferenceStore } from "../security/push-reference.test-support.js";
const mocks = vi.hoisted(() => ({ sign: vi.fn() }));
vi.mock("./push-envelope.js", () => ({ signPushEnvelope: mocks.sign }));
import { buildApnsPqcWake } from "./push-apns-wake.js";
import { buildWebPushPayloadWithEnvelope } from "./push-web-m11.js";
afterEach(() => vi.resetAllMocks());
describe("fail-closed opaque push transport", () => {
  it("never sends sensitive fields or a full signature through the relay", () => {
    const input = {
      title: "secret title",
      body: "secret body",
      url: "https://evil.example/",
      aps: { alert: "sensitive" },
    };
    mocks.sign.mockReturnValue({
      payload: JSON.stringify(input),
      envelope: { recipient_id: "alice" },
    });
    const store = new InMemoryPushReferenceStore();
    const wake = buildWebPushPayloadWithEnvelope(input, "alice", { store });
    expect(JSON.stringify(wake)).not.toMatch(/secret|sensitive|evil|mldsa65_sig/);
    expect(Buffer.byteLength(JSON.stringify(wake))).toBeLessThan(3993);
    expect(JSON.parse(store.redeem(wake.pqc_ref, "alice").payload)).toEqual(input);
    const apns = buildApnsPqcWake(input, "alice", store);
    expect(JSON.stringify(apns)).not.toMatch(/secret|sensitive|evil/);
    expect(apns.aps.alert?.title).toBe("OpenClaw");
    expect(Buffer.byteLength(JSON.stringify(apns))).toBeLessThan(4096);
  });
  it("stops before storing or emitting when signing fails", () => {
    mocks.sign.mockImplementation(() => {
      throw new Error("signing failed");
    });
    const store = new InMemoryPushReferenceStore();
    expect(() => buildWebPushPayloadWithEnvelope({ body: "secret" }, "alice", { store })).toThrow(
      "signing failed",
    );
    expect(store.size).toBe(0);
    expect(() => buildWebPushPayloadWithEnvelope({}, "", { store })).toThrow("authenticated");
  });
});
