import { describe, expect, it } from "vitest";
import type { PushDualEnvelope } from "./push-dual-signature.js";
import { InMemoryPushReferenceStore } from "./push-reference.test-support.js";

const envelope = { version: 2 } as PushDualEnvelope;

describe("one-time push reference store", () => {
  it("redeems exactly once and deletes before returning", () => {
    const store = new InMemoryPushReferenceStore();
    const ref = store.create(
      { payload: "{}", envelope, recipientId: "device-a" },
      { nowMs: 100, ttlMs: 100 },
    );
    expect(JSON.stringify({ pqc_ref: ref }).length).toBeLessThan(256);
    expect(store.redeem(ref, "device-a", 150).payload).toBe("{}");
    expect(() => store.redeem(ref, "device-a", 151)).toThrow(/unknown or already consumed/);
  });

  it("fails closed for wrong recipient and invalid token without letting an attacker burn the reference", () => {
    const store = new InMemoryPushReferenceStore();
    const ref = store.create(
      { payload: "{}", envelope, recipientId: "device-a" },
      { nowMs: 100, ttlMs: 100 },
    );
    expect(() => store.redeem(ref, "device-b", 150)).toThrow(/recipient/);
    const replacement = ref.token.endsWith("A") ? "B" : "A";
    expect(() =>
      store.redeem({ ...ref, token: `${ref.token.slice(0, -1)}${replacement}` }, "device-a", 150),
    ).toThrow(/token/);
    expect(store.size).toBe(1);
    expect(store.redeem(ref, "device-a", 150).payload).toBe("{}");
  });

  it("deletes an expired reference", () => {
    const store = new InMemoryPushReferenceStore();
    const ref = store.create(
      { payload: "{}", envelope, recipientId: "device-a" },
      { nowMs: 100, ttlMs: 100 },
    );
    expect(() => store.redeem(ref, "device-a", 201)).toThrow(/expired/);
    expect(store.size).toBe(0);
  });
});
