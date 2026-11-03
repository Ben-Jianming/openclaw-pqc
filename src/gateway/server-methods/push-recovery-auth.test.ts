import { createHash } from "node:crypto";
import { beforeEach, describe, expect, it, vi } from "vitest";
import { getPairedDevice } from "../../infra/device-pairing.js";
import { hasPushRecoveryCapabilities } from "../../shared/push-recovery.js";
import { requirePushRecoveryRecipient } from "./push-recovery-auth.js";

vi.mock("../../infra/device-pairing.js", async (importOriginal) => ({
  ...(await importOriginal<typeof import("../../infra/device-pairing.js")>()),
  getPairedDevice: vi.fn(),
}));
const connection = () => ({
  connectionKind: "gateway" as const,
  isDeviceTokenAuth: true,
  authenticatedDeviceTokenSha256: createHash("sha256")
    .update("test-only-placeholder")
    .digest("hex"),
  verifiedDeviceProof: { id: "alice", publicKey: "proven-public-key" },
  invalidated: false,
  socket: { close: vi.fn() },
  isControlUiDeviceAuthMigrationSession: false,
  isControlUiDeviceAuthMigration: false,
  connect: {
    role: "operator",
    scopes: ["operator.read"],
    caps: ["push-key-policy-v1", "push-recovery-snapshot-v1"],
  },
});
const paired = () => ({
  deviceId: "alice",
  publicKey: "proven-public-key",
  role: "operator",
  roles: ["operator"],
  scopes: ["operator.read"],
  approvedScopes: ["operator.read"],
  createdAtMs: 1,
  approvedAtMs: 1,
  tokens: {
    operator: {
      token: "test-only-placeholder",
      role: "operator",
      scopes: ["operator.read"],
      createdAtMs: 1,
    },
  },
});
beforeEach(() => {
  vi.mocked(getPairedDevice).mockReset();
  vi.mocked(getPairedDevice).mockResolvedValue(paired());
});

describe("recovery identity authorization", () => {
  it.each([
    [undefined, false],
    [[], false],
    [["push-key-policy-v1"], false],
    [["push-recovery-snapshot-v1"], false],
    [["push-key-policy-v1", "push-recovery-snapshot-v1"], true],
  ] as const)("negotiates the same capability pair for hello and RPC: %j", (caps, expected) => {
    expect(hasPushRecoveryCapabilities(caps)).toBe(expected);
  });
  it("rejects a session authenticated with a replaced token even when pairing stays active", async () => {
    const client = connection();
    await expect(requirePushRecoveryRecipient(client)).resolves.toBe("alice");
    const current = paired();
    current.tokens.operator.token = "test-only-rotated-placeholder";
    vi.mocked(getPairedDevice).mockResolvedValue(current);
    await expect(requirePushRecoveryRecipient(client)).rejects.toThrow("unavailable");
    expect(client.invalidated).toBe(true);
    expect(client.socket.close).toHaveBeenCalledWith(4000, "secure push reauthentication required");
    const reconnected = connection();
    reconnected.authenticatedDeviceTokenSha256 = createHash("sha256")
      .update(current.tokens.operator.token)
      .digest("hex");
    await expect(requirePushRecoveryRecipient(reconnected)).resolves.toBe("alice");
  });
  it.each([undefined, "", "not-a-digest"])(
    "rejects unavailable credential binding %s",
    async (digest) => {
      await expect(
        requirePushRecoveryRecipient({ ...connection(), authenticatedDeviceTokenSha256: digest }),
      ).rejects.toThrow("unavailable");
      expect(getPairedDevice).not.toHaveBeenCalled();
    },
  );
  it.each([false, undefined])(
    "rejects signed sessions without actual device-token authentication: %s",
    async (isDeviceTokenAuth) => {
      await expect(
        requirePushRecoveryRecipient({ ...connection(), isDeviceTokenAuth }),
      ).rejects.toThrow("unavailable");
      expect(getPairedDevice).not.toHaveBeenCalled();
    },
  );
  it("uses retained server proof and re-reads pairing on each operation", async () => {
    expect(await requirePushRecoveryRecipient(connection())).toBe("alice");
    expect(getPairedDevice).toHaveBeenCalledWith("alice");
    vi.mocked(getPairedDevice).mockResolvedValue(null);
    await expect(requirePushRecoveryRecipient(connection())).rejects.toThrow("unavailable");
    expect(getPairedDevice).toHaveBeenCalledTimes(2);
  });
  it("rejects shared-auth or wire-claimed identities without server proof before reading pairing", async () => {
    const client = {
      ...connection(),
      verifiedDeviceProof: undefined,
      connect: { ...connection().connect, device: { id: "alice" } },
    };
    await expect(requirePushRecoveryRecipient(client)).rejects.toThrow("unavailable");
    expect(getPairedDevice).not.toHaveBeenCalled();
  });
  it.each([undefined, null])("rejects missing connection %s", async (client) => {
    await expect(requirePushRecoveryRecipient(client)).rejects.toThrow("unavailable");
  });
  it.each([
    { connectionKind: "worker" as const },
    { invalidated: true },
    { isControlUiDeviceAuthMigrationSession: true },
    { isControlUiDeviceAuthMigration: true },
    { connect: { ...connection().connect, role: "node" } },
    { connect: { ...connection().connect, scopes: [] } },
    { connect: { ...connection().connect, caps: ["push-key-policy-v1"] } },
    { connect: { ...connection().connect, caps: ["push-recovery-snapshot-v1"] } },
  ])("rejects unavailable session privilege %#", async (patch) => {
    await expect(requirePushRecoveryRecipient({ ...connection(), ...patch })).rejects.toThrow(
      "unavailable",
    );
    expect(getPairedDevice).not.toHaveBeenCalled();
  });
  const pairingChanges: Array<Partial<NonNullable<Awaited<ReturnType<typeof getPairedDevice>>>>> = [
    { publicKey: "replaced-key" },
    { deviceId: "bob" },
    { roles: ["node"], role: "node" },
    { approvedScopes: [] },
    { tokens: {} },
    { tokens: { operator: { ...paired().tokens.operator, revokedAtMs: 2 } } },
    { tokens: { operator: { ...paired().tokens.operator, scopes: [] } } },
  ];
  it.each(pairingChanges)("rejects current pairing or token changes %#", async (patch) => {
    vi.mocked(getPairedDevice).mockResolvedValue({ ...paired(), ...patch });
    const client = connection();
    await expect(requirePushRecoveryRecipient(client)).rejects.toThrow("unavailable");
    expect(client.invalidated).toBe(true);
    expect(client.socket.close).toHaveBeenCalledTimes(1);
  });
  it("rechecks connection invalidation while asynchronous pairing lookup resolves", async () => {
    const client = connection();
    vi.mocked(getPairedDevice).mockImplementation(async () => {
      client.invalidated = true;
      return paired();
    });
    await expect(requirePushRecoveryRecipient(client)).rejects.toThrow("unavailable");
  });
  it("propagates storage failure without allowing recovery", async () => {
    vi.mocked(getPairedDevice).mockRejectedValue(new Error("test pairing storage unavailable"));
    await expect(requirePushRecoveryRecipient(connection())).rejects.toThrow("storage unavailable");
  });
});
