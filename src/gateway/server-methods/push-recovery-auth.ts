import { createHash, timingSafeEqual } from "node:crypto";
import type { ConnectParams } from "../../../packages/gateway-protocol/src/index.js";
import { getPairedDevice, listEffectivePairedDeviceRoles } from "../../infra/device-pairing.js";
import { roleScopesAllow } from "../../shared/operator-scope-compat.js";
import { hasPushRecoveryCapabilities } from "../../shared/push-recovery.js";
import type { GatewayWsClient } from "../server/ws-types.js";

type RecoveryConnection = Pick<
  GatewayWsClient,
  | "connectionKind"
  | "invalidated"
  | "isDeviceTokenAuth"
  | "authenticatedDeviceTokenSha256"
  | "verifiedDeviceProof"
  | "isControlUiDeviceAuthMigrationSession"
  | "isControlUiDeviceAuthMigration"
> & {
  connect: Pick<ConnectParams, "caps" | "role" | "scopes">;
  socket?: Pick<GatewayWsClient["socket"], "close">;
};

/** Recovery requires both a proven device key and actual device-token session authentication. */
export async function requirePushRecoveryAuthorization(
  client: RecoveryConnection | null | undefined,
): Promise<{ recipientId: string; tokenSha256: string }> {
  const denied = () => new Error("push recovery unavailable");
  const proof = client?.verifiedDeviceProof;
  const tokenSha256 = client?.authenticatedDeviceTokenSha256;
  if (
    !client ||
    client.connectionKind !== "gateway" ||
    client.isDeviceTokenAuth !== true ||
    typeof tokenSha256 !== "string" ||
    !/^[0-9a-f]{64}$/.test(tokenSha256) ||
    client.invalidated ||
    client.isControlUiDeviceAuthMigrationSession ||
    client.isControlUiDeviceAuthMigration ||
    !proof ||
    !proof.id ||
    !proof.publicKey ||
    client.connect.role !== "operator" ||
    !hasPushRecoveryCapabilities(client.connect.caps) ||
    !roleScopesAllow({
      role: "operator",
      requestedScopes: ["operator.read"],
      allowedScopes: client.connect.scopes ?? [],
    })
  ) {
    throw denied();
  }
  // Re-read on every list and every ACK. Handshake-time approval is insufficient after revocation.
  const paired = await getPairedDevice(proof.id);
  const token = paired?.tokens?.operator;
  if (
    client.invalidated ||
    !token ||
    !timingSafeEqual(
      Buffer.from(tokenSha256, "hex"),
      createHash("sha256").update(token.token).digest(),
    ) ||
    token.revokedAtMs ||
    !roleScopesAllow({
      role: "operator",
      requestedScopes: ["operator.read"],
      allowedScopes: token.scopes,
    }) ||
    !paired ||
    paired.deviceId !== proof.id ||
    paired.publicKey !== proof.publicKey ||
    !listEffectivePairedDeviceRoles(paired).includes("operator") ||
    !roleScopesAllow({
      role: "operator",
      requestedScopes: ["operator.read"],
      allowedScopes: paired.approvedScopes ?? paired.scopes ?? [],
    })
  ) {
    // A negotiated recovery session cannot keep polling with stale pairing or
    // credentials. The existing reconnect supervisor reloads the device token;
    // no authorization failure may fall back to shared/legacy push operations.
    client.invalidated = true;
    try {
      client.socket?.close(4000, "secure push reauthentication required");
    } catch {
      // A concurrently closed socket does not revive the invalidated session.
    }
    throw denied();
  }
  return { recipientId: proof.id, tokenSha256 };
}

export async function requirePushRecoveryRecipient(
  client: RecoveryConnection | null | undefined,
): Promise<string> {
  return (await requirePushRecoveryAuthorization(client)).recipientId;
}
