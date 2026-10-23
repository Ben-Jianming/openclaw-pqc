// Authenticated connect metadata, not a field supplied by an individual push RPC.
export const PUSH_KEY_POLICY_CAPABILITY = "push-key-policy-v1";

export type PushKeyPolicy = {
  algorithm: "ed25519" | "ml-dsa-65";
  keyId: string;
  senderId: string;
  publicKeyBase64Url: string;
  status: "active" | "revoked";
  validFromMs: number;
  validUntilMs: number;
  revision: number;
};

/** Policy is trusted only through the authenticated key provisioning channel. */
export function assertPushKeyPolicy(
  policy: PushKeyPolicy | undefined,
  algorithm: PushKeyPolicy["algorithm"],
  keyId: string,
  senderId: string,
  publicKeyBase64Url: string,
  nowMs: number,
): asserts policy is PushKeyPolicy {
  if (
    !policy ||
    policy.algorithm !== algorithm ||
    policy.keyId !== keyId ||
    policy.senderId !== senderId ||
    policy.publicKeyBase64Url !== publicKeyBase64Url ||
    policy.status !== "active" ||
    !Number.isSafeInteger(policy.validFromMs) ||
    !Number.isSafeInteger(policy.validUntilMs) ||
    policy.validFromMs < 0 ||
    policy.validUntilMs <= policy.validFromMs ||
    !Number.isSafeInteger(policy.revision) ||
    policy.revision < 1 ||
    !Number.isSafeInteger(nowMs) ||
    nowMs < policy.validFromMs ||
    nowMs >= policy.validUntilMs
  ) {
    throw new Error("push key policy unavailable, invalid, expired or revoked");
  }
}
