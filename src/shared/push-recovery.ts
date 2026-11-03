import { PUSH_KEY_POLICY_CAPABILITY } from "./push-key-policy.js";

// Existing objects allow 64 KiB text plus a 16 KiB envelope. JSON text escaping
// can expand payload bytes sixfold. This budget still fits at least five maximum
// legal objects per page, so a 100-object recipient queue needs at most 20 reads.
export const MAX_PUSH_RECOVERY_PAGE_BYTES = 2 * 1024 * 1024;
export const MAX_PUSH_RECOVERY_PAGE_ITEMS = 16;
// Bound malformed/hostile cursor streams, while allowing the full durable queue.
export const MAX_PUSH_RECOVERY_PAGES = 32;
// Advertised back only on a session eligible for the immutable-snapshot contract.
export const PUSH_RECOVERY_CAPABILITY = "push-recovery-snapshot-v1";
export const PUSH_RECOVERY_ACTIVE_CAPABILITY = "push-recovery-snapshot-active-v1";

/** Hello advertisement and request authorization must negotiate the same pair. */
export function hasPushRecoveryCapabilities(caps: readonly string[] | undefined): boolean {
  return Boolean(
    caps?.includes(PUSH_RECOVERY_CAPABILITY) && caps.includes(PUSH_KEY_POLICY_CAPABILITY),
  );
}
