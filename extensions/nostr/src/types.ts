import { createAccountListHelpers } from "openclaw/plugin-sdk/account-helpers";
// Nostr type declarations define plugin contracts.
import {
  DEFAULT_ACCOUNT_ID,
  normalizeAccountId,
  normalizeOptionalAccountId,
} from "openclaw/plugin-sdk/account-id";
import type { OpenClawConfig } from "openclaw/plugin-sdk/config-contracts";
import { normalizeSecretInputString, type SecretInput } from "openclaw/plugin-sdk/secret-input";
import { normalizeOptionalString } from "openclaw/plugin-sdk/string-coerce-runtime";
import type { NostrPqcMode, NostrProfile } from "./config-schema.js";
import { DEFAULT_RELAYS } from "./default-relays.js";
import { getPublicKeyFromPrivate, normalizePubkey } from "./nostr-key-utils.js";

interface NostrAccountConfig {
  enabled?: boolean;
  name?: string;
  defaultAccount?: string;
  privateKey?: SecretInput;
  pqcMode?: NostrPqcMode;
  pqcPrivateKey?: SecretInput;
  pqcPreviousPrivateKeys?: SecretInput[];
  pqcPeerPublicKeys?: Record<string, string>;
  relays?: string[];
  dmPolicy?: "pairing" | "allowlist" | "open" | "disabled";
  allowFrom?: Array<string | number>;
  profile?: NostrProfile;
}

export interface ResolvedNostrAccount {
  accountId: string;
  name?: string;
  enabled: boolean;
  configured: boolean;
  privateKey: string;
  publicKey: string;
  relays: string[];
  pqcMode: NostrPqcMode;
  pqcPrivateKeys: string[];
  pqcPeerPublicKeys: Record<string, string>;
  profile?: NostrProfile;
  config: NostrAccountConfig;
}

const {
  listAccountIds: listNostrAccountIds,
  resolveDefaultAccountId: resolveDefaultNostrAccountId,
} = createAccountListHelpers("nostr", {
  fallbackAccountIdWhenEmpty: false,
  resolveImplicitAccountId: (cfg) => {
    const account = cfg.channels?.nostr as NostrAccountConfig | undefined;
    return normalizeSecretInputString(account?.privateKey)
      ? (normalizeOptionalAccountId(account?.defaultAccount) ?? DEFAULT_ACCOUNT_ID)
      : undefined;
  },
});

export { listNostrAccountIds, resolveDefaultNostrAccountId };

/**
 * Resolve a Nostr account from config
 */
export function resolveNostrAccount(opts: {
  cfg: OpenClawConfig;
  accountId?: string | null;
}): ResolvedNostrAccount {
  const accountId = normalizeAccountId(opts.accountId ?? resolveDefaultNostrAccountId(opts.cfg));
  const nostrCfg = (opts.cfg.channels as Record<string, unknown> | undefined)?.nostr as
    | NostrAccountConfig
    | undefined;

  const baseEnabled = nostrCfg?.enabled !== false;
  const privateKey = normalizeSecretInputString(nostrCfg?.privateKey) ?? "";
  const configured = Boolean(privateKey);
  const pqcPrivateKeys = [
    normalizeSecretInputString(nostrCfg?.pqcPrivateKey),
    ...(nostrCfg?.pqcPreviousPrivateKeys ?? []).map((entry) => normalizeSecretInputString(entry)),
  ].filter((entry): entry is string => Boolean(entry));
  const pqcPeerPublicKeys: Record<string, string> = {};
  for (const [peer, publicKey] of Object.entries(nostrCfg?.pqcPeerPublicKeys ?? {})) {
    pqcPeerPublicKeys[normalizePubkey(peer)] = publicKey.trim();
  }
  const pqcMode = nostrCfg?.pqcMode ?? (pqcPrivateKeys.length > 0 ? "preferred" : "disabled");

  let publicKey = "";
  if (privateKey) {
    try {
      publicKey = getPublicKeyFromPrivate(privateKey);
    } catch {
      // Invalid key - leave publicKey empty, configured will indicate issues
    }
  }

  return {
    accountId,
    name: normalizeOptionalString(nostrCfg?.name),
    enabled: baseEnabled,
    configured,
    privateKey,
    publicKey,
    relays: nostrCfg?.relays ?? DEFAULT_RELAYS,
    pqcMode,
    pqcPrivateKeys,
    pqcPeerPublicKeys,
    profile: nostrCfg?.profile,
    config: {
      enabled: nostrCfg?.enabled,
      name: nostrCfg?.name,
      privateKey: nostrCfg?.privateKey,
      pqcMode: nostrCfg?.pqcMode,
      pqcPrivateKey: nostrCfg?.pqcPrivateKey,
      pqcPreviousPrivateKeys: nostrCfg?.pqcPreviousPrivateKeys,
      pqcPeerPublicKeys: nostrCfg?.pqcPeerPublicKeys,
      relays: nostrCfg?.relays,
      dmPolicy: nostrCfg?.dmPolicy,
      allowFrom: nostrCfg?.allowFrom,
      profile: nostrCfg?.profile,
    },
  };
}
