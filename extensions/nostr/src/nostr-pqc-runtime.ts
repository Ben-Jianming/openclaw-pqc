import { decrypt, encrypt } from "nostr-tools/nip04";
import type { NostrPqcMode } from "./config-schema.js";
import {
  decodeMlKemPublicKey,
  decodeMlKemSecretKey,
  decryptNip44V2,
  encryptNip44V2,
  isPqcNip44Envelope,
} from "./pqc-nip44.js";

export interface NostrPqcConfig {
  mode: NostrPqcMode;
  privateKeys: string[];
  peerPublicKeys: Record<string, string>;
}

export interface NostrPqcRuntime {
  mode: NostrPqcMode;
  privateKeys: Uint8Array[];
  peerPublicKeys: Map<string, Uint8Array>;
}

export function createNostrPqcRuntime(config?: NostrPqcConfig): NostrPqcRuntime {
  const mode = config?.mode ?? "disabled";
  const privateKeys = (config?.privateKeys ?? []).map(decodeMlKemSecretKey);
  const peerPublicKeys = new Map(
    Object.entries(config?.peerPublicKeys ?? {}).map(([peer, key]) => [
      peer.toLowerCase(),
      decodeMlKemPublicKey(key),
    ]),
  );
  if (mode === "required" && privateKeys.length === 0) {
    throw new Error("Nostr PQC mode is required but no ML-KEM-768 private key is configured");
  }
  return { mode, privateKeys, peerPublicKeys };
}

export function decryptDirectMessage(
  pqc: NostrPqcRuntime,
  nostrPrivateKey: Uint8Array,
  senderPubkey: string,
  ciphertext: string,
): string {
  if (isPqcNip44Envelope(ciphertext)) {
    if (pqc.privateKeys.length === 0) {
      throw new Error("received an ML-KEM-768 message without a configured private key");
    }
    let lastError: unknown;
    for (const privateKey of pqc.privateKeys) {
      try {
        return new TextDecoder().decode(decryptNip44V2(privateKey, ciphertext));
      } catch (error) {
        lastError = error;
      }
    }
    throw new Error("ML-KEM-768 message did not match the current or retained rotation keys", {
      cause: lastError,
    });
  }
  if (pqc.mode === "required") {
    throw new Error("legacy NIP-04 message rejected because Nostr PQC mode is required");
  }
  return decrypt(nostrPrivateKey, senderPubkey, ciphertext);
}

export function encryptDirectMessage(
  pqc: NostrPqcRuntime,
  nostrPrivateKey: Uint8Array,
  recipientPubkey: string,
  plaintext: string,
): { ciphertext: string; pqc: boolean } {
  const recipientPqcKey = pqc.peerPublicKeys.get(recipientPubkey.toLowerCase());
  if (recipientPqcKey) {
    return {
      ciphertext: encryptNip44V2(recipientPqcKey, new TextEncoder().encode(plaintext)),
      pqc: true,
    };
  }
  if (pqc.mode === "required") {
    throw new Error(
      `no trusted ML-KEM-768 public key is configured for Nostr peer ${recipientPubkey}`,
    );
  }
  return { ciphertext: encrypt(nostrPrivateKey, recipientPubkey, plaintext), pqc: false };
}
