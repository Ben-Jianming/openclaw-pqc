import { ed25519 } from "@noble/curves/ed25519";
import { sha256, sha384, sha512 } from "@noble/hashes/sha2";
import { hmac as hmacN } from "@noble/hashes/hmac";
import { ml_dsa44, ml_dsa65, ml_dsa87 } from "@noble/post-quantum";
import { ml_kem768 } from "@noble/post-quantum";
import { CryptoError, UnsupportedAlgorithmError } from "./provider.js"; import type { CryptoProvider, Key, SignAlg, KemAlg, HashAlg } from "./provider.js";
export class NobleCryptoProvider implements CryptoProvider {
  readonly name = "noble";
  async sign(alg: SignAlg, key: Key, m: Uint8Array): Promise<Uint8Array> {
    if (key.kind !== "private") throw new CryptoError("need private key");
    if (alg === "ed25519") return ed25519.sign(m, key.material);
    if (alg === "ml-dsa-44") return ml_dsa44.sign(m, key.material);
    if (alg === "ml-dsa-65") return ml_dsa65.sign(m, key.material);
    if (alg === "ml-dsa-87") return ml_dsa87.sign(m, key.material);
    throw new UnsupportedAlgorithmError(alg);
  }
  async verify(alg: SignAlg, key: Key, m: Uint8Array, s: Uint8Array): Promise<boolean> {
    if (key.kind !== "public") throw new CryptoError("need public key");
    if (alg === "ed25519") return ed25519.verify(s, m, key.material);
    if (alg === "ml-dsa-44") return ml_dsa44.verify(s, m, key.material);
    if (alg === "ml-dsa-65") return ml_dsa65.verify(s, m, key.material);
    if (alg === "ml-dsa-87") return ml_dsa87.verify(s, m, key.material);
    throw new UnsupportedAlgorithmError(alg);
  }
  async kemGenerate(alg: KemAlg): Promise<{publicKey: Key, privateKey: Key}> {
    if (alg === "ml-kem-768") { const k = ml_kem768.keygen(); return { publicKey: {alg, material: k.publicKey, kind:"public"}, privateKey: {alg, material: k.secretKey, kind:"private"} }; }
    throw new UnsupportedAlgorithmError(alg);
  }
  async kemEncapsulate(alg: KemAlg, pk: Key): Promise<{sharedSecret: Uint8Array, ciphertext: Uint8Array}> {
    if (alg === "ml-kem-768") { const r = ml_kem768.encapsulate(pk.material); return {sharedSecret: r.sharedSecret, ciphertext: r.cipherText}; }
    throw new UnsupportedAlgorithmError(alg);
  }
  async kemDecapsulate(alg: KemAlg, sk: Key, ct: Uint8Array): Promise<Uint8Array> {
    if (alg === "ml-kem-768") return ml_kem768.decapsulate(ct, sk.material);
    throw new UnsupportedAlgorithmError(alg);
  }
  async hash(alg: HashAlg, m: Uint8Array): Promise<Uint8Array> { if (alg==="sha-256") return sha256(m); if (alg==="sha-384") return sha384(m); if (alg==="sha-512") return sha512(m); throw new UnsupportedAlgorithmError(alg); }
  async hmac(alg: HashAlg, k: Uint8Array, m: Uint8Array): Promise<Uint8Array> { if (alg==="sha-256") return hmacN(sha256, k, m); if (alg==="sha-384") return hmacN(sha384, k, m); if (alg==="sha-512") return hmacN(sha512, k, m); throw new UnsupportedAlgorithmError(alg); }
  randomBytes(n: number): Uint8Array { const {randomBytes} = require("node:crypto"); return new Uint8Array(randomBytes(n)); }
}
