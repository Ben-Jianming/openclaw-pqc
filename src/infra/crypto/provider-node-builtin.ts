import { createHash, createHmac, createPrivateKey, createPublicKey, sign, verify, randomBytes } from "node:crypto";
import { CryptoError, UnsupportedAlgorithmError } from "./provider.js"; import type { CryptoProvider, Key, SignAlg, KemAlg, HashAlg } from "./provider.js";
export class NodeBuiltinCryptoProvider implements CryptoProvider {
  readonly name = "node-builtin";
  async sign(alg: SignAlg, key: Key, m: Uint8Array): Promise<Uint8Array> {
    if (alg === "ed25519") { const k = createPrivateKey(Buffer.from(key.material)); return new Uint8Array(sign(null, Buffer.from(m), k)); }
    throw new UnsupportedAlgorithmError(alg);
  }
  async verify(alg: SignAlg, key: Key, m: Uint8Array, s: Uint8Array): Promise<boolean> {
    if (alg === "ed25519") { const k = createPublicKey(Buffer.from(key.material)); return verify(null, Buffer.from(m), k, Buffer.from(s)); }
    throw new UnsupportedAlgorithmError(alg);
  }
  async kemGenerate(alg: KemAlg): Promise<any> { throw new UnsupportedAlgorithmError(alg); }
  async kemEncapsulate(): Promise<any> { throw new CryptoError("not supported"); }
  async kemDecapsulate(): Promise<any> { throw new CryptoError("not supported"); }
  async hash(alg: HashAlg, m: Uint8Array): Promise<Uint8Array> { return new Uint8Array(createHash(alg.replace("-","")).update(m).digest()); }
  async hmac(alg: HashAlg, k: Uint8Array, m: Uint8Array): Promise<Uint8Array> { return new Uint8Array(createHmac(alg.replace("-",""), k).update(m).digest()); }
  randomBytes(n: number): Uint8Array { return new Uint8Array(randomBytes(n)); }
}
