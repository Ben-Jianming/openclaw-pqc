export type SignAlg = "ed25519" | "ml-dsa-44" | "ml-dsa-65" | "ml-dsa-87" | "slh-dsa-sha2-128s";
export type KemAlg = "x25519" | "ml-kem-512" | "ml-kem-768" | "ml-kem-1024";
export type HashAlg = "sha-256" | "sha-384" | "sha-512";
export interface Key {
  readonly alg: SignAlg | KemAlg;
  readonly material: Uint8Array;
  readonly kind: "private" | "public" | "secret";
}
export interface CryptoProvider {
  readonly name: string;
  sign(alg: SignAlg, key: Key, message: Uint8Array): Promise<Uint8Array>;
  verify(alg: SignAlg, key: Key, message: Uint8Array, signature: Uint8Array): Promise<boolean>;
  kemGenerate(alg: KemAlg): Promise<{ publicKey: Key; privateKey: Key }>;
  kemEncapsulate(
    alg: KemAlg,
    pk: Key,
  ): Promise<{ sharedSecret: Uint8Array; ciphertext: Uint8Array }>;
  kemDecapsulate(alg: KemAlg, sk: Key, ct: Uint8Array): Promise<Uint8Array>;
  hash(alg: HashAlg, message: Uint8Array): Promise<Uint8Array>;
  hmac(alg: HashAlg, key: Uint8Array, message: Uint8Array): Promise<Uint8Array>;
  randomBytes(length: number): Uint8Array;
}
export class CryptoError extends Error {
  constructor(
    m: string,
    public alg?: string,
  ) {
    super(m);
    this.name = "CryptoError";
  }
}
export class UnsupportedAlgorithmError extends CryptoError {
  constructor(alg: string) {
    super("unsupported: " + alg, alg);
    this.name = "UnsupportedAlgorithmError";
  }
}
export type BackendName = "noble" | "node-builtin" | "liboqs";
let cachedProvider: CryptoProvider | null = null;
export async function getCryptoProvider(b: BackendName = "noble"): Promise<CryptoProvider> {
  if (cachedProvider) {
    return cachedProvider;
  }
  if (b === "noble") {
    const m = await import("./provider-noble.js");
    cachedProvider = new m.NobleCryptoProvider();
  } else if (b === "node-builtin") {
    const m = await import("./provider-node-builtin.js");
    cachedProvider = new m.NodeBuiltinCryptoProvider();
  } else {
    throw new Error("liboqs not implemented");
  }
  return cachedProvider;
}
function resetProviderForTesting(): void {
  cachedProvider = null;
}
export { resetProviderForTesting as _resetProviderForTesting };
export interface DualSignature {
  readonly ed25519?: Uint8Array;
  readonly mlDsa44?: Uint8Array;
}
export async function dualSignDevice(
  message: Uint8Array,
  edKey: Key,
  mlKey: Key,
): Promise<DualSignature> {
  const p = await getCryptoProvider();
  const sig: { ed25519?: Uint8Array; mlDsa44?: Uint8Array } = {};
  try {
    sig.ed25519 = await p.sign("ed25519", edKey, message);
  } catch (e) {
    console.warn("ed25519 fail:", e);
  }
  if (mlKey) {
    sig.mlDsa44 = await p.sign("ml-dsa-44", mlKey, message);
  }
  return sig;
}
export async function dualVerifyDevice(
  message: Uint8Array,
  edKey: Key,
  mlKey: Key | null,
  sig: DualSignature,
): Promise<boolean> {
  const p = await getCryptoProvider();
  if (sig.ed25519 && edKey) {
    if (await p.verify("ed25519", edKey, message, sig.ed25519)) {
      return true;
    }
  }
  if (sig.mlDsa44 && mlKey) {
    if (await p.verify("ml-dsa-44", mlKey, message, sig.mlDsa44)) {
      return true;
    }
  }
  return false;
}
