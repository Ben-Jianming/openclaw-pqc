import CMLDSANative
import CryptoKit
import Foundation
import Security

enum MLDSA65Provider {
    static let seedByteCount = Int(OPENCLAW_MLDSA65_SEED_BYTES)
    static let publicKeyByteCount = Int(OPENCLAW_MLDSA65_PUBLIC_KEY_BYTES)
    static let signatureByteCount = Int(OPENCLAW_MLDSA65_SIGNATURE_BYTES)
    private static let randomnessByteCount = Int(OPENCLAW_MLDSA65_RANDOM_BYTES)

    enum ProviderError: Error {
        case invalidSeed
        case invalidPublicKey
        case randomGenerationFailed(OSStatus)
        case nativeFailure(Int32)
    }

    static func generate() throws -> (seed: Data, publicKey: Data) {
        if #available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *) {
            let privateKey = try MLDSA65.PrivateKey()
            return (privateKey.seedRepresentation, privateKey.publicKey.rawRepresentation)
        }
        let seed = try self.randomData(count: self.seedByteCount)
        return (seed, try self.portablePublicKey(seed: seed))
    }

    static func publicKey(seed: Data) throws -> Data {
        try self.portablePublicKey(seed: seed)
    }

    static func sign(message: Data, seed: Data, publicKey: Data) throws -> Data {
        guard seed.count == self.seedByteCount else { throw ProviderError.invalidSeed }
        guard publicKey.count == self.publicKeyByteCount else { throw ProviderError.invalidPublicKey }
        if #available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, visionOS 26.0, *) {
            let systemPublicKey = try MLDSA65.PublicKey(rawRepresentation: publicKey)
            let privateKey = try MLDSA65.PrivateKey(
                seedRepresentation: seed,
                publicKey: systemPublicKey)
            return try privateKey.signature(for: message)
        }
        return try self.portableSign(message: message, seed: seed)
    }

    static func portablePublicKey(seed: Data) throws -> Data {
        guard seed.count == self.seedByteCount else { throw ProviderError.invalidSeed }
        let outputCount = self.publicKeyByteCount
        var output = Data(count: outputCount)
        let result = seed.withUnsafeBytes { seedBytes in
            output.withUnsafeMutableBytes { outputBytes in
                openclaw_mldsa65_public_from_seed(
                    seedBytes.bindMemory(to: UInt8.self).baseAddress,
                    seed.count,
                    outputBytes.bindMemory(to: UInt8.self).baseAddress,
                    outputCount)
            }
        }
        guard result == 0 else { throw ProviderError.nativeFailure(result) }
        return output
    }

    static func portableSign(
        message: Data,
        seed: Data,
        randomness: Data? = nil) throws -> Data
    {
        guard seed.count == self.seedByteCount else { throw ProviderError.invalidSeed }
        let signingRandomness = try (randomness ?? self.randomData(count: self.randomnessByteCount))
        guard signingRandomness.count == self.randomnessByteCount else {
            throw ProviderError.randomGenerationFailed(errSecParam)
        }
        let signatureCount = self.signatureByteCount
        var signature = Data(count: signatureCount)
        let result = seed.withUnsafeBytes { seedBytes in
            message.withUnsafeBytes { messageBytes in
                signingRandomness.withUnsafeBytes { randomnessBytes in
                    signature.withUnsafeMutableBytes { signatureBytes in
                        openclaw_mldsa65_sign(
                            seedBytes.bindMemory(to: UInt8.self).baseAddress,
                            seed.count,
                            messageBytes.bindMemory(to: UInt8.self).baseAddress,
                            message.count,
                            randomnessBytes.bindMemory(to: UInt8.self).baseAddress,
                            signingRandomness.count,
                            signatureBytes.bindMemory(to: UInt8.self).baseAddress,
                            signatureCount)
                    }
                }
            }
        }
        guard result == 0 else { throw ProviderError.nativeFailure(result) }
        return signature
    }

    static func portableVerify(signature: Data, message: Data, publicKey: Data) -> Bool {
        guard publicKey.count == self.publicKeyByteCount,
              signature.count == self.signatureByteCount
        else { return false }
        let result = publicKey.withUnsafeBytes { publicKeyBytes in
            message.withUnsafeBytes { messageBytes in
                signature.withUnsafeBytes { signatureBytes in
                    openclaw_mldsa65_verify(
                        publicKeyBytes.bindMemory(to: UInt8.self).baseAddress,
                        publicKey.count,
                        messageBytes.bindMemory(to: UInt8.self).baseAddress,
                        message.count,
                        signatureBytes.bindMemory(to: UInt8.self).baseAddress,
                        signature.count)
                }
            }
        }
        return result == 0
    }

    private static func randomData(count: Int) throws -> Data {
        var data = Data(count: count)
        let status = data.withUnsafeMutableBytes { bytes in
            SecRandomCopyBytes(kSecRandomDefault, count, bytes.baseAddress!)
        }
        guard status == errSecSuccess else { throw ProviderError.randomGenerationFailed(status) }
        return data
    }
}
