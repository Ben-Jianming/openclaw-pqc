import CryptoKit
import Foundation
import OpenClawNativeState

public struct PushV2Envelope: Codable, Sendable {
    public var version: Int64
    public var algorithms: [String]
    public var sender_id: String
    public var recipient_id: String
    public var key_id_ed25519: String
    public var key_id_mldsa65: String
    public var created_at_ms: Int64
    public var sequence: Int64
    public var nonce: String
    public var payload_type: String
    public var payload_sha256: String
    public var ed25519_sig: String
    public var mldsa65_sig: String
}

/// Obtain only over the already authenticated gateway route, never from APNs.
public struct PushV2TrustedKeys: Codable, Sendable {
    public var senderId: String
    public var recipientId: String
    public var keyIdEd25519: String
    public var keyIdMldsa65: String
    public var ed25519PublicKeyBase64Url: String
    public var mldsa65PublicKeyBase64Url: String
}

public struct PushV2Object: Codable, Sendable {
    public var payload: String
    public var envelope: PushV2Envelope
}

/// Only opaque capabilities may wait for app initialization, never provider text or routes.
public struct PushV2Wake: Sendable {
    private struct Reference: Codable {
        let version: Int64
        let object_id: String
        let token: String
        let expires_at_ms: Int64
    }

    public let referenceJSON: String
    public let expiresAtMs: Int64

    public var objectID: String? {
        (try? JSONDecoder().decode(Reference.self, from: Data(self.referenceJSON.utf8)))?.object_id
    }

    public init?(userInfo: [AnyHashable: Any], nowMs: Int64) {
        guard nowMs >= 0, nowMs <= 9_007_199_254_740_991,
              userInfo["kind"] as? String == "openclaw.pqc.wake.v2",
              let reference = userInfo["pqc_ref"] as? [String: Any],
              JSONSerialization.isValidJSONObject(reference),
              let data = try? JSONSerialization.data(withJSONObject: reference), data.count <= 1024,
              let value = try? JSONDecoder().decode(Reference.self, from: data), value.version == 1,
              let id = UUID(uuidString: value.object_id), id.uuidString.lowercased() == value.object_id,
              value.expires_at_ms > nowMs, value.expires_at_ms <= 9_007_199_254_740_991,
              value.expires_at_ms - nowMs <= 330_000,
              (try? PushV2Verifier.decode(value.token, count: 32)) != nil
        else { return nil }
        let encoder = JSONEncoder()
        encoder.outputFormatting = .sortedKeys
        guard let encoded = try? encoder.encode(value),
              let json = String(data: encoded, encoding: .utf8)
        else { return nil }
        self.referenceJSON = json
        self.expiresAtMs = value.expires_at_ms
    }

    public var userInfo: [AnyHashable: Any] {
        guard let reference = try? JSONSerialization.jsonObject(with: Data(self.referenceJSON.utf8))
        else { return [:] }
        return ["kind": "openclaw.pqc.wake.v2", "pqc_ref": reference]
    }
}

/// Opaque capabilities survive suspension and process death; no unverified body is stored.
/// SQLite transactions enforce capacity and deduplication across concurrent callbacks.
public final class PushV2WakeQueue: @unchecked Sendable {
    private let database: OpenClawNativeStateSQLite
    private let capacity: Int

    public init(databaseURL: URL, capacity: Int = 64) throws {
        self.capacity = max(0, min(capacity, 64))
        self.database = try OpenClawNativeStateSQLite(databaseURL: databaseURL)
        try self.database.withImmediateTransaction {
            try self.database.ensureCanonicalTable(.pqcPushWakes)
        }
    }

    public static func openDefault() throws -> PushV2WakeQueue {
        try PushV2WakeQueue(databaseURL: DeviceIdentityPaths.stateDirURL()
            .appendingPathComponent("state", isDirectory: true).appendingPathComponent("openclaw.sqlite"))
    }

    private func prune(nowMs: Int64) throws {
        let statement = try self.database.prepare("DELETE FROM pqc_push_wakes WHERE expires_at_ms <= ?")
        try statement.bindInt64(nowMs, at: 1)
        _ = try statement.step()
    }

    public func enqueue(_ wake: PushV2Wake, nowMs: Int64) throws -> Bool {
        try self.database.withImmediateTransaction {
            try self.prune(nowMs: nowMs)
            guard wake.expiresAtMs > nowMs else { return false }
            let existing = try self.database.prepare("SELECT 1 FROM pqc_push_wakes WHERE reference_json = ?")
            try existing.bindText(wake.referenceJSON, at: 1)
            if try existing.step() == .row { return true }
            guard try self.database.scalarInt64("SELECT COUNT(*) FROM pqc_push_wakes") < Int64(self.capacity)
            else { return false }
            let insert = try self.database.prepare(
                "INSERT INTO pqc_push_wakes(reference_json, expires_at_ms) VALUES (?, ?)")
            try insert.bindText(wake.referenceJSON, at: 1)
            try insert.bindInt64(wake.expiresAtMs, at: 2)
            _ = try insert.step()
            return true
        }
    }

    public func ready(nowMs: Int64) throws -> [PushV2Wake] {
        try self.database.withImmediateTransaction {
            try self.prune(nowMs: nowMs)
            let read = try self.database.prepare(
                "SELECT reference_json FROM pqc_push_wakes ORDER BY expires_at_ms, reference_json LIMIT 64")
            var references: [String] = []
            while try read.step() == .row {
                try references.append(read.requiredText(at: 0, field: "push reference"))
            }
            var wakes: [PushV2Wake] = []
            for json in references {
                if json.utf8.count <= 1024,
                   let reference = try? JSONSerialization.jsonObject(with: Data(json.utf8)),
                   let wake = PushV2Wake(userInfo: ["kind": "openclaw.pqc.wake.v2", "pqc_ref": reference], nowMs: nowMs)
                {
                    wakes.append(wake)
                } else {
                    try self.removeJSON(json)
                }
            }
            return wakes
        }
    }

    private func removeJSON(_ json: String) throws {
        let remove = try self.database.prepare("DELETE FROM pqc_push_wakes WHERE reference_json = ?")
        try remove.bindText(json, at: 1)
        _ = try remove.step()
    }

    public func remove(_ wake: PushV2Wake) throws {
        try self.database.withImmediateTransaction {
            try self.removeJSON(wake.referenceJSON)
        }
    }
}

public enum PushV2Error: Error {
    case format, binding, expired, hash, signature, replay, capacity
}

public enum PushV2DeliveryClaim: Equatable, Sendable {
    case ready(leaseUntilMs: Int64)
    case completed
    case deferred
}

public enum PushV2Verifier {
    static let maximumInteger: Int64 = 9_007_199_254_740_991

    static func decode(_ value: String, count: Int) throws -> Data {
        guard value.utf8.count <= 8192,
              !value.isEmpty,
              value.utf8.allSatisfy({
                  (65...90).contains($0) || (97...122).contains($0) ||
                      (48...57).contains($0) || $0 == 45 || $0 == 95
              }) else { throw PushV2Error.format }
        var padded = value.replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        padded += String(repeating: "=", count: (4 - padded.utf8.count % 4) % 4)
        guard let data = Data(base64Encoded: padded), data.count == count,
              self.base64(data).utf8.elementsEqual(value.utf8)
        else { throw PushV2Error.format }
        return data
    }

    static func base64(_ value: Data) -> String {
        value.base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
    }

    static func text(_ value: String, maximum: Int = 256) throws -> Data {
        guard !value.isEmpty, value.utf8.count <= maximum,
              value.utf8.elementsEqual(value.precomposedStringWithCanonicalMapping.utf8)
        else { throw PushV2Error.format }
        return Data(value.utf8)
    }

    /// Independent encoder, checked against a server-produced fixed signature vector.
    public static func signedMessage(_ e: PushV2Envelope) throws -> Data {
        guard e.algorithms == ["ed25519", "ml-dsa-65"] else { throw PushV2Error.format }
        var transcript = Data("OpenClaw-PQC/Push/V2\0".utf8)
        func uint(_ tag: UInt8, _ value: Int64) throws {
            guard value >= 0, value <= self.maximumInteger else { throw PushV2Error.format }
            transcript.append(tag)
            var encoded = UInt64(value).bigEndian
            withUnsafeBytes(of: &encoded) { transcript.append(contentsOf: $0) }
        }
        func bytes(_ tag: UInt8, _ value: Data) {
            transcript.append(tag)
            var size = UInt32(value.count).bigEndian
            withUnsafeBytes(of: &size) { transcript.append(contentsOf: $0) }
            transcript.append(value)
        }
        try uint(1, e.version)
        try bytes(2, self.text(e.algorithms[0]))
        try bytes(3, self.text(e.algorithms[1]))
        try bytes(4, self.text(e.sender_id))
        try bytes(5, self.text(e.recipient_id))
        try bytes(6, self.text(e.key_id_ed25519, maximum: 128))
        try bytes(7, self.text(e.key_id_mldsa65, maximum: 128))
        try uint(8, e.created_at_ms)
        try uint(9, e.sequence)
        try bytes(10, self.decode(e.nonce, count: 24))
        try bytes(11, self.text(e.payload_type, maximum: 128))
        try bytes(12, self.decode(e.payload_sha256, count: 32))
        return Data("openclaw-push-v2-binary:\(self.base64(transcript))".utf8)
    }

    /// Returns content only after both signatures and a durable replay commit succeed.
    public static func accept(
        _ object: PushV2Object,
        keys: PushV2TrustedKeys,
        expectedRecipientID: String,
        nowMs: Int64,
        replayStore: PushV2ReplayStore) throws -> String
    {
        let payload = try self.verify(object, keys: keys, expectedRecipientID: expectedRecipientID, nowMs: nowMs)
        try replayStore.accept(object.envelope, nowMs: nowMs)
        return payload
    }

    /// Persist verified work with replay acceptance before any asynchronous effect.
    public static func stageDelivery(
        _ object: PushV2Object,
        keys: PushV2TrustedKeys,
        expectedRecipientID: String,
        nowMs: Int64,
        referenceID: String,
        replayStore: PushV2ReplayStore) throws -> PushV2DeliveryClaim
    {
        _ = try self.verify(object, keys: keys, expectedRecipientID: expectedRecipientID, nowMs: nowMs)
        return try replayStore.stageDelivery(object, referenceID: referenceID, nowMs: nowMs)
    }

    private static func verify(
        _ object: PushV2Object,
        keys: PushV2TrustedKeys,
        expectedRecipientID: String,
        nowMs: Int64) throws -> String
    {
        let e = object.envelope
        guard object.payload.utf8.count <= 65536,
              try JSONEncoder().encode(e).count <= 16384,
              e.version == 2 else { throw PushV2Error.format }
        guard e.recipient_id.utf8.elementsEqual(expectedRecipientID.utf8),
              keys.recipientId.utf8.elementsEqual(expectedRecipientID.utf8),
              e.sender_id.utf8.elementsEqual(keys.senderId.utf8),
              e.key_id_ed25519.utf8.elementsEqual(keys.keyIdEd25519.utf8),
              e.key_id_mldsa65.utf8.elementsEqual(keys.keyIdMldsa65.utf8)
        else { throw PushV2Error.binding }
        guard nowMs >= 0, nowMs <= self.maximumInteger,
              e.created_at_ms >= 0, e.created_at_ms <= self.maximumInteger,
              e.created_at_ms <= nowMs + 30000, nowMs - e.created_at_ms <= 300_000
        else { throw PushV2Error.expired }
        guard try Data(SHA256.hash(data: Data(object.payload.utf8))) ==
            (self.decode(e.payload_sha256, count: 32)) else { throw PushV2Error.hash }
        let message = try self.signedMessage(e)
        let edKey = try Curve25519.Signing.PublicKey(
            rawRepresentation: self.decode(keys.ed25519PublicKeyBase64Url, count: 32))
        guard try edKey.isValidSignature(self.decode(e.ed25519_sig, count: 64), for: message),
              try MLDSA65Provider.portableVerify(
                  signature: self.decode(e.mldsa65_sig, count: 3309),
                  message: message,
                  publicKey: self.decode(keys.mldsa65PublicKeyBase64Url, count: 1952))
        else { throw PushV2Error.signature }
        return object.payload
    }
}

/// Shared SQLite transaction prevents replay after restart or in competing processes.
public final class PushV2ReplayStore: @unchecked Sendable {
    private let database: OpenClawNativeStateSQLite

    public init(databaseURL: URL) throws {
        self.database = try OpenClawNativeStateSQLite(databaseURL: databaseURL)
        try self.database.withImmediateTransaction {
            try self.database.ensureCanonicalTable(.pqcPushReplay)
            try self.database.ensureCanonicalTable(.pqcPushNonces)
            try self.database.ensureCanonicalTable(.pqcPushCompletions)
        }
    }

    public static func openDefault() throws -> PushV2ReplayStore {
        try PushV2ReplayStore(databaseURL: DeviceIdentityPaths.stateDirURL()
            .appendingPathComponent("state", isDirectory: true).appendingPathComponent("openclaw.sqlite"))
    }

    func accept(_ e: PushV2Envelope, nowMs: Int64) throws {
        try self.database.withImmediateTransaction {
            try self.acceptInTransaction(e, nowMs: nowMs)
        }
    }

    private func acceptInTransaction(_ e: PushV2Envelope, nowMs: Int64) throws {
        let prune = try self.database.prepare("DELETE FROM pqc_push_nonces WHERE expires_at_ms <= ?")
        try prune.bindInt64(nowMs, at: 1)
        _ = try prune.step()
        let previous = try self.database.prepare(
            "SELECT sequence FROM pqc_push_replay WHERE sender_id = ? AND recipient_id = ?")
        try previous.bindText(e.sender_id, at: 1)
        try previous.bindText(e.recipient_id, at: 2)
        let existing = try previous.step() == .row
        if existing, previous.int64(at: 0) >= e.sequence { throw PushV2Error.replay }
        let nonce = try self.database.prepare(
            "SELECT 1 FROM pqc_push_nonces WHERE sender_id = ? AND recipient_id = ? AND nonce = ?")
        try nonce.bindText(e.sender_id, at: 1)
        try nonce.bindText(e.recipient_id, at: 2)
        try nonce.bindText(e.nonce, at: 3)
        if try nonce.step() == .row { throw PushV2Error.replay }
        guard try (existing || self.database.scalarInt64("SELECT COUNT(*) FROM pqc_push_replay") < 10000),
              try self.database.scalarInt64("SELECT COUNT(*) FROM pqc_push_nonces") < 50000
        else { throw PushV2Error.capacity }
        let update = try self.database.prepare("""
        INSERT INTO pqc_push_replay(sender_id, recipient_id, sequence) VALUES (?, ?, ?)
        ON CONFLICT(sender_id, recipient_id) DO UPDATE SET sequence = excluded.sequence
        """)
        try update.bindText(e.sender_id, at: 1)
        try update.bindText(e.recipient_id, at: 2)
        try update.bindInt64(e.sequence, at: 3)
        _ = try update.step()
        let insert = try self.database.prepare(
            "INSERT INTO pqc_push_nonces(sender_id, recipient_id, nonce, expires_at_ms) VALUES (?, ?, ?, ?)")
        try insert.bindText(e.sender_id, at: 1)
        try insert.bindText(e.recipient_id, at: 2)
        try insert.bindText(e.nonce, at: 3)
        try insert.bindInt64(e.created_at_ms + 330_000, at: 4)
        _ = try insert.step()
    }

    private func transcriptHash(_ e: PushV2Envelope) throws -> String {
        try Data(SHA256.hash(data: PushV2Verifier.signedMessage(e)))
            .map { String(format: "%02x", $0) }.joined()
    }

    private func bindMessage(_ e: PushV2Envelope, to statement: OpenClawNativeStateSQLiteStatement) throws {
        try statement.bindText(e.sender_id, at: 1)
        try statement.bindText(e.recipient_id, at: 2)
        try statement.bindText(e.nonce, at: 3)
    }

    public func retainedDelivery(referenceID: String, recipientID: String) throws -> PushV2Object? {
        let read = try self.database.prepare("""
        SELECT result_json FROM pqc_push_completions WHERE recipient_id = ? AND reference_id = ?
        """)
        try read.bindText(recipientID, at: 1)
        try read.bindText(referenceID, at: 2)
        guard try read.step() == .row else { return nil }
        let json = try read.requiredText(at: 0, field: "verified push inbox")
        guard json.utf8.count <= 100_000 else { throw PushV2Error.format }
        return try JSONDecoder().decode(PushV2Object.self, from: Data(json.utf8))
    }

    fileprivate func stageDelivery(
        _ object: PushV2Object,
        referenceID: String,
        nowMs: Int64) throws -> PushV2DeliveryClaim
    {
        let e = object.envelope
        let hash = try self.transcriptHash(e)
        let encoded = try JSONEncoder().encode(object)
        guard UUID(uuidString: referenceID)?.uuidString.lowercased() == referenceID,
              nowMs <= PushV2Verifier.maximumInteger - 30000,
              e.created_at_ms <= PushV2Verifier.maximumInteger - 300_000,
              encoded.count <= 100_000,
              let json = String(data: encoded, encoding: .utf8)
        else { throw PushV2Error.format }
        let leaseUntilMs = nowMs + 30000
        return try self.database.withImmediateTransaction {
            let previous = try self.database.prepare("""
            SELECT transcript_hash, state, lease_until_ms, expires_at_ms FROM pqc_push_completions
            WHERE sender_id = ? AND recipient_id = ? AND nonce = ?
            """)
            try self.bindMessage(e, to: previous)
            if try previous.step() == .row {
                guard try previous.requiredText(at: 0, field: "push transcript hash") == hash,
                      previous.int64(at: 3) > nowMs else { throw PushV2Error.binding }
                let state = try previous.requiredText(at: 1, field: "push completion state")
                if state == "completed" { return .completed }
                guard state == "pending" else { throw PushV2Error.format }
                if previous.int64(at: 2) > nowMs { return .deferred }
                let claim = try self.database.prepare("""
                UPDATE pqc_push_completions SET lease_until_ms = ?
                WHERE sender_id = ? AND recipient_id = ? AND nonce = ?
                """)
                try claim.bindInt64(leaseUntilMs, at: 1)
                try claim.bindText(e.sender_id, at: 2)
                try claim.bindText(e.recipient_id, at: 3)
                try claim.bindText(e.nonce, at: 4)
                _ = try claim.step()
                return .ready(leaseUntilMs: leaseUntilMs)
            }
            let prune = try self.database.prepare("DELETE FROM pqc_push_completions WHERE expires_at_ms <= ?")
            try prune.bindInt64(nowMs, at: 1)
            _ = try prune.step()
            guard try self.database.scalarInt64("SELECT COUNT(*) FROM pqc_push_completions") < 50000
            else { throw PushV2Error.capacity }
            try self.acceptInTransaction(e, nowMs: nowMs)
            let insert = try self.database.prepare("""
            INSERT INTO pqc_push_completions(sender_id,recipient_id,nonce,transcript_hash,result_json,expires_at_ms,state,lease_until_ms,reference_id)
            VALUES (?,?,?,?,?,?,'pending',?,?)
            """)
            try self.bindMessage(e, to: insert)
            try insert.bindText(hash, at: 4)
            try insert.bindText(json, at: 5)
            try insert.bindInt64(e.created_at_ms + 300_000, at: 6)
            try insert.bindInt64(leaseUntilMs, at: 7)
            try insert.bindText(referenceID, at: 8)
            _ = try insert.step()
            return .ready(leaseUntilMs: leaseUntilMs)
        }
    }

    /// Complete only the lease that performed the effect; a stale callback cannot steal a newer lease.
    public func completeDelivery(_ e: PushV2Envelope, leaseUntilMs: Int64) throws {
        try self.updateDelivery(e, leaseUntilMs: leaseUntilMs, completed: true)
    }

    public func releaseDelivery(_ e: PushV2Envelope, leaseUntilMs: Int64) throws {
        try self.updateDelivery(e, leaseUntilMs: leaseUntilMs, completed: false)
    }

    private func updateDelivery(_ e: PushV2Envelope, leaseUntilMs: Int64, completed: Bool) throws {
        let hash = try self.transcriptHash(e)
        try self.database.withImmediateTransaction {
            let update = try self.database.prepare("""
            UPDATE pqc_push_completions SET state = ?, lease_until_ms = 0
            WHERE sender_id = ? AND recipient_id = ? AND nonce = ?
              AND transcript_hash = ? AND state = 'pending' AND lease_until_ms = ?
            """)
            try update.bindText(completed ? "completed" : "pending", at: 1)
            try update.bindText(e.sender_id, at: 2)
            try update.bindText(e.recipient_id, at: 3)
            try update.bindText(e.nonce, at: 4)
            try update.bindText(hash, at: 5)
            try update.bindInt64(leaseUntilMs, at: 6)
            _ = try update.step()
            guard self.database.changes == 1 else { throw PushV2Error.binding }
        }
    }
}
