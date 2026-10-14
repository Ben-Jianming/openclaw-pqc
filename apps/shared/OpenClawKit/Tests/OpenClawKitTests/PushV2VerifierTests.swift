import CryptoKit
import Foundation
import OpenClawNativeState
import Testing
@testable import OpenClawKit

struct PushV2VerifierTests {
    private struct Fixture: Codable {
        var object: PushV2Object
        var keys: PushV2TrustedKeys
        var signedMessage: String
        var nowMs: Int64
    }

    private func fixture() throws -> Fixture {
        var root = URL(fileURLWithPath: #filePath)
        for _ in 0..<6 {
            root.deleteLastPathComponent()
        }
        return try JSONDecoder().decode(
            Fixture.self,
            from: Data(contentsOf: root
                .appendingPathComponent("test/fixtures/pqc/push-v2.json")))
    }

    private func withDatabase(_ body: (URL) throws -> Void) throws {
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        try body(directory.appendingPathComponent("openclaw.sqlite"))
    }

    private func wake(_ id: String, expiresAtMs: Int64 = 2000) throws -> PushV2Wake {
        try #require(PushV2Wake(userInfo: [
            "kind": "openclaw.pqc.wake.v2",
            "pqc_ref": [
                "version": 1,
                "object_id": id,
                "token": PushV2Verifier.base64(Data(repeating: 1, count: 32)),
                "expires_at_ms": expiresAtMs,
            ],
            "title": "untrusted relay text", "approvalId": "untrusted route",
        ], nowMs: 1000))
    }

    @Test func `startup wakes keep only opaque capabilities`() throws {
        let wake = try self.wake("00000000-0000-4000-8000-000000000001")
        #expect(wake.userInfo.count == 2)
        #expect(wake.userInfo["title"] == nil)
        #expect(wake.userInfo["approvalId"] == nil)
        #expect(PushV2Wake(userInfo: wake.userInfo, nowMs: 2000) == nil)
        let farFuture = try self.wake("00000000-0000-4000-8000-000000000001", expiresAtMs: 331_000)
        #expect(PushV2Wake(userInfo: farFuture.userInfo, nowMs: 999) == nil)
    }

    @Test func `provider acknowledgement flag cannot turn a wake read into deletion`() throws {
        let original = try self.wake("00000000-0000-4000-8000-000000000001")
        var poisoned = original.userInfo
        var reference = try #require(poisoned["pqc_ref"] as? [String: Any])
        reference["acknowledge"] = true
        reference["recipient_id"] = "untrusted route"
        poisoned["pqc_ref"] = reference
        let sanitized = try #require(PushV2Wake(userInfo: poisoned, nowMs: 1000))
        let readRequest = try #require(JSONSerialization.jsonObject(
            with: Data(sanitized.referenceJSON.utf8)) as? [String: Any])
        #expect(Set(readRequest.keys) == ["version", "object_id", "token", "expires_at_ms"])
        #expect(readRequest["acknowledge"] == nil)
        #expect(readRequest["recipient_id"] == nil)
        #expect(sanitized.referenceJSON == original.referenceJSON)
    }

    @Test func `cold start wake survives reopen and concurrent callbacks share capacity`() throws {
        try self.withDatabase { url in
            let first = try self.wake("00000000-0000-4000-8000-000000000001")
            let second = try self.wake("00000000-0000-4000-8000-000000000002")
            do {
                let queue = try PushV2WakeQueue(databaseURL: url, capacity: 1)
                #expect(try queue.enqueue(first, nowMs: 1000))
                #expect(try queue.enqueue(first, nowMs: 1000))
            }
            let reopened = try PushV2WakeQueue(databaseURL: url, capacity: 1)
            let concurrent = try PushV2WakeQueue(databaseURL: url, capacity: 1)
            #expect(try reopened.ready(nowMs: 1001).map(\.referenceJSON) == [first.referenceJSON])
            #expect(try concurrent.enqueue(first, nowMs: 1001))
            #expect(try !concurrent.enqueue(second, nowMs: 1001))
            #expect(try reopened.ready(nowMs: 1002).count == 1)
            try concurrent.remove(first)
            #expect(try reopened.ready(nowMs: 1002).isEmpty)
        }
    }

    @Test func `expired durable wakes release queue capacity`() throws {
        try self.withDatabase { url in
            let queue = try PushV2WakeQueue(databaseURL: url, capacity: 1)
            let expired = try self.wake("00000000-0000-4000-8000-000000000001")
            let fresh = try self.wake("00000000-0000-4000-8000-000000000002", expiresAtMs: 3000)
            #expect(try queue.enqueue(expired, nowMs: 1000))
            #expect(try queue.enqueue(fresh, nowMs: 2000))
            #expect(try queue.ready(nowMs: 2001).map(\.referenceJSON) == [fresh.referenceJSON])
            #expect(try !queue.enqueue(expired, nowMs: 2001))
        }
    }

    @Test func `corrupt durable reference cannot be routed and is pruned`() throws {
        try self.withDatabase { url in
            let queue = try PushV2WakeQueue(databaseURL: url)
            let database = try OpenClawNativeStateSQLite(databaseURL: url)
            try database.execute("INSERT INTO pqc_push_wakes VALUES ('{\"title\":\"unverified\"}', 2000)")
            #expect(try queue.ready(nowMs: 1000).isEmpty)
            #expect(try database.scalarInt64("SELECT COUNT(*) FROM pqc_push_wakes") == 0)
        }
    }

    @Test func `server vector and restart replay`() throws {
        let f = try self.fixture()
        #expect(try PushV2Verifier.signedMessage(f.object.envelope) == Data(f.signedMessage.utf8))
        try self.withDatabase { url in
            do {
                let store = try PushV2ReplayStore(databaseURL: url)
                #expect(try PushV2Verifier.accept(
                    f.object,
                    keys: f.keys,
                    expectedRecipientID: "alice",
                    nowMs: f.nowMs,
                    replayStore: store) == f.object.payload)
            }
            let reopened = try PushV2ReplayStore(databaseURL: url)
            #expect(throws: PushV2Error.self) {
                try PushV2Verifier.accept(
                    f.object,
                    keys: f.keys,
                    expectedRecipientID: "alice",
                    nowMs: f.nowMs,
                    replayStore: reopened)
            }
        }
    }

    @Test func `pending delivery survives reopen and a lost acknowledgement`() throws {
        let f = try self.fixture()
        let referenceID = "00000000-0000-4000-8000-000000000001"
        try self.withDatabase { url in
            do {
                let store = try PushV2ReplayStore(databaseURL: url)
                #expect(try PushV2Verifier.stageDelivery(
                    f.object, keys: f.keys, expectedRecipientID: "alice", nowMs: f.nowMs,
                    referenceID: referenceID, replayStore: store) == .ready(leaseUntilMs: f.nowMs + 30000))
            }
            let reopened = try PushV2ReplayStore(databaseURL: url)
            #expect(try reopened.retainedDelivery(referenceID: referenceID, recipientID: "alice")?.payload ==
                f.object.payload)
            #expect(try reopened.retainedDelivery(referenceID: referenceID, recipientID: "bob") == nil)
            #expect(try PushV2Verifier.stageDelivery(
                f.object, keys: f.keys, expectedRecipientID: "alice", nowMs: f.nowMs + 1,
                referenceID: referenceID, replayStore: reopened) == .deferred)
            // A killed presenter loses its lease, not its verified inbox.
            let retryTime = f.nowMs + 30001
            let retryLease = retryTime + 30000
            #expect(try PushV2Verifier.stageDelivery(
                f.object, keys: f.keys, expectedRecipientID: "alice", nowMs: retryTime,
                referenceID: referenceID, replayStore: reopened) == .ready(leaseUntilMs: retryLease))
            #expect(throws: PushV2Error.self) {
                try reopened.completeDelivery(f.object.envelope, leaseUntilMs: f.nowMs + 30000)
            }
            try reopened.completeDelivery(f.object.envelope, leaseUntilMs: retryLease)
            let afterCompletion = try PushV2ReplayStore(databaseURL: url)
            #expect(try PushV2Verifier.stageDelivery(
                f.object, keys: f.keys, expectedRecipientID: "alice", nowMs: retryTime + 1,
                referenceID: referenceID, replayStore: afterCompletion) == .completed)
            var wrongKeys = f.keys
            wrongKeys.keyIdMldsa65 = "changed-current-key"
            #expect(throws: PushV2Error.self) {
                try PushV2Verifier.stageDelivery(
                    f.object, keys: wrongKeys, expectedRecipientID: "alice", nowMs: retryTime + 1,
                    referenceID: referenceID, replayStore: afterCompletion)
            }
        }
    }

    @Test func `presentation failure releases the owned delivery lease`() throws {
        let f = try self.fixture()
        let referenceID = "00000000-0000-4000-8000-000000000001"
        try self.withDatabase { url in
            let store = try PushV2ReplayStore(databaseURL: url)
            let lease = f.nowMs + 30000
            #expect(try PushV2Verifier.stageDelivery(
                f.object, keys: f.keys, expectedRecipientID: "alice", nowMs: f.nowMs,
                referenceID: referenceID, replayStore: store) == .ready(leaseUntilMs: lease))
            try store.releaseDelivery(f.object.envelope, leaseUntilMs: lease)
            #expect(try PushV2Verifier.stageDelivery(
                f.object, keys: f.keys, expectedRecipientID: "alice", nowMs: f.nowMs + 1,
                referenceID: referenceID, replayStore: store) == .ready(leaseUntilMs: lease + 1))
            #expect(throws: PushV2Error.self) {
                try store.releaseDelivery(f.object.envelope, leaseUntilMs: lease)
            }
            #expect(throws: PushV2Error.self) {
                try PushV2Verifier.stageDelivery(
                    f.object, keys: f.keys, expectedRecipientID: "bob", nowMs: f.nowMs + 1,
                    referenceID: referenceID, replayStore: store)
            }
        }
    }

    @Test func `tampering does not burn valid state`() throws {
        let f = try self.fixture()
        try self.withDatabase { url in
            let store = try PushV2ReplayStore(databaseURL: url)
            var bad = f.object
            bad.payload += "tampered"
            #expect(throws: PushV2Error.self) {
                try PushV2Verifier.accept(
                    bad,
                    keys: f.keys,
                    expectedRecipientID: "alice",
                    nowMs: f.nowMs,
                    replayStore: store)
            }
            #expect(throws: PushV2Error.self) {
                try PushV2Verifier.accept(
                    f.object,
                    keys: f.keys,
                    expectedRecipientID: "bob",
                    nowMs: f.nowMs,
                    replayStore: store)
            }
            #expect(throws: PushV2Error.self) {
                try PushV2Verifier.accept(
                    f.object,
                    keys: f.keys,
                    expectedRecipientID: "alice",
                    nowMs: f.nowMs + 300_001,
                    replayStore: store)
            }
            bad = f.object
            bad.envelope.mldsa65_sig = String(repeating: "A", count: bad.envelope.mldsa65_sig.count)
            #expect(throws: PushV2Error.self) {
                try PushV2Verifier.accept(
                    bad,
                    keys: f.keys,
                    expectedRecipientID: "alice",
                    nowMs: f.nowMs,
                    replayStore: store)
            }
            #expect(try PushV2Verifier.accept(
                f.object,
                keys: f.keys,
                expectedRecipientID: "alice",
                nowMs: f.nowMs,
                replayStore: store) == f.object.payload)
        }
    }

    @Test func `non canonical unicode and integer are rejected`() throws {
        var e = try self.fixture().object.envelope
        e.sender_id = "e\u{301}"
        #expect(throws: PushV2Error.self) { try PushV2Verifier.signedMessage(e) }
        e.sender_id = "gateway"
        e.sequence = 9_007_199_254_740_992
        #expect(throws: PushV2Error.self) { try PushV2Verifier.signedMessage(e) }
    }

    @Test func `native signatures can be exported for server verification`() throws {
        let f = try self.fixture()
        let ed = Curve25519.Signing.PrivateKey()
        let seed = Data(repeating: 7, count: MLDSA65Provider.seedByteCount)
        let mlPublic = try MLDSA65Provider.portablePublicKey(seed: seed)
        var object = f.object
        object.payload = "{\"body\":\"Swift ↔ Node 验签\"}"
        object.envelope.sender_id = "swift-generator"
        object.envelope.key_id_ed25519 = "swift-ed"
        object.envelope.key_id_mldsa65 = "swift-ml"
        object.envelope.payload_sha256 = PushV2Verifier.base64(Data(SHA256.hash(data: Data(object.payload.utf8))))
        let message = try PushV2Verifier.signedMessage(object.envelope)
        object.envelope.ed25519_sig = try PushV2Verifier.base64(ed.signature(for: message))
        object.envelope.mldsa65_sig = try PushV2Verifier.base64(MLDSA65Provider.portableSign(
            message: message,
            seed: seed))
        let keys = PushV2TrustedKeys(
            senderId: object.envelope.sender_id,
            recipientId: "alice",
            keyIdEd25519: "swift-ed",
            keyIdMldsa65: "swift-ml",
            ed25519PublicKeyBase64Url: PushV2Verifier.base64(ed.publicKey.rawRepresentation),
            mldsa65PublicKeyBase64Url: PushV2Verifier.base64(mlPublic))
        try self.withDatabase { url in
            let store = try PushV2ReplayStore(databaseURL: url)
            #expect(try PushV2Verifier.accept(
                object,
                keys: keys,
                expectedRecipientID: "alice",
                nowMs: f.nowMs,
                replayStore: store) == object.payload)
        }
        if let output = ProcessInfo.processInfo.environment["PQC_PUSH_INTEROP_OUTPUT"] {
            let result = Fixture(
                object: object,
                keys: keys,
                signedMessage: String(decoding: message, as: UTF8.self),
                nowMs: f.nowMs)
            // Public material only; native private keys never leave this test.
            try JSONEncoder().encode(result).write(to: URL(fileURLWithPath: output), options: .atomic)
        }
    }
}
