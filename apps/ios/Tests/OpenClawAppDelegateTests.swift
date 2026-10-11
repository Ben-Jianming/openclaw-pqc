import Foundation
import OpenClawKit
import Testing
import UIKit
@testable import OpenClaw

@Suite(.serialized) struct OpenClawAppDelegateTests {
    @Test @MainActor func `resolves registry model before view task assigns delegate model`() {
        let registryModel = NodeAppModel()
        OpenClawAppModelRegistry.appModel = registryModel
        defer { OpenClawAppModelRegistry.appModel = nil }

        let delegate = OpenClawAppDelegate()

        #expect(delegate._test_resolvedAppModel() === registryModel)
    }

    @Test @MainActor func `prefers explicit delegate model over registry fallback`() {
        let registryModel = NodeAppModel()
        let explicitModel = NodeAppModel()
        OpenClawAppModelRegistry.appModel = registryModel
        defer { OpenClawAppModelRegistry.appModel = nil }

        let delegate = OpenClawAppDelegate()
        delegate.appModel = explicitModel

        #expect(delegate._test_resolvedAppModel() === explicitModel)
    }

    @Test @MainActor func `derives background refresh task identifier from app bundle identifier`() {
        let delegate = OpenClawAppDelegate()
        let bundleIdentifier = Bundle.main.bundleIdentifier ?? "ai.openclawfoundation.app.tests"

        #expect(delegate._test_wakeRefreshTaskIdentifier() == "\(bundleIdentifier).bgrefresh")
    }

    @Test @MainActor func `stages a gateway URL when the model is ready`() async throws {
        OpenClawAppModelRegistry.appModel = nil
        defer { OpenClawAppModelRegistry.appModel = nil }
        let model = NodeAppModel()
        let delegate = OpenClawAppDelegate()
        delegate.appModel = model
        let url = try #require(URL(
            string: "openclaw://gateway?host=gateway.example.com&port=443&tls=1&token=tok"))

        #expect(delegate.application(UIApplication.shared, open: url))
        let link = await Self.waitForGatewaySetup(in: model)

        #expect(link?.host == "gateway.example.com")
        #expect(link?.port == 443)
        #expect(link?.tls == true)
        #expect(link?.token == "tok")
    }

    @Test @MainActor func `replays a gateway URL received before the model is ready`() async throws {
        OpenClawAppModelRegistry.appModel = nil
        defer { OpenClawAppModelRegistry.appModel = nil }
        let delegate = OpenClawAppDelegate()
        let url = try #require(URL(
            string: "openclaw://gateway?host=gateway.example.com&port=443&tls=1&token=tok"))

        #expect(delegate.application(UIApplication.shared, open: url))

        let model = NodeAppModel()
        delegate.appModel = model
        let link = await Self.waitForGatewaySetup(in: model)

        #expect(link?.host == "gateway.example.com")
        #expect(link?.token == "tok")
    }

    @Test @MainActor func `queues an opaque cold startup push instead of dropping it`() async throws {
        OpenClawAppModelRegistry.appModel = nil
        defer { OpenClawAppModelRegistry.appModel = nil }
        let delegate = OpenClawAppDelegate()
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        let databaseURL = directory.appendingPathComponent("openclaw.sqlite")
        try delegate._test_usePqcWakeQueue(databaseURL: databaseURL)
        let nowMs = Int64(Date().timeIntervalSince1970 * 1000)
        let userInfo: [AnyHashable: Any] = [
            "kind": "openclaw.pqc.wake.v2",
            "pqc_ref": [
                "version": 1,
                "object_id": "00000000-0000-4000-8000-000000000001",
                "token": Data(repeating: 1, count: 32).base64EncodedString()
                    .replacingOccurrences(of: "+", with: "-")
                    .replacingOccurrences(of: "/", with: "_")
                    .replacingOccurrences(of: "=", with: ""),
                "expires_at_ms": nowMs + 10000,
            ],
            "title": "unverified content", "approvalId": "unverified route",
        ]
        let result: UIBackgroundFetchResult = await withCheckedContinuation { continuation in
            delegate.application(UIApplication.shared, didReceiveRemoteNotification: userInfo) {
                continuation.resume(returning: $0)
            }
        }
        #expect(result == .newData)
        // A new delegate reconstructs the SQLite queue, simulating process loss before retry.
        let relaunched = OpenClawAppDelegate()
        try relaunched._test_usePqcWakeQueue(databaseURL: databaseURL)
        let wakes = try relaunched._test_takeQueuedPqcPushWakes(nowMs: nowMs)
        #expect(wakes.count == 1)
        #expect(wakes.first?.userInfo["title"] == nil)
        #expect(wakes.first?.userInfo["approvalId"] == nil)
        #expect(try delegate._test_takeQueuedPqcPushWakes(nowMs: nowMs).isEmpty)
    }

    @Test @MainActor func `does not queue raw remote content before model initialization`() async throws {
        OpenClawAppModelRegistry.appModel = nil
        defer { OpenClawAppModelRegistry.appModel = nil }
        let delegate = OpenClawAppDelegate()
        let directory = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
        defer { try? FileManager.default.removeItem(at: directory) }
        try delegate._test_usePqcWakeQueue(databaseURL: directory.appendingPathComponent("openclaw.sqlite"))
        let result: UIBackgroundFetchResult = await withCheckedContinuation { continuation in
            delegate.application(UIApplication.shared, didReceiveRemoteNotification: ["title": "injected"]) {
                continuation.resume(returning: $0)
            }
        }
        #expect(result == .noData)
        #expect(try delegate._test_takeQueuedPqcPushWakes(nowMs: 0).isEmpty)
    }

    @Test @MainActor func `rejects an invalid URL`() throws {
        let delegate = OpenClawAppDelegate()
        let url = try #require(URL(string: "https://example.com/gateway"))

        #expect(!delegate.application(UIApplication.shared, open: url))
    }

    @MainActor
    private static func waitForGatewaySetup(in model: NodeAppModel) async -> GatewayConnectDeepLink? {
        for _ in 0..<20 {
            if model.gatewaySetupRequestID > 0 {
                return model.consumePendingGatewaySetupLink()
            }
            await Task.yield()
        }
        return nil
    }
}
