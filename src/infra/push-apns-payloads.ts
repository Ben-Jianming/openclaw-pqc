// Builds portable APNs payloads for alerts, wakes, and approval lifecycle events.

function toPushMetadata(params: {
  kind: "push.test" | "node.wake";
  nodeId: string;
  reason?: string;
}): { kind: "push.test" | "node.wake"; nodeId: string; ts: number; reason?: string } {
  return {
    kind: params.kind,
    nodeId: params.nodeId,
    ts: Date.now(),
    ...(params.reason ? { reason: params.reason } : {}),
  };
}

export function createApnsAlertPayload(params: {
  nodeId: string;
  title: string;
  body: string;
}): object {
  return {
    aps: {
      alert: {
        title: params.title,
        body: params.body,
      },
      sound: "default",
    },
    openclaw: toPushMetadata({
      kind: "push.test",
      nodeId: params.nodeId,
    }),
  };
}

export function createApnsBackgroundPayload(params: {
  nodeId: string;
  wakeReason?: string;
}): object {
  return {
    aps: {
      "content-available": 1,
    },
    openclaw: toPushMetadata({
      kind: "node.wake",
      reason: params.wakeReason ?? "node.invoke",
      nodeId: params.nodeId,
    }),
  };
}

/** Opaque approval wake; canonical title/body are fetched over the authenticated gateway. */
export function createApnsApprovalWakePayload(params: {
  kind: "exec" | "plugin";
  approvalId: string;
  gatewayDeviceId: string;
}): object {
  return {
    aps: { "content-available": 1 },
    openclaw: {
      kind: `${params.kind}.approval.requested`,
      approvalId: params.approvalId,
      gatewayDeviceId: params.gatewayDeviceId,
      ts: Date.now(),
    },
  };
}

export function createApnsApprovalResolvedPayload(params: {
  kind: "exec" | "plugin";
  approvalId: string;
  gatewayDeviceId: string;
}): object {
  return {
    aps: {
      "content-available": 1,
    },
    openclaw: {
      kind: `${params.kind}.approval.resolved`,
      approvalId: params.approvalId,
      gatewayDeviceId: params.gatewayDeviceId,
      ts: Date.now(),
    },
  };
}
