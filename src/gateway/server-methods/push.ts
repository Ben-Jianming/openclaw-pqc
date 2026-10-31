// Push gateway methods send APNs/web-push test notifications and manage web
// push subscriptions/VAPID public-key access for UI clients.
import { normalizeStringifiedOptionalString } from "@openclaw/normalization-core/string-coerce";
import {
  ErrorCodes,
  errorShape,
  validatePushTestParams,
  validatePushPqcKeysParams,
  validatePushPqcRedeemParams,
  validateWebPushSubscribeParams,
  validateWebPushTestParams,
  validateWebPushUnsubscribeParams,
  validateWebPushVapidPublicKeyParams,
} from "../../../packages/gateway-protocol/src/index.js";
import { allowPushRedemption, SqlitePushReferenceStore } from "../../infra/pqc-push-state.js";
import {
  clearApnsRegistrationIfCurrent,
  loadApnsRegistration,
  normalizeApnsEnvironment,
  resolveApnsAuthConfigFromEnv,
  resolveApnsRelayConfigFromEnv,
  sendApnsAlert,
  shouldClearStoredApnsRegistration,
} from "../../infra/push-apns.js";
import { getPushEnvelopeVerificationKeys } from "../../infra/push-envelope.js";
import {
  broadcastWebPush,
  clearWebPushSubscriptionByEndpoint,
  registerWebPushSubscription,
  resolveVapidKeys,
} from "../../infra/push-web.js";
import { PUSH_KEY_POLICY_CAPABILITY } from "../../shared/push-key-policy.js";
import { respondInvalidParams, respondUnavailableOnThrow } from "./nodes.helpers.js";
import { resolveDispatchableNodeSession } from "./nodes.shared.js";
import { normalizeTrimmedString } from "./record-shared.js";
import type { GatewayRequestHandlers, GatewayRequestHandlerOptions } from "./types.js";

function requirePushKeyPolicyClient({
  client,
  respond,
}: Pick<GatewayRequestHandlerOptions, "client" | "respond">): boolean {
  if (client?.connect.caps?.includes(PUSH_KEY_POLICY_CAPABILITY)) {
    return true;
  }
  // Old/native clients must not redeem signed content while ignoring lifecycle metadata.
  // Node aliases delegate here too; non-push methods and unsubscribe remain available.
  respond(
    false,
    undefined,
    errorShape(ErrorCodes.INVALID_REQUEST, "upgrade required for secure push key policy", {
      details: {
        code: "PUSH_KEY_POLICY_CAPABILITY_REQUIRED",
        requiredCapability: PUSH_KEY_POLICY_CAPABILITY,
      },
    }),
  );
  return false;
}

export const pushHandlers: GatewayRequestHandlers = {
  "push.pqc.keys": ({ params, client, respond }) => {
    const recipientId = client?.connect.device?.id;
    if (!recipientId || !validatePushPqcKeysParams(params)) {
      respond(
        false,
        undefined,
        errorShape(ErrorCodes.INVALID_REQUEST, "authenticated device and empty params required"),
      );
      return;
    }
    if (!requirePushKeyPolicyClient({ client, respond })) {
      return;
    }
    try {
      respond(true, { ...getPushEnvelopeVerificationKeys(), recipientId }, undefined);
    } catch {
      respond(
        false,
        undefined,
        errorShape(ErrorCodes.UNAVAILABLE, "push verification keys unavailable"),
      );
    }
  },
  "push.pqc.redeem": ({ params, client, respond }) => {
    const recipientId = client?.connect.device?.id;
    if (!recipientId || !validatePushPqcRedeemParams(params)) {
      respond(
        false,
        undefined,
        errorShape(ErrorCodes.INVALID_REQUEST, "authenticated device and valid reference required"),
      );
      return;
    }
    if (!requirePushKeyPolicyClient({ client, respond })) {
      return;
    }
    try {
      const operation = params.acknowledge === true ? "acknowledge" : "read";
      if (!allowPushRedemption(recipientId, {}, Date.now(), operation)) {
        throw new Error("rate limit");
      }
      const store = new SqlitePushReferenceStore();
      if (params.acknowledge === true) {
        store.acknowledge(params, recipientId);
        respond(true, { acknowledged: true }, undefined);
      } else {
        respond(true, store.redeem(params, recipientId), undefined);
      }
    } catch {
      // Never log the capability, payload or a distinguishable binding failure.
      respond(false, undefined, errorShape(ErrorCodes.UNAVAILABLE, "push reference unavailable"));
    }
  },
  "push.test": async ({ params, respond, context }) => {
    if (!validatePushTestParams(params)) {
      respondInvalidParams({
        respond,
        method: "push.test",
        validator: validatePushTestParams,
      });
      return;
    }

    const nodeId = normalizeStringifiedOptionalString(params.nodeId) ?? "";
    if (!nodeId) {
      respond(false, undefined, errorShape(ErrorCodes.INVALID_REQUEST, "nodeId required"));
      return;
    }

    const title = normalizeTrimmedString(params.title) ?? "OpenClaw";
    const body = normalizeTrimmedString(params.body) ?? `Push test for node ${nodeId}`;

    await respondUnavailableOnThrow(respond, async () => {
      const registration = await loadApnsRegistration(nodeId);
      if (!registration) {
        respond(
          false,
          undefined,
          errorShape(
            ErrorCodes.INVALID_REQUEST,
            `node ${nodeId} has no APNs registration (connect iOS node first)`,
          ),
        );
        return;
      }

      const overrideEnvironment = normalizeApnsEnvironment(params.environment);
      const result =
        registration.transport === "direct"
          ? await (async () => {
              // Direct registrations require local APNs signing material at
              // send time; relay registrations must not touch those secrets.
              const auth = await resolveApnsAuthConfigFromEnv(process.env);
              if (!auth.ok) {
                respond(false, undefined, errorShape(ErrorCodes.INVALID_REQUEST, auth.error));
                return null;
              }
              return await sendApnsAlert({
                registration: {
                  ...registration,
                  environment: overrideEnvironment ?? registration.environment,
                },
                nodeId,
                title,
                body,
                auth: auth.value,
              });
            })()
          : await (async () => {
              // Relay registrations carry a grant from the node, so the gateway
              // only needs relay config plus the origin bound at registration.
              const relay = resolveApnsRelayConfigFromEnv(
                process.env,
                context.getRuntimeConfig().gateway,
                { registrationRelayOrigin: registration.relayOrigin },
              );
              if (!relay.ok) {
                respond(false, undefined, errorShape(ErrorCodes.INVALID_REQUEST, relay.error));
                return null;
              }
              return await sendApnsAlert({
                registration,
                nodeId,
                title,
                body,
                relayConfig: relay.value,
              });
            })();
      if (!result) {
        return;
      }
      if (
        shouldClearStoredApnsRegistration({
          registration,
          result,
          overrideEnvironment,
        })
      ) {
        // Clear only the exact registration we tested; a reconnect may have
        // written a newer token while the push request was in flight.
        await clearApnsRegistrationIfCurrent({
          nodeId,
          registration,
        });
      }
      respond(true, result, undefined);
    });
  },

  "push.web.vapidPublicKey": async ({ params, respond }) => {
    if (!validateWebPushVapidPublicKeyParams(params)) {
      respondInvalidParams({
        respond,
        method: "push.web.vapidPublicKey",
        validator: validateWebPushVapidPublicKeyParams,
      });
      return;
    }

    await respondUnavailableOnThrow(respond, async () => {
      const vapid = await resolveVapidKeys();
      respond(true, { vapidPublicKey: vapid.publicKey }, undefined);
    });
  },

  "push.web.subscribe": async ({ params, client, respond }) => {
    if (!validateWebPushSubscribeParams(params)) {
      respondInvalidParams({
        respond,
        method: "push.web.subscribe",
        validator: validateWebPushSubscribeParams,
      });
      return;
    }

    const deviceId = client?.connect.device?.id;
    if (!deviceId) {
      respond(
        false,
        undefined,
        errorShape(ErrorCodes.INVALID_REQUEST, "authenticated device required"),
      );
      return;
    }

    await respondUnavailableOnThrow(respond, async () => {
      if (!requirePushKeyPolicyClient({ client, respond })) {
        return;
      }
      const subscription = await registerWebPushSubscription({
        endpoint: params.endpoint,
        keys: params.keys,
        deviceId,
      });
      respond(true, { subscriptionId: subscription.subscriptionId }, undefined);
    });
  },

  "push.web.unsubscribe": async ({ params, client, respond }) => {
    if (!validateWebPushUnsubscribeParams(params)) {
      respondInvalidParams({
        respond,
        method: "push.web.unsubscribe",
        validator: validateWebPushUnsubscribeParams,
      });
      return;
    }

    const deviceId = client?.connect.device?.id;
    if (!deviceId) {
      respond(
        false,
        undefined,
        errorShape(ErrorCodes.INVALID_REQUEST, "authenticated device required"),
      );
      return;
    }
    await respondUnavailableOnThrow(respond, async () => {
      const removed = await clearWebPushSubscriptionByEndpoint(
        params.endpoint,
        undefined,
        deviceId,
      );
      respond(true, { removed }, undefined);
    });
  },

  "push.web.test": async ({ params, respond }) => {
    if (!validateWebPushTestParams(params)) {
      respondInvalidParams({
        respond,
        method: "push.web.test",
        validator: validateWebPushTestParams,
      });
      return;
    }

    const title = normalizeTrimmedString(params.title) ?? "OpenClaw";
    const body = normalizeTrimmedString(params.body) ?? "Web push test notification";

    await respondUnavailableOnThrow(respond, async () => {
      const results = await broadcastWebPush({ title, body });
      if (results.length === 0) {
        respond(
          false,
          undefined,
          errorShape(ErrorCodes.INVALID_REQUEST, "no web push subscriptions registered"),
        );
        return;
      }
      respond(true, { results }, undefined);
    });
  },
};

// Preserve separate node/operator role policies while sharing the same recipient checks.
for (const method of ["keys", "redeem"] as const) {
  pushHandlers[`node.push.pqc.${method}`] = async (options) => {
    const { client, context, respond } = options;
    const nodeId = client?.connect.device?.id;
    const connId = client?.connId;
    const generation = nodeId ? context.nodeRegistry.get(nodeId)?.pairingGeneration : undefined;
    const current = () =>
      nodeId && generation
        ? resolveDispatchableNodeSession(
            context.nodeRegistry.getForPairingGeneration(nodeId, generation),
          )
        : undefined;
    if (
      !connId ||
      current()?.connId !== connId ||
      !(await context.nodeRegistry.isConnectionCurrentPairingState(connId)) ||
      current()?.connId !== connId
    ) {
      respond(false, undefined, errorShape(ErrorCodes.UNAVAILABLE, "push session unavailable"));
      return;
    }
    await pushHandlers[`push.pqc.${method}`]!(options);
  };
}
