// Gateway Protocol schema module defines protocol validation shapes.
import type { Static } from "typebox";
import { Type } from "typebox";
import { closedObject } from "./closed-object.js";
import { NonEmptyString } from "./primitives.js";

/**
 * Push-notification protocol schemas.
 *
 * APNS test schemas exercise native push routing; Web Push schemas describe the
 * browser subscription lifecycle exposed by the gateway.
 */
const ApnsEnvironmentSchema = Type.String({ enum: ["sandbox", "production"] });

/** Request payload for sending a test APNS notification to one node. */
export const PushTestParamsSchema = closedObject({
  nodeId: NonEmptyString,
  title: Type.Optional(Type.String()),
  body: Type.Optional(Type.String()),
  environment: Type.Optional(ApnsEnvironmentSchema),
});

/** Result payload from an APNS push test, including provider status and transport. */
export const PushTestResultSchema = closedObject({
  ok: Type.Boolean(),
  status: Type.Integer(),
  apnsId: Type.Optional(Type.String()),
  reason: Type.Optional(Type.String()),
  tokenSuffix: Type.String(),
  topic: Type.String(),
  environment: ApnsEnvironmentSchema,
  transport: Type.String({ enum: ["direct", "relay"] }),
});

// --- Web Push schemas ---

const WebPushKeysSchema = closedObject({
  p256dh: Type.String({ minLength: 1, maxLength: 512 }),
  auth: Type.String({ minLength: 1, maxLength: 512 }),
});

/** Empty request payload for fetching the Web Push VAPID public key. */
export const WebPushVapidPublicKeyParamsSchema = closedObject({});

/** Browser Web Push subscription payload registered with the gateway. */
export const WebPushSubscribeParamsSchema = closedObject({
  endpoint: Type.String({ minLength: 1, maxLength: 2048, pattern: "^https://" }),
  keys: WebPushKeysSchema,
});

/** Browser Web Push endpoint removal payload. */
export const WebPushUnsubscribeParamsSchema = closedObject({
  endpoint: Type.String({ minLength: 1, maxLength: 2048, pattern: "^https://" }),
});

/** Request payload for sending a test Web Push notification to current subscriptions. */
export const WebPushTestParamsSchema = closedObject({
  title: Type.Optional(Type.String()),
  body: Type.Optional(Type.String()),
});

export const PushPqcKeysParamsSchema = closedObject({});
export const PushPqcRedeemParamsSchema = closedObject({
  version: Type.Literal(1),
  object_id: Type.String({ minLength: 1, maxLength: 64 }),
  token: Type.String({ minLength: 43, maxLength: 43, pattern: "^[A-Za-z0-9_-]+$" }),
  expires_at_ms: Type.Integer({ minimum: 0, maximum: Number.MAX_SAFE_INTEGER }),
});

/** Empty request type for fetching the Web Push VAPID public key. */
export type WebPushVapidPublicKeyParams = Record<string, never>;
/** Browser PushSubscription subset persisted by the gateway. */
export type WebPushSubscribeParams = {
  endpoint: string;
  keys: { p256dh: string; auth: string };
};
/** Browser PushSubscription endpoint removal request. */
export type WebPushUnsubscribeParams = {
  endpoint: string;
};
/** Optional title/body overrides for a Web Push test notification. */
export type WebPushTestParams = {
  title?: string;
  body?: string;
};

// Wire types derive directly from local schema consts so public d.ts graphs never
// pull in the ProtocolSchemas registry.
export type PushTestParams = Static<typeof PushTestParamsSchema>;
export type PushTestResult = Static<typeof PushTestResultSchema>;
