// M9 (PQC migration, whitepaper 2.2.9): structured PQC logging chokepoint.
//
// Every PQC event flows through `pqcLog.{info,warn,error,debug}`. The emit
// boundary applies a uniform redaction pass so the surface that
// subscribers see never carries secret fields, undefined values, or raw
// buffer payloads. A default in-process recorder captures the events
// when no other sink has been bound — useful for tests, and a no-op for
// production callers that wire their own logger via
// `bindOpenClawLogger`.

export const PQC_EVENT = [
  "wrap-secret",
  "unwrap-secret",
  "device-identity",
  "keyring",
  "rotation",
  "backup",
  "restore",
  "doctor",
] as const;

export type PqcEvent = (typeof PQC_EVENT)[number];

export type PqcLogLevel = "info" | "warn" | "error" | "debug";
export type PqcLogStatus = "ok" | "fail";

export interface PqcLogPayload {
  event: PqcEvent;
  level: PqcLogLevel;
  status: PqcLogStatus;
  identityKey?: string;
  keyId?: string;
  detail?: string;
  /** Optional auxiliary fields. The emitter applies the redaction pass
   *  to every nested key; values that cannot survive redaction (Buffer /
   *  TypedArray) are dropped. */
  [extra: string]: unknown;
}

export type PqcEmit = (record: PqcLogPayload) => void;

const REDACTED_FIELD_PATTERNS: RegExp[] = [
  /passphrase/i,
  /raw[-_]?key/i,
  /private[-_]?key/i,
  /secret/i,
];

function isBufferLike(value: unknown): boolean {
  if (value === null || value === undefined) return false;
  if (value instanceof Buffer) return true;
  if (value instanceof Uint8Array) return true;
  if (value instanceof ArrayBuffer) return true;
  if (ArrayBuffer.isView(value)) return true;
  return false;
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  if (value === null || typeof value !== "object") return false;
  if (Array.isArray(value)) return false;
  if (isBufferLike(value)) return false;
  const proto = Object.getPrototypeOf(value);
  return proto === Object.prototype || proto === null;
}

/**
 * Redact a payload in place: drop undefined values, drop Buffer /
 * TypedArray values, and drop keys whose name matches a secret pattern.
 * Returns a new object; the input is left untouched. Nested objects are
 * redacted recursively; nested arrays are mapped over.
 */
export function redactPqcLogPayload(payload: PqcLogPayload): PqcLogPayload {
  const out: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(payload)) {
    if (v === undefined) continue;
    if (REDACTED_FIELD_PATTERNS.some((re) => re.test(k))) {
      // Match the whitepaper 2.2.9 contract: refuse to emit any field
      // whose name is even slightly secret. Replace with a marker so the
      // downstream log still knows a value was attempted.
      out[k] = "[REDACTED]";
      continue;
    }
    if (isBufferLike(v)) {
      // Buffer / TypedArray fields are never safe to log. Drop.
      continue;
    }
    if (isPlainObject(v)) {
      out[k] = redactPqcLogPayload(v as unknown as PqcLogPayload);
      continue;
    }
    if (Array.isArray(v)) {
      out[k] = v
        .map((item) =>
          isPlainObject(item)
            ? redactPqcLogPayload(item as unknown as PqcLogPayload)
            : isBufferLike(item)
              ? undefined
              : item,
        )
        .filter((item) => item !== undefined);
      continue;
    }
    out[k] = v;
  }
  return out as PqcLogPayload;
}

let installedEmitter: PqcEmit = defaultEmitter;

export function setPqcEmit(emit: PqcEmit): void {
  installedEmitter = emit;
}

export function getPqcEmit(): PqcEmit {
  return installedEmitter;
}

export function resetPqcEmit(): void {
  installedEmitter = defaultEmitter;
}

export interface OpenClawLogger {
  info: (record: Record<string, unknown>) => void;
  warn: (record: Record<string, unknown>) => void;
  error: (record: Record<string, unknown>) => void;
  debug: (record: Record<string, unknown>) => void;
}

export function bindOpenClawLogger(logger: OpenClawLogger): void {
  installedEmitter = (record) => {
    const redacted = redactPqcLogPayload(record);
    const enriched = {
      ...redacted,
      tag: "PQC",
    };
    switch (redacted.level) {
      case "warn":
        logger.warn(enriched);
        return;
      case "error":
        logger.error(enriched);
        return;
      case "debug":
        logger.debug(enriched);
        return;
      case "info":
      default:
        logger.info(enriched);
        return;
    }
  };
}

function defaultEmitter(record: PqcLogPayload): void {
  const redacted = redactPqcLogPayload(record);
  // eslint-disable-next-line no-console -- this is the in-process fallback
  console.log(`[PQC] ${JSON.stringify(redacted)}`);
}

export const pqcLog = {
  info(payload: Omit<PqcLogPayload, "level">): void {
    installedEmitter({ ...payload, level: "info" });
  },
  warn(payload: Omit<PqcLogPayload, "level">): void {
    installedEmitter({ ...payload, level: "warn" });
  },
  error(payload: Omit<PqcLogPayload, "level">): void {
    installedEmitter({ ...payload, level: "error" });
  },
  debug(payload: Omit<PqcLogPayload, "level">): void {
    installedEmitter({ ...payload, level: "debug" });
  },
};
