/**
 * Typed wire contracts for Auditable MCP (the Zod source of ergonomics and validation).
 *
 * These schemas mirror the language-neutral JSON Schema under `spec/schema/`, which remains the
 * normative contract. Zod gives tool authors IDE completion (via `z.infer`) and strict runtime shape
 * validation; a parsed object is the exact JSON — absent optionals omitted — that canonicalization
 * and hashing consume (§8).
 *
 * The contracts here are the audit event (§4), the capability object (§6.1), the attempt response
 * tagged union (§7.1), and the two `_meta` objects the 2026-07-28 binding carries (§6.4). The §8.2
 * record-hash preimage is deliberately *not* modeled — it is a local hash input, never a wire object
 * (see `hashing.ts`).
 *
 * String fields carry the schema's `pattern` verbatim rather than Zod's built-in `uuid()` / ISO
 * helpers, which accept a different (looser) set: the value must pass through untouched and match the
 * contract exactly so the canonical bytes survive for hashing. Every code-valued field is pinned to
 * the §7.6 Tier-1 vocabulary. `tests/conformance` guards these copies against schema drift.
 */

import { z } from 'zod';
import { hasLoneSurrogate, MAX_SAFE_INTEGER } from './canonical';

// The only spec version defined by this contract; a mismatch is a hard validation error.
export const SPEC_VERSION = 'auditable-mcp/0.3' as const;

/**
 * The [SEP-2133] extension identifier: the key of the capability object in the `extensions` member of
 * ClientCapabilities (host) or ServerCapabilities (tool), and of this extension's `_meta` objects
 * (§6.1, §6.4). The identifier names the extension; `SPEC_VERSION` names the wire version.
 */
export const EXTENSION_ID = 'com.timberlandchapel/auditable-mcp' as const;

// Patterns copied verbatim from the normative JSON Schema (spec/schema/). A UUID is the lowercase form
// RFC 9562 §4 gives for output, compared as a string (§4). An event `id` (and a `responses` key) admits
// the nil UUID; a `session_id` does not (§6.3).
export const UUID_PATTERN =
  '^([0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}|00000000-0000-0000-0000-000000000000)$';
export const SESSION_ID_PATTERN = '^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$';
// String.raw keeps the `\d` classes readable, matching the schema's escaped source one-to-one.
export const DATETIME_PATTERN = String.raw`^(?:(?:\d\d[2468][048]|\d\d[13579][26]|\d\d0[48]|[02468][048]00|[13579][26]00)-02-29|\d{4}-(?:(?:0[13578]|1[02])-(?:0[1-9]|[12]\d|3[01])|(?:0[469]|11)-(?:0[1-9]|[12]\d|30)|(?:02)-(?:0[1-9]|1\d|2[0-8])))T(?:(?:[01]\d|2[0-3]):[0-5]\d(?::[0-5]\d(?:\.\d+)?)?(?:Z))$`;
export const CHAIN_HASH_PATTERN = '^[0-9a-f]{64}$';
export const CONTEXT_HASH_PATTERN = '^sha256:[0-9a-f]{64}$';
// base64url without padding, as JWS writes a signature (§5.1).
export const SIGNATURE_PATTERN = '^[A-Za-z0-9_-]+$';
// The signature pattern of events sealed before v0.3, which were standard base64.
const EARLIER_SIGNATURE_PATTERN = '^[A-Za-z0-9+/]+={0,2}$';

const uuidRegex = new RegExp(UUID_PATTERN);
const sessionIdRegex = new RegExp(SESSION_ID_PATTERN);
// Events sealed before v0.3 were validated against the looser mixed-case pattern of their own schema.
const earlierUuidRegex =
  /^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}|00000000-0000-0000-0000-000000000000)$/;
const datetimeRegex = new RegExp(DATETIME_PATTERN);
const chainHashRegex = new RegExp(CHAIN_HASH_PATTERN);
const contextHashRegex = new RegExp(CONTEXT_HASH_PATTERN);
const signatureRegex = new RegExp(SIGNATURE_PATTERN);
const earlierSignatureRegex = new RegExp(EARLIER_SIGNATURE_PATTERN);

/** The lifecycle state an event records (§7.2). */
export const Outcome = {
  ATTEMPTED: 'attempted',
  SUCCESS: 'success',
  FAILED: 'failed',
  ABORTED: 'aborted',
} as const;
export type Outcome = (typeof Outcome)[keyof typeof Outcome];

/** The negotiated assurance level (§5, §6.1). */
export const Level = {
  L1: 'L1',
  L2: 'L2',
} as const;
export type Level = (typeof Level)[keyof typeof Level];

/**
 * What a participant declares on the countersignature axis (§5.2, §6.1).
 *
 * Unlike `Level`, the obligation on this axis falls on the host: `HOST` means sealed records carry a
 * countersignature - a host declaring it will countersign, a tool declaring it requires one.
 */
export const Countersign = {
  NONE: 'none',
  HOST: 'host',
} as const;
export type Countersign = (typeof Countersign)[keyof typeof Countersign];

/** The attempt-response discriminator (§7.1). */
export const Status = {
  ACCEPT: 'accept',
  REJECT: 'reject',
  UNAVAILABLE: 'unavailable',
} as const;
export type Status = (typeof Status)[keyof typeof Status];

// The §7.6 Tier-1 code enums pinned onto the wire contracts.
const abortReasonSchema = z.enum([
  'hash-mismatch',
  'host-rejected',
  'host-unavailable',
  'host-uncountersigned',
  'host-signature-invalid',
]);
const rejectReasonSchema = z.enum([
  'schema-invalid',
  'replay-detected',
  'signature-invalid',
  'l2-unsigned',
  'unknown-key',
]);

/** A Tier-1 host reject reason (§7.6) — the codes a host may return on `status: "reject"`. */
export type RejectReason = z.infer<typeof rejectReasonSchema>;

/** The domain target of an operation (§4). */
export const targetResourceSchema = z.strictObject({
  kind: z.string().min(1),
  ref: z.string().min(1),
  scope_hint: z.string().optional(),
});
export type TargetResource = z.infer<typeof targetResourceSchema>;

/**
 * One audit record describing one internal operation (§4).
 *
 * The Level-2 fields (`signer_seq`, `key_id`, `signature`) are optional so a single schema serves
 * both levels; the signing layer populates them. `reason` is pinned to the Tier-1 abort codes and is
 * required exactly when `outcome` is `aborted` (§7.6, §7.2).
 */
// Shared event fields; `spec_version` and the call's name are added per schema below. Field order does
// not affect validation or canonicalization (hashing uses the raw event, not the parsed object).
const auditEventFields = {
  id: z.string().regex(uuidRegex),
  ts: z.string().regex(datetimeRegex),
  traceparent: z.string().optional(),
  action_type: z.string().min(1),
  mutates: z.boolean(),
  egress: z.boolean(),
  target_resource: targetResourceSchema,
  outcome: z.enum(Outcome),
  reason: abortReasonSchema.optional(),
  action_context: z.record(z.string(), z.unknown()).optional(),
  action_context_hash: z.string().regex(contextHashRegex).optional(),
  signer_seq: z.int().min(0).max(MAX_SAFE_INTEGER).optional(),
  key_id: z.string().min(1).optional(),
  signature: z.string().regex(signatureRegex).optional(),
} as const;

/** The Level-2 trio appears together or not at all (the schema's `dependentRequired`, §4). */
function level2Together(event: { signer_seq?: unknown; key_id?: unknown; signature?: unknown }): boolean {
  const present = [event.signer_seq, event.key_id, event.signature].filter((value) => value !== undefined).length;
  return present === 0 || present === 3;
}
const LEVEL2_TOGETHER = {
  message: 'signer_seq, key_id, and signature must appear together or not at all',
  path: ['signature'],
};

export const auditEventSchema = z
  .strictObject({
    spec_version: z.literal(SPEC_VERSION),
    // The audit session the host issued for the parent tools/call (§6.3), hashed and signed.
    session_id: z.string().regex(sessionIdRegex),
    ...auditEventFields,
  })
  .refine((event) => event.outcome !== Outcome.ABORTED || event.reason !== undefined, {
    message: 'an aborted outcome requires a reason',
    path: ['reason'],
  })
  .refine(level2Together, LEVEL2_TOGETHER);
export type AuditEvent = z.infer<typeof auditEventSchema>;

// Published spec versions a verifier accepts when reading a sealed ledger. Emission and ingest stay
// pinned to the current SPEC_VERSION (auditEventSchema, §6.1); a verifier reading a stored ledger must
// accept records sealed under an earlier published version, since their bytes and hash chain are
// immutable evidence.
export const KNOWN_SPEC_VERSIONS = [
  'auditable-mcp/0.1',
  'auditable-mcp/0.1.1',
  'auditable-mcp/0.2',
  'auditable-mcp/0.3',
] as const;

const EARLIER_SPEC_VERSIONS = KNOWN_SPEC_VERSIONS.slice(0, -1) as [string, ...string[]];

/** True for a published `spec_version` before v0.3, whose records a verifier reads in their own shape (§11.4). */
export function isEarlierSpecVersion(version: unknown): boolean {
  return typeof version === 'string' && (EARLIER_SPEC_VERSIONS as readonly string[]).includes(version);
}

// The verification views of events sealed before v0.3, each the vendored schema of its own version
// (spec/schema/earlier/). They named the call by its JSON-RPC `call_id` and wrote the signature in
// standard base64; 0.1 also numbered events as `sequence` and left `reason` and `signature` free. Their
// bytes are immutable evidence, so a verifier reads each in the shape it was sealed in (§11.4).
const earlierSharedFields = {
  id: z.string().regex(earlierUuidRegex),
  ts: z.string().regex(datetimeRegex),
  call_id: z.string().min(1),
  traceparent: z.string().optional(),
  action_type: z.string().min(1),
  mutates: z.boolean(),
  egress: z.boolean(),
  target_resource: targetResourceSchema,
  outcome: z.enum(Outcome),
  action_context: z.record(z.string(), z.unknown()).optional(),
  action_context_hash: z.string().regex(contextHashRegex).optional(),
} as const;

const version01EventSchema = z.strictObject({
  ...earlierSharedFields,
  spec_version: z.literal('auditable-mcp/0.1'),
  reason: z.string().optional(),
  sequence: z.int().min(0).max(MAX_SAFE_INTEGER).optional(),
  key_id: z.string().optional(),
  signature: z.string().optional(),
});

function version011Or02EventSchema(version: 'auditable-mcp/0.1.1' | 'auditable-mcp/0.2') {
  return z
    .strictObject({
      ...earlierSharedFields,
      spec_version: z.literal(version),
      reason: z.enum(['hash-mismatch', 'host-rejected', 'host-unavailable']).optional(),
      signer_seq: z.int().min(0).max(MAX_SAFE_INTEGER).optional(),
      key_id: z.string().min(1).optional(),
      signature: z.string().regex(earlierSignatureRegex).optional(),
    })
    .refine((event) => event.outcome !== Outcome.ABORTED || event.reason !== undefined, {
      message: 'an aborted outcome requires a reason',
      path: ['reason'],
    });
}

const EARLIER_EVENT_SCHEMAS: Record<string, z.ZodType> = {
  'auditable-mcp/0.1': version01EventSchema,
  'auditable-mcp/0.1.1': version011Or02EventSchema('auditable-mcp/0.1.1'),
  'auditable-mcp/0.2': version011Or02EventSchema('auditable-mcp/0.2'),
};

/** An audit capability exchanged during negotiation: the version, level, and attempt mode (§6.1). */
export const auditCapabilitySchema = z.strictObject({
  // All four REQUIRED (§6.1, normative audit-capability.schema.json): a peer that omits any field is
  // rejected, not silently coerced, so version or countersign negotiation cannot be bypassed by omission.
  // The host completes its own partial self-declaration with explicit SDK defaults before parsing.
  spec_version: z.string().min(1),
  level: z.enum(Level),
  attempt: z.literal('request'),
  countersign: z.enum(Countersign),
});
export type AuditCapability = z.infer<typeof auditCapabilitySchema>;

/** A sealed attempt: carries the host-assigned fields the tool needs for Polluted Stop (§7.1, §7.2). */
export const acceptResponseSchema = z
  .strictObject({
    status: z.literal(Status.ACCEPT),
    seq: z.int().min(0).max(MAX_SAFE_INTEGER),
    record_hash: z.string().regex(chainHashRegex),
    host_ts: z.string().regex(datetimeRegex),
    previous_hash: z.string().regex(chainHashRegex),
    // The countersignature (§7.1): present exactly when the host declares `countersign: "host"`. The
    // three fields appear together or not at all - a signature no key names is unverifiable, one that
    // names no ledger can be presented as a statement about another, and a key or a ledger name with
    // no signature establishes nothing.
    host_signature: z.string().regex(signatureRegex).optional(),
    host_key_id: z.string().min(1).optional(),
    log_id: z.string().min(1).optional(),
  })
  .refine(
    (response) =>
      (response.host_signature === undefined) === (response.host_key_id === undefined) &&
      (response.host_signature === undefined) === (response.log_id === undefined),
    {
      message: 'host_signature, host_key_id, and log_id must appear together or not at all',
      path: ['log_id'],
    },
  );
export type AcceptResponse = z.infer<typeof acceptResponseSchema>;

/** A refused attempt: ledger integrity could not be guaranteed (§7.1). `reason` is a Tier-1 code. */
export const rejectResponseSchema = z.strictObject({
  status: z.literal(Status.REJECT),
  reason: rejectReasonSchema,
});
export type RejectResponse = z.infer<typeof rejectResponseSchema>;

/** Nothing was decided: the tool fails closed, and may send the identical attempt again (§7.1). */
export const unavailableResponseSchema = z.strictObject({
  status: z.literal(Status.UNAVAILABLE),
  reason: z.literal('internal-error'),
});
export type UnavailableResponse = z.infer<typeof unavailableResponseSchema>;

/** The host's answer to an attempt — a tagged union discriminated on `status` (§7.1). */
export const attemptResponseSchema = z.discriminatedUnion('status', [
  acceptResponseSchema,
  rejectResponseSchema,
  unavailableResponseSchema,
]);
export type AttemptResponse = z.infer<typeof attemptResponseSchema>;

/**
 * What the host puts in a tools/call's `_meta` under the extension identifier (§6.3, §6.4).
 *
 * `session_id` names the audit session on every request of the call; `responses` answers, on a
 * retry, every attempt of the round before, keyed by the attempt's `id`.
 */
export const auditRequestMetaSchema = z.strictObject({
  session_id: z.string().regex(sessionIdRegex),
  responses: z.record(z.string().regex(uuidRegex), attemptResponseSchema).optional(),
});
export type AuditRequestMeta = z.infer<typeof auditRequestMetaSchema>;

/**
 * What the tool puts in a result's `_meta` under the extension identifier (§6.4).
 *
 * The events are the wire objects exactly as emitted, not re-parsed: their bytes are hashed. The envelope
 * asks only that each be an object; a host validates each one on its own and refuses an invalid one alone
 * (§6.4, §7.1).
 */
export const auditResultMetaSchema = z.strictObject({
  session_id: z.string().regex(sessionIdRegex),
  events: z.array(z.record(z.string(), z.unknown())).min(1),
});
export type AuditResultMeta = z.infer<typeof auditResultMetaSchema>;

function firstError(schema: z.ZodType, event: unknown): string | null {
  const result = schema.safeParse(event);
  if (result.success) {
    return null;
  }
  const issue = result.error.issues[0];
  if (issue === undefined) {
    return 'invalid';
  }
  const location = issue.path.join('.');
  return location ? `${location}: ${issue.message}` : issue.message;
}

/**
 * Return the first structural validation message for `event` as a wire AuditEvent, or null if valid.
 *
 * The strict ingest/emission shape check (§7.1): `spec_version` must equal the current `SPEC_VERSION`.
 * The ledger verifier uses `firstSealedValidationError` instead, which accepts any published version.
 *
 * @returns null if valid, otherwise the first error as `<path>: <message>`.
 */
export function firstValidationError(event: unknown): string | null {
  return firstError(auditEventSchema, event) ?? surrogateError(event);
}

/** §8.1: every string, member names included, is Unicode scalar values; a lone surrogate is structural. */
function surrogateError(event: unknown): string | null {
  return hasLoneSurrogate(event) ? 'a string carries a lone surrogate (§8.1)' : null;
}

/**
 * Like `firstValidationError`, but read-lenient on `spec_version` (ledger verification).
 *
 * A sealed record is immutable evidence, so a verifier reading a stored ledger accepts records sealed
 * under any published `spec_version` (`KNOWN_SPEC_VERSIONS`), each in the shape its version defined;
 * ingest and emission stay pinned to the current version.
 *
 * @returns null if valid, otherwise the first error as `<path>: <message>`.
 */
export function firstSealedValidationError(event: unknown): string | null {
  const version = (event as { spec_version?: unknown } | null)?.spec_version;
  const earlier = typeof version === 'string' ? EARLIER_EVENT_SCHEMAS[version] : undefined;
  if (earlier !== undefined && Object.hasOwn(EARLIER_EVENT_SCHEMAS, version as string)) {
    return firstError(earlier, event) ?? surrogateError(event);
  }
  return firstValidationError(event);
}
