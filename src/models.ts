/**
 * Typed wire contracts for Auditable MCP (the Zod source of ergonomics and validation).
 *
 * These schemas mirror the language-neutral JSON Schema under `spec/schema/`, which remains the
 * normative contract. Zod gives tool authors IDE completion (via `z.infer`) and strict runtime shape
 * validation; a parsed object is the exact JSON — absent optionals omitted — that canonicalization
 * and hashing consume (§8).
 *
 * Three contracts live here: the audit event (§4), the capability object (§6.1), and the attempt
 * response tagged union (§7.1). The §8.2 record-hash preimage is deliberately *not* modeled — it is
 * a local hash input, never a wire object (see `hashing.ts`).
 *
 * String fields carry the schema's `pattern` verbatim rather than Zod's built-in `uuid()` / ISO
 * helpers, which accept a different (looser) set: the value must pass through untouched and match the
 * contract exactly so the canonical bytes survive for hashing. Every code-valued field is pinned to
 * the §7.6 Tier-1 vocabulary. `tests/conformance` guards these copies against schema drift.
 */

import { z } from 'zod';
import { MAX_SAFE_INTEGER } from './canonical';

// The only spec version defined by this contract; a mismatch is a hard validation error.
export const SPEC_VERSION = 'auditable-mcp/0.1.1' as const;

// Patterns copied verbatim from the normative JSON Schema (spec/schema/).
export const UUID_PATTERN =
  '^([0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}|00000000-0000-0000-0000-000000000000)$';
// String.raw keeps the `\d` classes readable, matching the schema's escaped source one-to-one.
export const DATETIME_PATTERN = String.raw`^(?:(?:\d\d[2468][048]|\d\d[13579][26]|\d\d0[48]|[02468][048]00|[13579][26]00)-02-29|\d{4}-(?:(?:0[13578]|1[02])-(?:0[1-9]|[12]\d|3[01])|(?:0[469]|11)-(?:0[1-9]|[12]\d|30)|(?:02)-(?:0[1-9]|1\d|2[0-8])))T(?:(?:[01]\d|2[0-3]):[0-5]\d(?::[0-5]\d(?:\.\d+)?)?(?:Z))$`;
export const CHAIN_HASH_PATTERN = '^[0-9a-f]{64}$';
export const CONTEXT_HASH_PATTERN = '^sha256:[0-9a-f]{64}$';
// Standard base64 with optional padding (§5.1: base64url is forbidden on the wire).
export const SIGNATURE_PATTERN = '^[A-Za-z0-9+/]+={0,2}$';

const uuidRegex = new RegExp(UUID_PATTERN);
const datetimeRegex = new RegExp(DATETIME_PATTERN);
const chainHashRegex = new RegExp(CHAIN_HASH_PATTERN);
const contextHashRegex = new RegExp(CONTEXT_HASH_PATTERN);
const signatureRegex = new RegExp(SIGNATURE_PATTERN);

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

/** The attempt-response discriminator (§7.1). */
export const Status = {
  ACCEPT: 'accept',
  REJECT: 'reject',
  UNAVAILABLE: 'unavailable',
} as const;
export type Status = (typeof Status)[keyof typeof Status];

// The §7.6 Tier-1 code enums pinned onto the wire contracts.
const abortReasonSchema = z.enum(['hash-mismatch', 'host-rejected', 'host-unavailable']);
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
export const auditEventSchema = z
  .strictObject({
    id: z.string().regex(uuidRegex),
    spec_version: z.literal(SPEC_VERSION),
    ts: z.string().regex(datetimeRegex),
    call_id: z.string().min(1),
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
  })
  .refine((event) => event.outcome !== Outcome.ABORTED || event.reason !== undefined, {
    message: 'an aborted outcome requires a reason',
    path: ['reason'],
  });
export type AuditEvent = z.infer<typeof auditEventSchema>;

/** An audit capability exchanged during negotiation: the version, level, and attempt mode (§6.1). */
export const auditCapabilitySchema = z.strictObject({
  // All three REQUIRED (§6.1, normative audit-capability.schema.json): a peer that omits any field is
  // rejected, not silently coerced, so version negotiation cannot be bypassed by omission. The host
  // completes its own partial self-declaration with explicit SDK defaults before parsing (host.ts).
  spec_version: z.string().min(1),
  level: z.enum(Level),
  attempt: z.literal('request'),
});
export type AuditCapability = z.infer<typeof auditCapabilitySchema>;

/** A sealed attempt: carries the host-assigned fields the tool needs for Polluted Stop (§7.1, §7.2). */
export const acceptResponseSchema = z.strictObject({
  status: z.literal(Status.ACCEPT),
  seq: z.int().min(0).max(MAX_SAFE_INTEGER),
  record_hash: z.string().regex(chainHashRegex),
  host_ts: z.string().regex(datetimeRegex),
  previous_hash: z.string().regex(chainHashRegex),
});
export type AcceptResponse = z.infer<typeof acceptResponseSchema>;

/** A refused attempt: ledger integrity could not be guaranteed (§7.1). `reason` is a Tier-1 code. */
export const rejectResponseSchema = z.strictObject({
  status: z.literal(Status.REJECT),
  reason: rejectReasonSchema,
});
export type RejectResponse = z.infer<typeof rejectResponseSchema>;

/** A transient host-internal failure: fail closed and retry (§7.1). `retryable` is always true. */
export const unavailableResponseSchema = z.strictObject({
  status: z.literal(Status.UNAVAILABLE),
  reason: z.literal('internal-error'),
  retryable: z.literal(true),
});
export type UnavailableResponse = z.infer<typeof unavailableResponseSchema>;

/** The host reply to `audit/attempt` — a tagged union discriminated on `status` (§7.1). */
export const attemptResponseSchema = z.discriminatedUnion('status', [
  acceptResponseSchema,
  rejectResponseSchema,
  unavailableResponseSchema,
]);
export type AttemptResponse = z.infer<typeof attemptResponseSchema>;

/**
 * Return the first structural validation message for `event` as an AuditEvent, or null if valid.
 *
 * This is the shared shape check used at the host ingest boundary (§7.1) and by the ledger verifier.
 * It enforces the event's structure, types, required fields, closed shape, and the pattern / range /
 * enum constraints copied from the normative JSON Schema.
 *
 * @returns null if valid, otherwise the first error as `<path>: <message>`.
 */
export function firstValidationError(event: unknown): string | null {
  const result = auditEventSchema.safeParse(event);
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
