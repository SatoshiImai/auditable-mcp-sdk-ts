/**
 * Verify a sealed ledger for non-tampering and completeness (§8.3, §10.7).
 *
 * The chain is recomputed from the record bodies rather than read from the stored hashes, so any
 * mutation of an event propagates to the tail digest and is localized. An out-of-band anchored digest
 * (§8.3) catches a fully re-linked rewrite or truncation that an internally-consistent chain cannot.
 * This is a read-only auditor over records that may come straight from a `Ledger` or be reloaded from
 * untrusted storage. `verifyChain` checks chain integrity alone (§8.3); `verifyLedger` adds A-MCP
 * event-schema validation on top (§7.1).
 */

import * as fields from './fields';
import { computeRecordHash, GENESIS_HASH } from './hashing';
import type { SealedRecord } from './ledger';
import { firstSealedValidationError, Outcome } from './models';
import * as reasons from './reasons';

// A verifier reports only the §7.6 Tier-1 anomaly kinds. Re-exported here for convenience so callers
// can match against them without importing `reasons` directly; finer causes go in `detail` (Tier-2).
export const SCHEMA_INVALID = reasons.SCHEMA_INVALID;
export const SEQ_GAP = reasons.SEQ_GAP;
export const RECORD_HASH_MISMATCH = reasons.RECORD_HASH_MISMATCH;
export const DIGEST_MISMATCH = reasons.DIGEST_MISMATCH;
export const PRINCIPAL_MISMATCH = reasons.PRINCIPAL_MISMATCH;
export const ORPHANED_OUTCOME = reasons.ORPHANED_OUTCOME;

/** A single verification failure. `seq` is null for whole-ledger issues (e.g. digest mismatch). */
export interface VerifyIssue {
  seq: number | null;
  kind: string;
  detail: string;
}

/** The result of verifying a ledger; `ok` is true only when `issues` is empty. */
export interface VerifyReport {
  ok: boolean;
  count: number;
  computedDigest: string;
  issues: VerifyIssue[];
}

/**
 * How the verifier reads a-MCP correlation fields, the embedded event, and the governed identity.
 *
 * The defaults (`DEFAULT_ADAPTER`) read a bare, top-level a-MCP event. A caller that seals a-MCP
 * records inside another envelope (e.g. SEP-3004) provides accessors that reach into it, so the
 * verifier can correlate, schema-check, and principal-match the enveloped event without the SDK
 * importing any specific envelope shape.
 */
export interface RecordAdapter {
  /** Extract the correlation key that pairs an attempt with its terminal outcome. */
  idOf: (event: Record<string, unknown>) => unknown;
  /** True when the record is an attempt, false for a terminal outcome. */
  isAttempt: (event: Record<string, unknown>) => boolean;
  /** Extract the embedded a-MCP event that `verifyLedger` schema-checks. */
  eventOf: (event: Record<string, unknown>) => unknown;
  /**
   * Extract the governed identity a record is attributed to, compared against `expectedPrincipal`.
   * Optional: a bare a-MCP event binds no identity (attributing a record to a principal is the
   * envelope's concern, not a-MCP's). A deployment that seals records inside an identity-binding
   * envelope (e.g. SEP-3004, whose protected core carries `principal_id`) reads that identity here.
   * Normalization (e.g. tenant hierarchy) belongs here, so the comparison stays a strict equality.
   */
  principalOf?: (event: Record<string, unknown>) => unknown;
}

/**
 * The sealed event is itself a bare, top-level a-MCP event, binding no governed identity. Frozen so
 * the process-wide default cannot be mutated; spread it to override only what you need:
 * `{ ...DEFAULT_ADAPTER, idOf: (e) => (e.sep3004 as { id: unknown }).id }`.
 */
export const DEFAULT_ADAPTER: RecordAdapter = Object.freeze({
  idOf: (event: Record<string, unknown>) => event[fields.ID],
  isAttempt: (event: Record<string, unknown>) => event[fields.OUTCOME] === Outcome.ATTEMPTED,
  eventOf: (event: Record<string, unknown>) => event,
  principalOf: () => undefined,
});

/**
 * Verify chain integrity alone, independent of the event vocabulary (§8.3).
 *
 * Checks sequence order, previous-hash linkage, record-hash recomputation, attempt/outcome
 * correlation, the principal binding (when `expectedPrincipal` is set), and (with `anchoredDigest`)
 * the anchored-digest compare. This is the tamper-evidence guarantee for any events sealed through
 * `Ledger`; it never inspects the event schema.
 *
 * @param records The sealed records in append order (from a `Ledger` or reloaded storage).
 * @param anchoredDigest An out-of-band anchored tail digest to compare against, if available (§8.3).
 * @param adapter How to read the correlation key and attempt flag from each sealed record. Defaults to
 *   a bare top-level a-MCP event; inject accessors to correlate records sealed inside an envelope.
 * @param expectedPrincipal When set, every record's `adapter.principalOf` is compared against it
 *   (strict equality); a mismatch or an absent identity is flagged `principal-mismatch`. This is an SDK
 *   check, not an a-MCP anomaly: it detects a transplant only for records sealed in an identity-binding
 *   envelope. Omit to skip.
 * @returns A report; `ok` is true only when no issues were found.
 */
export function verifyChain(
  records: SealedRecord[],
  anchoredDigest?: string,
  adapter: RecordAdapter = DEFAULT_ADAPTER,
  expectedPrincipal?: unknown,
): VerifyReport {
  const issues: VerifyIssue[] = [];
  const attemptedIds = new Set<unknown>();
  let prevRecomputed = GENESIS_HASH;

  for (let index = 0; index < records.length; index += 1) {
    const record = records[index];
    if (record === undefined) {
      continue;
    }
    const event = record.event;

    if (record.seq !== index) {
      // Out-of-order is rolled up to seq-gap (Tier-1); the direction is a Tier-2 detail.
      issues.push({ seq: record.seq, kind: SEQ_GAP, detail: `expected seq ${index}, got ${record.seq}` });
    }

    // Recompute from the record body against the recomputed prior link, not the stored one, so a
    // mutation cannot hide behind its own stored hashes. A broken previous_hash link surfaces as a
    // record-hash-mismatch (Tier-1); the "link" detail distinguishes it locally.
    const recomputed = computeRecordHash(event, record.seq, record.host_ts, prevRecomputed);
    if (record.previous_hash !== prevRecomputed) {
      issues.push({
        seq: record.seq,
        kind: RECORD_HASH_MISMATCH,
        detail: 'previous_hash does not link to prior record',
      });
    }
    if (record.record_hash !== recomputed) {
      issues.push({ seq: record.seq, kind: RECORD_HASH_MISMATCH, detail: 'stored record_hash != recomputed' });
    }

    const eventId = adapter.idOf(event);
    if (adapter.isAttempt(event)) {
      attemptedIds.add(eventId);
    } else if (!attemptedIds.has(eventId)) {
      issues.push({
        seq: record.seq,
        kind: ORPHANED_OUTCOME,
        detail: `terminal outcome with no matching attempt, id=${String(eventId)}`,
      });
    }

    // Per-record, fail-closed (an absent identity !== the expected one): a valid chain transplanted
    // under the wrong principal passes hash + chain but fails this.
    if (expectedPrincipal !== undefined && adapter.principalOf?.(event) !== expectedPrincipal) {
      issues.push({
        seq: record.seq,
        kind: PRINCIPAL_MISMATCH,
        detail: `record principal does not match expected ${String(expectedPrincipal)}`,
      });
    }

    prevRecomputed = recomputed;
  }

  const computedDigest = prevRecomputed;
  if (anchoredDigest !== undefined && anchoredDigest !== computedDigest) {
    issues.push({
      seq: null,
      kind: DIGEST_MISMATCH,
      detail: `anchored ${anchoredDigest} != computed ${computedDigest}`,
    });
  }

  return { ok: issues.length === 0, count: records.length, computedDigest, issues };
}

/**
 * Verify chain integrity and A-MCP event-schema conformance (§8.3 + §7.1).
 *
 * `verifyChain` followed by a per-record schema check: a record whose embedded event is not a valid
 * A-MCP event is flagged `schema-invalid`. It is read-lenient on `spec_version` (any published
 * version), so a chain sealed under an earlier version still verifies. For valid A-MCP events the
 * result is identical to `verifyChain`.
 *
 * @param records The sealed records in append order (from a `Ledger` or reloaded storage).
 * @param anchoredDigest An out-of-band anchored tail digest to compare against, if available (§8.3).
 * @param adapter How to read the correlation fields and extract the embedded a-MCP event. Defaults to
 *   a bare top-level a-MCP event; inject `eventOf` to schema-check an event sealed inside an envelope.
 * @param expectedPrincipal When set, each record's `adapter.principalOf` is compared against it, else
 *   `principal-mismatch` (an SDK check); forwarded to `verifyChain`.
 * @returns A report; `ok` is true only when no issues were found.
 */
export function verifyLedger(
  records: SealedRecord[],
  anchoredDigest?: string,
  adapter: RecordAdapter = DEFAULT_ADAPTER,
  expectedPrincipal?: unknown,
): VerifyReport {
  const report = verifyChain(records, anchoredDigest, adapter, expectedPrincipal);
  const schemaIssues: VerifyIssue[] = [];
  for (const record of records) {
    const structural = firstSealedValidationError(adapter.eventOf(record.event));
    if (structural !== null) {
      schemaIssues.push({ seq: record.seq, kind: reasons.SCHEMA_INVALID, detail: structural });
    }
  }
  if (schemaIssues.length === 0) {
    return report;
  }
  return {
    ok: false,
    count: report.count,
    computedDigest: report.computedDigest,
    issues: [...report.issues, ...schemaIssues],
  };
}
