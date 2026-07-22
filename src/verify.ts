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
import { firstValidationError, Outcome } from './models';
import * as reasons from './reasons';

// A verifier reports only the §7.6 Tier-1 anomaly kinds. Re-exported here for convenience so callers
// can match against them without importing `reasons` directly; finer causes go in `detail` (Tier-2).
export const SCHEMA_INVALID = reasons.SCHEMA_INVALID;
export const SEQ_GAP = reasons.SEQ_GAP;
export const RECORD_HASH_MISMATCH = reasons.RECORD_HASH_MISMATCH;
export const DIGEST_MISMATCH = reasons.DIGEST_MISMATCH;
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
 * Verify chain integrity alone, independent of the event vocabulary (§8.3).
 *
 * Checks sequence order, previous-hash linkage, record-hash recomputation, attempt/outcome
 * correlation, and (with `anchoredDigest`) the anchored-digest compare. This is the tamper-evidence
 * guarantee for any events sealed through `Ledger`; it never inspects the event schema.
 *
 * @param records The sealed records in append order (from a `Ledger` or reloaded storage).
 * @param anchoredDigest An out-of-band anchored tail digest to compare against, if available (§8.3).
 * @returns A report; `ok` is true only when no issues were found.
 */
export function verifyChain(records: SealedRecord[], anchoredDigest?: string): VerifyReport {
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

    const outcome = event[fields.OUTCOME];
    const eventId = event[fields.ID];
    if (outcome === Outcome.ATTEMPTED) {
      attemptedIds.add(eventId);
    } else if (!attemptedIds.has(eventId)) {
      issues.push({
        seq: record.seq,
        kind: ORPHANED_OUTCOME,
        detail: `outcome=${String(outcome)} id=${String(eventId)}`,
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
 * `verifyChain` followed by a per-record schema check: a record that is not a strict A-MCP event is
 * flagged `schema-invalid`. For A-MCP events the result is identical to `verifyChain`.
 *
 * @param records The sealed records in append order (from a `Ledger` or reloaded storage).
 * @param anchoredDigest An out-of-band anchored tail digest to compare against, if available (§8.3).
 * @returns A report; `ok` is true only when no issues were found.
 */
export function verifyLedger(records: SealedRecord[], anchoredDigest?: string): VerifyReport {
  const report = verifyChain(records, anchoredDigest);
  const schemaIssues: VerifyIssue[] = [];
  for (const record of records) {
    const structural = firstValidationError(record.event);
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
