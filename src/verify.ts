/**
 * Verify a sealed ledger for non-tampering and completeness (§8.3, §10.7).
 *
 * The chain is recomputed from the record bodies rather than read from the stored hashes, so any
 * mutation of an event propagates to the tail digest and is localized. An out-of-band anchored digest
 * (§8.3) catches a fully re-linked rewrite or truncation that an internally-consistent chain cannot.
 * This is a read-only auditor over records that may come straight from a `Ledger` or be reloaded from
 * untrusted storage, so each event is re-validated structurally before it is trusted.
 */

import * as fields from './fields';
import { computeRecordHash, GENESIS_HASH } from './hashing';
import type { SealedRecord } from './ledger';
import { firstValidationError, Outcome } from './models';
import * as reasons from './reasons';

// Verify issue kinds specific to full-chain audit; the host ingest path uses its own vocabulary.
export const SEQ_GAP = 'seq-gap';
export const SEQ_OUT_OF_ORDER = 'seq-out-of-order';
export const PREV_HASH_MISMATCH = 'prev-hash-mismatch';
export const RECORD_HASH_MISMATCH = 'record-hash-mismatch';
export const DIGEST_MISMATCH = 'digest-mismatch';

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
 * Verify a sealed ledger for non-tampering and completeness.
 *
 * Detects: malformed events, sequence gaps / out-of-order, broken previous-hash links, mutated
 * record hashes, outcomes with no correlating attempt, and (with `anchoredDigest`) a re-linked
 * rewrite or truncation.
 *
 * @param records The sealed records in append order (from a `Ledger` or reloaded storage).
 * @param anchoredDigest An out-of-band anchored tail digest to compare against, if available (§8.3).
 * @returns A report; `ok` is true only when no issues were found.
 */
export function verifyLedger(records: SealedRecord[], anchoredDigest?: string): VerifyReport {
  const issues: VerifyIssue[] = [];
  const attemptedIds = new Set<unknown>();
  let prevRecomputed = GENESIS_HASH;

  for (let index = 0; index < records.length; index += 1) {
    const record = records[index];
    if (record === undefined) {
      continue;
    }
    const event = record.event;

    const structural = firstValidationError(event);
    if (structural !== null) {
      issues.push({ seq: record.seq, kind: reasons.SCHEMA_INVALID, detail: structural });
    }

    if (record.seq !== index) {
      const kind = record.seq > index ? SEQ_GAP : SEQ_OUT_OF_ORDER;
      issues.push({ seq: record.seq, kind, detail: `expected seq ${index}, got ${record.seq}` });
    }

    // Recompute from the record body against the recomputed prior link, not the stored one, so a
    // mutation cannot hide behind its own stored hashes.
    const recomputed = computeRecordHash(event, record.seq, record.host_ts, prevRecomputed);
    if (record.previous_hash !== prevRecomputed) {
      issues.push({ seq: record.seq, kind: PREV_HASH_MISMATCH, detail: 'previous_hash does not link to prior record' });
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
        kind: reasons.OUTCOME_WITHOUT_ATTEMPT,
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
