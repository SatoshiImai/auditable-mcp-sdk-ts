import { describe, expect, it } from 'vitest';
import type { SealedRecord } from '../src/ledger';
import { DIGEST_MISMATCH, PREV_HASH_MISMATCH, RECORD_HASH_MISMATCH, SEQ_GAP, verifyLedger } from '../src/verify';
import { chainVector } from './vectors';

function cloneRecords(): SealedRecord[] {
  return chainVector.records.map((r) => ({ ...r, event: { ...r.event } }));
}

describe('verifyLedger accepts a sound golden chain', () => {
  it('reports ok=true with the digest equal to the chain digest', () => {
    const report = verifyLedger(chainVector.records as SealedRecord[]);
    expect(report.ok).toBe(true);
    expect(report.issues).toHaveLength(0);
    expect(report.computedDigest).toBe(chainVector.digest);
    expect(report.count).toBe(chainVector.records.length);
  });

  it('stays ok when the anchored digest matches', () => {
    const report = verifyLedger(chainVector.records as SealedRecord[], chainVector.digest);
    expect(report.ok).toBe(true);
  });
});

describe('verifyLedger detects tampering', () => {
  it('flags record-hash-mismatch when an event is mutated', () => {
    const records = cloneRecords();
    (records[0] as { event: Record<string, unknown> }).event.action_type = 'tampered';
    const report = verifyLedger(records);
    expect(report.ok).toBe(false);
    expect(report.issues.some((i) => i.kind === RECORD_HASH_MISMATCH)).toBe(true);
  });

  it('flags prev-hash-mismatch when a link is broken', () => {
    const records = cloneRecords();
    (records[1] as { previous_hash: string }).previous_hash = '0'.repeat(64);
    const report = verifyLedger(records);
    expect(report.issues.some((i) => i.kind === PREV_HASH_MISMATCH)).toBe(true);
  });

  it('flags seq-gap when a sequence jumps', () => {
    const records = cloneRecords();
    (records[1] as { seq: number }).seq = 5;
    const report = verifyLedger(records);
    expect(report.issues.some((i) => i.kind === SEQ_GAP)).toBe(true);
  });

  it('flags digest-mismatch on an anchored-digest mismatch (truncation / rewrite)', () => {
    const report = verifyLedger(chainVector.records as SealedRecord[], 'f'.repeat(64));
    expect(report.ok).toBe(false);
    expect(report.issues.some((i) => i.kind === DIGEST_MISMATCH)).toBe(true);
  });
});
