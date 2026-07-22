import { describe, expect, it } from 'vitest';
import type { SealedRecord } from '../src/ledger';
import { Ledger } from '../src/ledger';
import {
  DIGEST_MISMATCH,
  RECORD_HASH_MISMATCH,
  SCHEMA_INVALID,
  SEQ_GAP,
  verifyChain,
  verifyLedger,
} from '../src/verify';
import { chainSignedVector, chainVector } from './vectors';

function boundaryEvent(id: string, outcome = 'attempted'): Record<string, unknown> {
  return { id, actor: 'odin', tenant: 'tenant-a', category: 'boundary', outcome };
}

function sealedBoundaryPair(): Ledger {
  const ledger = new Ledger('tenant-a');
  ledger.append(boundaryEvent('call-1', 'attempted'), '2026-07-15T00:00:01.000Z');
  ledger.append(boundaryEvent('call-1', 'denied'), '2026-07-15T00:00:02.000Z');
  return ledger;
}

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

  it('reproduces the signed golden chain (record_hash includes the signature, §8.2)', () => {
    const report = verifyLedger(chainSignedVector.records as SealedRecord[]);
    expect(report.ok).toBe(true);
    expect(report.computedDigest).toBe(chainSignedVector.digest);
  });

  it('stays ok when the anchored digest matches', () => {
    const report = verifyLedger(chainVector.records as SealedRecord[], chainVector.digest);
    expect(report.ok).toBe(true);
  });
});

describe('verifyLedger detects tampering with Tier-1 anomaly kinds (§7.6)', () => {
  it('flags record-hash-mismatch when an event is mutated', () => {
    const records = cloneRecords();
    (records[0] as { event: Record<string, unknown> }).event.action_type = 'tampered';
    const report = verifyLedger(records);
    expect(report.ok).toBe(false);
    expect(report.issues.some((i) => i.kind === RECORD_HASH_MISMATCH)).toBe(true);
  });

  it('flags record-hash-mismatch when a previous_hash link is broken', () => {
    const records = cloneRecords();
    (records[1] as { previous_hash: string }).previous_hash = '0'.repeat(64);
    const report = verifyLedger(records);
    expect(report.issues.some((i) => i.kind === RECORD_HASH_MISMATCH)).toBe(true);
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

describe('verifyChain audits a non-A-MCP envelope schema-free', () => {
  it('accepts a boundary chain that verifyLedger rejects as schema-invalid', () => {
    const ledger = sealedBoundaryPair();
    const records = ledger.records();
    const chain = verifyChain(records, ledger.digest());
    expect(chain.ok).toBe(true);
    expect(chain.computedDigest).toBe(ledger.digest());
    expect(verifyLedger(records, ledger.digest()).issues.some((i) => i.kind === SCHEMA_INVALID)).toBe(true);
  });

  it('still detects a mutated body, and never emits schema-invalid', () => {
    const records = sealedBoundaryPair().records();
    records[1] = { ...(records[1] as SealedRecord), event: boundaryEvent('call-1', 'expired') };
    const report = verifyChain(records);
    expect(report.ok).toBe(false);
    expect(report.issues.some((i) => i.kind === RECORD_HASH_MISMATCH)).toBe(true);
    expect(report.issues.some((i) => i.kind === SCHEMA_INVALID)).toBe(false);
  });

  it('still detects a seq gap', () => {
    const ledger = new Ledger('tenant-a');
    for (let n = 1; n <= 3; n += 1) {
      ledger.append(boundaryEvent(`call-${n}`), `2026-07-15T00:00:0${n}.000Z`);
    }
    const records = ledger.records();
    records.splice(1, 1);
    expect(verifyChain(records).issues.some((i) => i.kind === SEQ_GAP)).toBe(true);
  });
});
