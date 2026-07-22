import { describe, expect, it } from 'vitest';
import { GENESIS_HASH } from '../src/hashing';
import { Ledger, type SealedRecord } from '../src/ledger';
import { chainVector } from './vectors';

describe('Ledger reproduces the golden chain', () => {
  it('appending the vector events with their host_ts yields the same record_hash and digest', () => {
    const ledger = new Ledger('tenant-a');
    for (const record of chainVector.records) {
      const sealed = ledger.append(record.event, record.host_ts);
      expect(sealed.record_hash).toBe(record.record_hash);
      expect(sealed.previous_hash).toBe(record.previous_hash);
    }
    expect(ledger.digest()).toBe(chainVector.digest);
    expect(ledger.length).toBe(chainVector.records.length);
  });
});

describe('Ledger seal / commit split', () => {
  it('does not advance chain state until commit', () => {
    const ledger = new Ledger('tenant-a');
    const event = chainVector.records[0]?.event as Record<string, unknown>;
    const sealed = ledger.seal(event, '2026-07-15T00:00:01.000Z');
    expect(ledger.length).toBe(0);
    expect(ledger.digest()).toBe(GENESIS_HASH);

    ledger.commit(sealed);
    expect(ledger.length).toBe(1);
    expect(ledger.digest()).toBe(sealed.record_hash);
  });

  it('an empty ledger digests to genesis', () => {
    expect(new Ledger('x').digest()).toBe(GENESIS_HASH);
  });
});

describe('Ledger.resumeFrom continues chain state without holding history', () => {
  it('continues seq and the tail link from a persisted tail', () => {
    const tail = chainVector.records[chainVector.records.length - 1] as SealedRecord;
    const ledger = new Ledger('tenant-a');
    ledger.resumeFrom(tail);

    expect(ledger.length).toBe(tail.seq + 1);
    expect(ledger.digest()).toBe(tail.record_hash);
    expect(ledger.records()).toHaveLength(0);
  });

  it('resets to genesis from a null tail', () => {
    const ledger = new Ledger('tenant-a');
    ledger.append(chainVector.records[0]?.event as Record<string, unknown>, '2026-07-15T00:00:01.000Z');
    ledger.resumeFrom(null);
    expect(ledger.length).toBe(0);
    expect(ledger.digest()).toBe(GENESIS_HASH);
  });
});
