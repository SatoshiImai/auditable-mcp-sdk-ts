import { describe, expect, it } from 'vitest';
import { computeRecordHash, GENESIS_HASH } from '../src/hashing';
import { chainVector } from './vectors';

describe('computeRecordHash reproduces the golden chain byte-for-byte', () => {
  for (const record of chainVector.records) {
    it(`seq=${record.seq}: record_hash matches`, () => {
      expect(computeRecordHash(record.event, record.seq, record.host_ts, record.previous_hash)).toBe(
        record.record_hash,
      );
    });
  }

  it('the first record chains from the genesis link', () => {
    expect(chainVector.records[0]?.previous_hash).toBe(GENESIS_HASH);
  });

  it('each previous_hash links to the prior record_hash', () => {
    for (let i = 1; i < chainVector.records.length; i += 1) {
      expect(chainVector.records[i]?.previous_hash).toBe(chainVector.records[i - 1]?.record_hash);
    }
  });

  it('the tail record_hash equals the chain digest', () => {
    const last = chainVector.records[chainVector.records.length - 1];
    expect(last?.record_hash).toBe(chainVector.digest);
  });
});

describe('GENESIS_HASH', () => {
  it('is 64 zeros', () => {
    expect(GENESIS_HASH).toBe('0'.repeat(64));
  });
});
