import { describe, expect, it } from 'vitest';
import { sha256Hex } from '../src/canonical';
import { computeRecordHash, countersignaturePayload, GENESIS_HASH } from '../src/hashing';
import { chainCountersignedVector, chainVector } from './vectors';

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

describe('countersignature preimage (§7.1, §8.4)', () => {
  it('reproduces the golden bytes for every record', () => {
    for (const record of chainCountersignedVector.records) {
      const payload = countersignaturePayload(
        record.seq,
        record.host_ts,
        record.log_id as string,
        record.previous_hash,
        record.record_hash,
      );
      expect(new TextDecoder().decode(payload)).toBe(record.countersignature_preimage.canonical);
      expect(sha256Hex(record.countersignature_preimage.canonical)).toBe(record.countersignature_preimage.sha256);
    }
  });

  it('the countersigned chain hashes identically to the uncountersigned one (§5.2)', () => {
    expect(chainCountersignedVector.digest).toBe(chainVector.digest);
    let previous = GENESIS_HASH;
    for (const [index, countersigned] of chainCountersignedVector.records.entries()) {
      const plain = chainVector.records[index];
      const computed = computeRecordHash(countersigned.event, countersigned.seq, countersigned.host_ts, previous);
      expect(computed).toBe(countersigned.record_hash);
      expect(computed).toBe(plain?.record_hash);
      expect(countersigned.host_signature).toBeTruthy();
      previous = computed;
    }
  });
});
