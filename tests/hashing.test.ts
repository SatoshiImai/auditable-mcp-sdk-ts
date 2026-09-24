import { describe, expect, it } from 'vitest';
import { sha256Hex } from '../src/canonical';
import { computeRecordHash, GENESIS_HASH, witnessPayload } from '../src/hashing';
import { chainVector, chainWitnessedVector } from './vectors';

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

describe('witness signature preimage (§7.1, §8.4)', () => {
  it('reproduces the golden bytes for every record', () => {
    for (const record of chainWitnessedVector.records) {
      const payload = witnessPayload(record.seq, record.host_ts, record.previous_hash, record.record_hash);
      expect(new TextDecoder().decode(payload)).toBe(record.witness_preimage.canonical);
      expect(sha256Hex(record.witness_preimage.canonical)).toBe(record.witness_preimage.sha256);
    }
  });

  it('the witnessed chain hashes identically to the unwitnessed one (§5.2)', () => {
    expect(chainWitnessedVector.digest).toBe(chainVector.digest);
    let previous = GENESIS_HASH;
    for (const [index, witnessed] of chainWitnessedVector.records.entries()) {
      const plain = chainVector.records[index];
      const computed = computeRecordHash(witnessed.event, witnessed.seq, witnessed.host_ts, previous);
      expect(computed).toBe(witnessed.record_hash);
      expect(computed).toBe(plain?.record_hash);
      expect(witnessed.host_signature).toBeTruthy();
      previous = computed;
    }
  });
});
