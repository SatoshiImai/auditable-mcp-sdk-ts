import { describe, expect, it } from 'vitest';
import type { SealedRecord } from '../src/ledger';
import { InMemoryLedgerRepository, RepositoryError } from '../src/storage';
import { chainVector } from './vectors';

const records = chainVector.records as SealedRecord[];

describe('InMemoryLedgerRepository', () => {
  it('returns records from readAll in append order', async () => {
    const repo = new InMemoryLedgerRepository();
    for (const record of records) {
      await repo.append('tenant-a', record);
    }
    const all = await repo.readAll('tenant-a');
    expect(all.map((r) => r.seq)).toEqual(records.map((r) => r.seq));
  });

  it('loadTail returns the last record, or null for an empty partition', async () => {
    const repo = new InMemoryLedgerRepository();
    expect(await repo.loadTail('empty')).toBeNull();
    await repo.append('tenant-a', records[0] as SealedRecord);
    await repo.append('tenant-a', records[1] as SealedRecord);
    expect((await repo.loadTail('tenant-a'))?.seq).toBe(records[1]?.seq);
  });

  it('never leaks records across partitions (§10.5)', async () => {
    const repo = new InMemoryLedgerRepository();
    await repo.append('tenant-a', records[0] as SealedRecord);
    await repo.append('tenant-a', records[1] as SealedRecord);
    await repo.append('tenant-b', records[0] as SealedRecord);
    expect(await repo.readAll('tenant-a')).toHaveLength(2);
    expect(await repo.readAll('tenant-b')).toHaveLength(1);
    expect((await repo.loadTail('tenant-b'))?.record_hash).toBe(records[0]?.record_hash);
  });

  it('refuses an append that is not the next position of its partition (§7.1)', async () => {
    const repo = new InMemoryLedgerRepository();
    await expect(repo.append('tenant-a', records[1] as SealedRecord)).rejects.toThrow(RepositoryError);
    await repo.append('tenant-a', records[0] as SealedRecord);
    await expect(repo.append('tenant-a', records[0] as SealedRecord)).rejects.toThrow(RepositoryError);
    expect(await repo.readAll('tenant-a')).toHaveLength(1);
  });
});
