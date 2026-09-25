/**
 * An in-memory `LedgerRepository` for tests and single-process use.
 *
 * It is durable only for the process lifetime. Production integrators supply a real adapter; this one
 * exists so the persistence path can be exercised without a backend.
 */

import type { SealedRecord } from '../ledger';
import { type LedgerRepository, RepositoryError } from './repository';

/** Holds sealed records per partition in memory (implements `LedgerRepository`). */
export class InMemoryLedgerRepository implements LedgerRepository {
  #byPartition = new Map<string, SealedRecord[]>();

  async append(partition: string, record: SealedRecord): Promise<void> {
    const records = this.#byPartition.get(partition) ?? [];
    const next = records.length === 0 ? 0 : (records[records.length - 1] as SealedRecord).seq + 1;
    if (record.seq !== next) {
      throw new RepositoryError(`seq ${record.seq} is not the next position ${next} of partition ${partition}`);
    }
    records.push(record);
    this.#byPartition.set(partition, records);
  }

  async loadTail(partition: string): Promise<SealedRecord | null> {
    const records = this.#byPartition.get(partition);
    return records && records.length > 0 ? (records[records.length - 1] ?? null) : null;
  }

  async readAll(partition: string): Promise<SealedRecord[]> {
    return [...(this.#byPartition.get(partition) ?? [])];
  }
}
