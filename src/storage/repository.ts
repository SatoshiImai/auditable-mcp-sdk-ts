/**
 * The durable-ledger repository contract.
 *
 * Persistence is the integrator's concern (§10.1). The SDK defines this interface and the host writes
 * through it; a concrete adapter maps it onto DynamoDB, Postgres, files, or anything else. No storage
 * backend is imported by this package. A `SealedRecord` is plain JSON data, so an adapter round-trips
 * it directly.
 *
 * Partition isolation (§10.5) is the adapter's responsibility: records for one partition MUST NOT be
 * returned for another. `append` MUST throw `RepositoryError` on any persistence failure so the host
 * can fail closed with a retryable `unavailable` (§7.1).
 */

import type { SealedRecord } from '../ledger';

/** A durable-storage operation failed. Adapters throw this so the host can fail closed. */
export class RepositoryError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = 'RepositoryError';
  }
}

/** A durable, append-only store of sealed records, partitioned per §10.5. */
export interface LedgerRepository {
  /**
   * Durably append `record` to `partition`, conditionally on its `seq`.
   *
   * The append is expected to succeed only if `record.seq` is the partition's next position - a
   * conditional put, a unique key on (partition, seq), or a compare-and-set on the tail - so two writers
   * can never both land a record at one position (§7.1 atomic sealing). A `RepositoryError` may leave it
   * unknown whether the record landed (a timeout after the write, for example); the host then re-reads
   * the tail with `loadTail` before it seals again and adopts the record if it is there.
   *
   * @throws {RepositoryError} If the record could not be durably persisted, or `record.seq` is not the
   *   next position.
   */
  append(partition: string, record: SealedRecord): Promise<void>;

  /** Return the last sealed record of `partition`, or null if it is empty (for resume). */
  loadTail(partition: string): Promise<SealedRecord | null>;

  /**
   * Return every sealed record of `partition` in append order (for resume and verification).
   *
   * This may be large; adapters over a real backend should stream internally. It is the input to
   * `verifyLedger` for a full-chain audit.
   */
  readAll(partition: string): Promise<SealedRecord[]>;
}
