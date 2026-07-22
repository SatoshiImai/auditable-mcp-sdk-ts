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
   * Durably append `record` to `partition`.
   *
   * @throws {RepositoryError} If the record could not be durably persisted.
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
