/**
 * Sealed records and the per-partition tamper-evident hash chain (§8.3, §10.5).
 *
 * A `Ledger` instance is exactly one partition: an append-only chain with its own `seq` counter and
 * genesis. Partition isolation (§10.5) is achieved by holding a separate `Ledger` per partition and
 * never appending a record to the wrong one — records, sequences, and anomalies never cross. This
 * module is a pure in-memory primitive; durable storage is a separate adapter concern.
 */

import { computeRecordHash, GENESIS_HASH } from './hashing';

/**
 * A tool-emitted event plus the host-assigned ledger fields (§7.1, §8.2).
 *
 * The field names are the persisted / wire shape (matching the golden chain vector) so a record is
 * directly JSON-serializable with no transformation: an adapter stores and reloads it as-is, and the
 * bytes the record hash is bound to never shift. `event` is the exact wire form (absent optionals
 * omitted).
 */
export interface SealedRecord {
  readonly event: Record<string, unknown>;
  readonly seq: number;
  readonly host_ts: string;
  readonly previous_hash: string;
  readonly record_hash: string;
}

/** An append-only, single-partition, tamper-evident ledger. */
export class Ledger {
  readonly partition: string;

  // Chain state is tracked independently of the held records so a durable ledger can resume from a
  // persisted tail without loading the whole history into memory.
  #records: SealedRecord[] = [];
  #count = 0;
  #tailHash = GENESIS_HASH;

  constructor(partition: string) {
    this.partition = partition;
  }

  /** The number of sealed records in the chain (including any resumed prefix). */
  get length(): number {
    return this.#count;
  }

  /**
   * Compute the next sealed record without committing it (§8.3).
   *
   * Splitting seal from commit lets the host persist the record durably before accepting it, so a
   * persistence failure leaves the in-memory chain untouched.
   */
  seal(event: Record<string, unknown>, hostTs: string): SealedRecord {
    return {
      event,
      seq: this.#count,
      host_ts: hostTs,
      previous_hash: this.#tailHash,
      record_hash: computeRecordHash(event, this.#count, hostTs, this.#tailHash),
    };
  }

  /** Append a record produced by `seal`, advancing the chain state and the tail. */
  commit(record: SealedRecord): void {
    this.#records.push(record);
    this.#count += 1;
    this.#tailHash = record.record_hash;
  }

  /** Seal and commit `event` in one step (the in-memory path). */
  append(event: Record<string, unknown>, hostTs: string): SealedRecord {
    const sealed = this.seal(event, hostTs);
    this.commit(sealed);
    return sealed;
  }

  /**
   * Restore the chain state from a persisted tail, holding no history in memory.
   *
   * After resume, `records()` returns only records sealed in this process; the full history lives in
   * the repository. `seq` and the tail link continue from where the persisted chain left off.
   */
  resumeFrom(tail: SealedRecord | null): void {
    this.#records = [];
    if (tail !== null) {
      this.#count = tail.seq + 1;
      this.#tailHash = tail.record_hash;
    } else {
      this.#count = 0;
      this.#tailHash = GENESIS_HASH;
    }
  }

  /** Return the records held in memory (a copy); a resumed ledger holds only new ones. */
  records(): SealedRecord[] {
    return [...this.#records];
  }

  /** Return the tail record hash — the anchorable ledger digest (genesis if empty, §8.3). */
  digest(): string {
    return this.#tailHash;
  }
}
