/**
 * The host-side audit subsystem — a deterministic recording engine (§7).
 *
 * `AuditHost` implements `AuditEndpoint` for exactly one partition (§10.5): it owns one `Ledger`, one
 * `seq` counter, one per-`key_id` sequence tracker, and one anomaly set, and there is no code path
 * that crosses partitions. Multi-tenant deployments instantiate one host per partition and route by
 * connection; that routing is the integrator's concern, above this SDK.
 *
 * The host validates ledger-integrity requirements before sealing (§7.1); it never authorizes the
 * tool's domain action (§2). Under Level 2 it defers signature checking to an injected
 * `SignatureVerifier` (the concrete Ed25519 verifier lives in the `l2` layer), while sequence
 * tracking and anomaly flagging are host logic. A persistence failure fails closed with a retryable
 * `unavailable` (§7.1).
 */

import { hasUnsafeNumber } from './canonical';
import { type Clock, SystemClock } from './clock';
import * as fields from './fields';
import { Ledger, type SealedRecord } from './ledger';
import { type AttemptResponse, type AuditCapability, firstValidationError, Level, Outcome } from './models';
import * as reasons from './reasons';
import { type LedgerRepository, RepositoryError } from './storage/repository';
import { type AuditEndpoint, accept, reject, unavailable } from './transport';

/** A detected integrity violation or inconsistency in the audit stream (flagged, not always fatal). */
export interface IntegrityAnomaly {
  id: string;
  kind: string;
  detail: string;
}

/**
 * Verifies a Level-2 detached signature over canonical(event − signature) (§8.2).
 *
 * The concrete verifiers (with their key registries) live in the `l2` layer, keeping the host free of
 * any cryptography dependency. `verify` is async because a production verifier may call a network
 * KMS; a local verifier just resolves synchronously under the async signature.
 */
export interface SignatureVerifier {
  /** Return a reject reason (e.g. `unknown-key`, `signature-invalid`), or null if the signature verifies. */
  verify(event: Record<string, unknown>): Promise<string | null>;
}

/** Options for constructing an {@link AuditHost}. */
export interface AuditHostOptions {
  verifier?: SignatureVerifier;
  repository?: LedgerRepository;
  clock?: Clock;
}

const DEFAULT_CAPABILITY: AuditCapability = { level: Level.L1, attempt: 'request' };

function eventId(event: Record<string, unknown>): string {
  const id = event[fields.ID];
  return typeof id === 'string' ? id : '<unknown>';
}

/** Receives self-attested events and seals valid ones into one partition's tamper-evident ledger. */
export class AuditHost implements AuditEndpoint {
  // Set to false by the integrator when persistence is known to be down; the host also fails closed.
  persistenceAvailable = true;

  readonly #partition: string;
  readonly #capability: AuditCapability;
  readonly #ledger: Ledger;
  readonly #verifier: SignatureVerifier | undefined;
  readonly #repository: LedgerRepository | undefined;
  readonly #clock: Clock;
  readonly #acceptedAttempts = new Set<string>();
  readonly #rejectedIds = new Set<string>();
  readonly #lastSeqByKey = new Map<string, number>();
  readonly #anomalies: IntegrityAnomaly[] = [];

  /**
   * Initialize the host for `partition` under a capability, with optional verifier and store.
   *
   * With a `repository`, every accepted record is durably persisted before it is committed and
   * acknowledged; a persistence failure fails closed (§7.1). Use {@link AuditHost.resume} to restart
   * a host from a persisted chain.
   *
   * @throws {Error} If the required level is Level 2 but no `verifier` was provided.
   */
  constructor(partition: string, capability: AuditCapability = DEFAULT_CAPABILITY, options: AuditHostOptions = {}) {
    if (capability.level === Level.L2 && options.verifier === undefined) {
      throw new Error('an L2 host requires a SignatureVerifier');
    }
    this.#partition = partition;
    this.#capability = capability;
    this.#ledger = new Ledger(partition);
    this.#verifier = options.verifier;
    this.#repository = options.repository;
    this.#clock = options.clock ?? new SystemClock();
  }

  /**
   * Build a host that continues `partition`'s persisted chain.
   *
   * The chain state (next `seq`, tail link) and the L2 replay/sequence state are reconstructed from
   * the stored records, so post-restart appends link correctly and replays are still caught. Reject
   * memory (`outcome-after-reject`) is not persisted, so an outcome for a pre-restart rejected id
   * degrades to `outcome-without-attempt`.
   */
  static async resume(
    partition: string,
    capability: AuditCapability = DEFAULT_CAPABILITY,
    options: AuditHostOptions & { repository: LedgerRepository },
  ): Promise<AuditHost> {
    const host = new AuditHost(partition, capability, options);
    const records = await options.repository.readAll(partition);
    host.#ledger.resumeFrom(records.length > 0 ? (records[records.length - 1] ?? null) : null);
    for (const record of records) {
      if (record.event[fields.OUTCOME] === Outcome.ATTEMPTED) {
        host.#acceptedAttempts.add(eventId(record.event));
      }
      host.#advanceSeq(record.event);
    }
    return host;
  }

  get capability(): AuditCapability {
    return this.#capability;
  }

  /** Return the detected integrity anomalies. */
  anomalies(): IntegrityAnomaly[] {
    return [...this.#anomalies];
  }

  /** Return the sealed ledger records for this partition. */
  records(): SealedRecord[] {
    return this.#ledger.records();
  }

  /** Return this partition's anchorable tail digest (§8.3). */
  digest(): string {
    return this.#ledger.digest();
  }

  #flag(id: string, kind: string, detail: string): void {
    this.#anomalies.push({ id, kind, detail });
  }

  /** Seal `event`, persist it if a repository is configured, then commit; null on persistence failure. */
  async #seal(event: Record<string, unknown>, hostTs: string): Promise<SealedRecord | null> {
    const sealed = this.#ledger.seal(event, hostTs);
    if (this.#repository !== undefined) {
      try {
        await this.#repository.append(this.#partition, sealed);
      } catch (error) {
        if (error instanceof RepositoryError) {
          return null;
        }
        throw error;
      }
    }
    this.#ledger.commit(sealed);
    return sealed;
  }

  /**
   * Verify the L2 signature and per-key sequence; return a reject reason, or null (no-op under L1).
   *
   * Unsigned / unknown-key / forged / replayed records are rejected. A forward sequence gap is flagged
   * but not rejected — the missing event cannot be recovered (§7.4).
   */
  async #checkL2(event: Record<string, unknown>): Promise<string | null> {
    if (this.#capability.level !== Level.L2) {
      return null;
    }
    const keyId = event[fields.KEY_ID];
    const signature = event[fields.SIGNATURE];
    const sequence = event[fields.SEQUENCE];
    if (!signature || typeof keyId !== 'string' || typeof sequence !== 'number' || !Number.isInteger(sequence)) {
      this.#flag(eventId(event), reasons.L2_UNSIGNED, 'L2 requires signature, key_id, and sequence');
      return reasons.L2_UNSIGNED;
    }
    // A verifier is guaranteed present under L2 (enforced in the constructor).
    const reason = await (this.#verifier as SignatureVerifier).verify(event);
    if (reason !== null) {
      this.#flag(eventId(event), reason, 'signature verification failed');
      return reason;
    }
    // The first event from a key only establishes the baseline: with no prior observation there is
    // nothing to have skipped, so neither replay nor gap applies (a tool's per-key start is arbitrary,
    // and cross-partition interleaving makes it unknowable from one partition, §10.5).
    const last = this.#lastSeqByKey.get(keyId);
    if (last !== undefined) {
      if (sequence <= last) {
        this.#flag(eventId(event), reasons.SIGNER_SEQUENCE_REPLAY, `sequence ${sequence} <= last ${last}`);
        return reasons.SIGNER_SEQUENCE_REPLAY;
      }
      if (sequence > last + 1) {
        this.#flag(
          eventId(event),
          reasons.SIGNER_SEQUENCE_GAP,
          `expected ${last + 1}, got ${sequence} (suppressed event)`,
        );
      }
    }
    return null;
  }

  /** Advance the per-key sequence tracker after a record is sealed (follows accepted, not seen). */
  #advanceSeq(event: Record<string, unknown>): void {
    const keyId = event[fields.KEY_ID];
    const sequence = event[fields.SEQUENCE];
    if (typeof keyId === 'string' && typeof sequence === 'number' && Number.isInteger(sequence)) {
      this.#lastSeqByKey.set(keyId, sequence);
    }
  }

  /** Validate and, if durable, seal an attempt; otherwise reject or fail closed (§7.1). */
  async handleAttempt(event: Record<string, unknown>): Promise<AttemptResponse> {
    const error = firstValidationError(event);
    if (error !== null) {
      this.#flag(eventId(event), reasons.SCHEMA_INVALID, error);
      return reject(reasons.SCHEMA_INVALID);
    }
    if (event[fields.OUTCOME] !== Outcome.ATTEMPTED) {
      this.#flag(eventId(event), reasons.SCHEMA_INVALID, 'an attempt must carry outcome=attempted');
      return reject(reasons.ATTEMPT_MUST_BE_ATTEMPTED);
    }
    // Not canonicalizable (§8.1): reject gracefully instead of throwing at seal time.
    if (hasUnsafeNumber(event)) {
      this.#flag(eventId(event), reasons.NUMERIC_DOMAIN, 'a numeric value is not canonicalizable (§8.1)');
      return reject(reasons.NUMERIC_DOMAIN);
    }
    const l2Reason = await this.#checkL2(event);
    if (l2Reason !== null) {
      this.#rejectedIds.add(eventId(event));
      return reject(l2Reason);
    }
    if (!this.persistenceAvailable) {
      // Fail closed: the tool must not act on an unpersisted record.
      return unavailable(reasons.PERSISTENCE_FAILURE);
    }
    const id = eventId(event);
    if (this.#acceptedAttempts.has(id)) {
      this.#rejectedIds.add(id);
      this.#flag(id, reasons.ATTEMPT_REPLAY, 'duplicate attempt id');
      return reject(reasons.ATTEMPT_REPLAY);
    }
    const sealed = await this.#seal(event, this.#clock.now());
    if (sealed === null) {
      // Persistence failed after validation: fail closed so the tool retries (not accepted).
      return unavailable(reasons.PERSISTENCE_FAILURE);
    }
    this.#acceptedAttempts.add(id);
    this.#advanceSeq(event);
    // Verifiable Accept (§7.1): return the host-assigned fields the tool needs for Polluted Stop.
    return accept(sealed.seq, sealed.record_hash, sealed.host_ts, sealed.previous_hash);
  }

  /** Seal a correlated outcome, or flag an uncorrelated one; drop invalid records (§7.2). */
  async handleOutcome(event: Record<string, unknown>): Promise<void> {
    const error = firstValidationError(event);
    if (error !== null) {
      this.#flag(eventId(event), reasons.SCHEMA_INVALID, error);
      return;
    }
    if (hasUnsafeNumber(event)) {
      this.#flag(eventId(event), reasons.NUMERIC_DOMAIN, 'a numeric value is not canonicalizable (§8.1)');
      return;
    }
    const id = eventId(event);
    const outcome = event[fields.OUTCOME];
    // §10.4: a fail-closed aborted outcome for a never-accepted attempt is the honest refused-action
    // signal, not a tampering anomaly. Exempt it before #checkL2 so a fresh signer sequence that
    // outran the unsealed attempt is not flagged as a suppression gap.
    if (outcome === Outcome.ABORTED && !this.#acceptedAttempts.has(id)) {
      return;
    }
    if ((await this.#checkL2(event)) !== null) {
      return;
    }
    if (this.#acceptedAttempts.has(id)) {
      // Correlated outcomes are sealed, not de-duplicated (§8.3). An outcome is a notification with no
      // response channel, so a persistence failure is flagged, not returned.
      const sealed = await this.#seal(event, this.#clock.now());
      if (sealed === null) {
        this.#flag(id, reasons.PERSISTENCE_FAILURE, 'could not persist outcome');
        return;
      }
      this.#advanceSeq(event);
      return;
    }
    if (this.#rejectedIds.has(id)) {
      this.#flag(id, reasons.OUTCOME_AFTER_REJECT, `outcome=${String(outcome)} for rejected id`);
    } else {
      this.#flag(id, reasons.OUTCOME_WITHOUT_ATTEMPT, `outcome=${String(outcome)} without accepted attempt`);
    }
  }
}
