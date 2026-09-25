/**
 * The host-side audit subsystem — a deterministic recording engine (§7).
 *
 * `AuditHost` implements `AuditEndpoint` for exactly one partition (§10.5): it owns one `Ledger`, one
 * `seq` counter, and one anomaly set, and there is no code path that crosses partitions. Multi-tenant
 * deployments instantiate one host per partition and route by connection; that routing is the
 * integrator's concern, above this SDK.
 *
 * The host issues an audit session for each call it audits and closes it when the call ends (§6.3);
 * `signer_seq` is tracked within a session (§7.4). It validates ledger-integrity requirements before
 * sealing (§7.1) and never authorizes the tool's domain action (§2). Under Level 2 it defers signature
 * checking to an injected `SignatureVerifier` (the concrete registry-backed verifier lives in the `l2`
 * layer), while sequence tracking and anomaly flagging are host logic. A persistence failure answers
 * `unavailable`, which decides nothing (§7.1).
 */

import { canonicalize, hasUnsafeNumber, sha256Hex } from './canonical';
import { type Clock, SystemClock } from './clock';
import * as fields from './fields';
import { countersignaturePayload } from './hashing';
import { Ledger, type SealedRecord } from './ledger';
import {
  type AttemptResponse,
  type AuditCapability,
  auditCapabilitySchema,
  Countersign,
  firstValidationError,
  Level,
  Outcome,
  type RejectReason,
  SPEC_VERSION,
} from './models';
import { Mutex } from './mutex';
import * as reasons from './reasons';
import { type LedgerRepository, RepositoryError } from './storage/repository';
import { type AuditEndpoint, accept, reject, unavailable } from './transport';

/** A detected integrity violation or inconsistency in the audit stream (flagged, not always fatal). */
export interface IntegrityAnomaly {
  id: string;
  kind: reasons.Tier1Code;
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
  /** Return a Tier-1 reject reason (`unknown-key` / `signature-invalid`), or null if it verifies (§7.6). */
  verify(event: Record<string, unknown>): Promise<RejectReason | null>;
}

/** Options for constructing an {@link AuditHost}. */
export interface AuditHostOptions {
  verifier?: SignatureVerifier;
  countersigner?: Countersigner;
  /**
   * The name every countersignature gives this partition's chain (§7.1). It must be stable for the
   * chain's lifetime and distinct from every other chain the host keeps; it defaults to the partition.
   */
  logId?: string;
  repository?: LedgerRepository;
  clock?: Clock;
}

/**
 * Countersigns a record this host sealed (§5.2, §7.1).
 *
 * `sign` is async for the same reason `EventSigner.sign` is: a production host signs through a
 * network HSM or KMS. The payload is already canonical (`countersignaturePayload`), so a signer does
 * cryptography only - the preimage is built in one place, by the host.
 */
export interface Countersigner {
  /** The `host_key_id` a verifier's registry binds to this host. */
  readonly keyId: string;
  /** Return the base64url detached signature, without padding, over `payload`. */
  sign(payload: Uint8Array): Promise<string>;
}

/** A partial host self-declaration: unset fields are filled from the SDK's own capability defaults. */
export type AuditCapabilityInput = Partial<AuditCapability>;

function eventId(event: Record<string, unknown>): string {
  const id = event[fields.ID];
  return typeof id === 'string' ? id : '<unknown>';
}

/** A digest of an event's canonical form: two events with one digest are the same bytes (§8.3). */
function digestOf(event: Record<string, unknown>): string {
  return sha256Hex(canonicalize(event));
}

/**
 * One audit session: one tools/call (§6.3).
 *
 * Per key, `decided` is the set of `signer_seq` values the host reached a decision on (the replay
 * window, the whole session) and `received` the highest it received with a verifying signature (the gap
 * bound) (§7.4). `terminal` holds, per operation `id`, the digest of the one outcome sealed for it
 * (§7.2).
 */
interface Session {
  readonly decided: Map<string, Set<number>>;
  readonly received: Map<string, number>;
  readonly accepted: Set<string>;
  readonly terminal: Map<string, string>;
}

function acceptOf(record: SealedRecord): AttemptResponse {
  return accept(record.seq, record.record_hash, record.host_ts, record.previous_hash, {
    hostSignature: record.host_signature,
    hostKeyId: record.host_key_id,
    logId: record.log_id,
  });
}

/** Receives self-attested events and seals valid ones into one partition's tamper-evident ledger. */
export class AuditHost implements AuditEndpoint {
  // Set to false by the integrator when persistence is known to be down; the host also fails closed.
  persistenceAvailable = true;

  readonly #partition: string;
  readonly #logId: string;
  readonly #capability: AuditCapability;
  readonly #ledger: Ledger;
  readonly #verifier: SignatureVerifier | undefined;
  readonly #countersigner: Countersigner | undefined;
  readonly #repository: LedgerRepository | undefined;
  readonly #clock: Clock;
  // One lock per host is one lock per partition (§10.5); §7.1 constrains nothing across them.
  readonly #lock = new Mutex();
  readonly #sessions = new Map<string, Session>();
  // Every session id this host ever issued, open or closed: §6.3 forbids issuing one twice.
  readonly #issued = new Set<string>();
  // Set when a persistence failure left it unknown whether the record landed (§7.1).
  #tailUncertain = false;
  // The partition's sealed attempts by id, so a byte-identical repeat is answered from the ledger
  // (§7.1), and a digest of every sealed event, so none is sealed twice (§8.3).
  readonly #sealedAttempts = new Map<string, SealedRecord>();
  readonly #sealedDigests = new Set<string>();
  readonly #rejectedIds = new Set<string>();
  readonly #anomalies: IntegrityAnomaly[] = [];

  /**
   * Initialize the host for `partition` under a capability, with optional verifier and store.
   *
   * With a `repository`, every accepted record is durably persisted before it is committed and
   * acknowledged; a persistence failure fails closed (§7.1). Use {@link AuditHost.resume} to restart
   * a host from a persisted chain.
   *
   * @throws {Error} If the required level is Level 2 but no `verifier` was provided, or the host
   *   declares `countersign: "host"` but no `countersigner` was provided.
   */
  constructor(partition: string, capability: AuditCapabilityInput = {}, options: AuditHostOptions = {}) {
    // The host's own capability: complete the partial self-declaration with the SDK's explicit
    // defaults, then parse. The schema itself is strict (all fields REQUIRED, §6.1), so a peer
    // capability validated directly is rejected on any omission rather than defaulted.
    const resolved = auditCapabilitySchema.parse({
      spec_version: SPEC_VERSION,
      level: Level.L1,
      attempt: 'request',
      countersign: Countersign.NONE,
      ...capability,
    });
    if (resolved.level === Level.L2 && options.verifier === undefined) {
      throw new Error('an L2 host requires a SignatureVerifier');
    }
    // A host that declares it countersigns and then does not would leave every record uncountersigned
    // while its peers expect otherwise; the declaration is refused at construction instead.
    if (resolved.countersign === Countersign.HOST && options.countersigner === undefined) {
      throw new Error('a host declaring countersign "host" requires a Countersigner');
    }
    // §7.1: a host that declares `none` MUST NOT return the countersignature. Holding a signer while
    // declaring `none` is the only way to violate that, so it is refused here rather than silently
    // ignored at seal time.
    if (resolved.countersign === Countersign.NONE && options.countersigner !== undefined) {
      throw new Error('a host declaring countersign "none" must not hold a Countersigner');
    }
    this.#partition = partition;
    this.#logId = options.logId ?? partition;
    this.#capability = resolved;
    this.#ledger = new Ledger(partition);
    this.#verifier = options.verifier;
    this.#countersigner = options.countersigner;
    this.#repository = options.repository;
    this.#clock = options.clock ?? new SystemClock();
  }

  /**
   * Build a host that continues `partition`'s persisted chain.
   *
   * The chain state (next `seq`, tail link) and what makes a repeat recognizable - the sealed attempts,
   * and a digest of every sealed event - are reconstructed from the stored records, so post-restart
   * appends link correctly and a repeat is still answered from the ledger. Audit sessions are not: a
   * call in flight across the restart has ended as far as this host knows, and its events are refused
   * (§6.3). Reject memory is not persisted either, so an outcome for a pre-restart rejected id is
   * flagged `orphaned-outcome`, as a never-accepted one.
   *
   * A restart ends every call that was in flight, so each sealed attempt with no sealed terminal outcome
   * of the same session and id after it is recorded `unresolved-attempt`, as closing its session would
   * have (§6.3), and its session is not open. Anomalies are held in memory only; an integrator who needs
   * them across restarts persists `anomalies()`.
   */
  static async resume(
    partition: string,
    capability: AuditCapabilityInput = {},
    options: AuditHostOptions & { repository: LedgerRepository },
  ): Promise<AuditHost> {
    const host = new AuditHost(partition, capability, options);
    const records = await options.repository.readAll(partition);
    host.#ledger.resumeFrom(records.length > 0 ? (records[records.length - 1] ?? null) : null);
    for (const record of records) {
      host.#remember(record);
      const sessionId = record.event[fields.SESSION_ID];
      if (typeof sessionId === 'string') {
        host.#issued.add(sessionId);
      }
    }
    host.#flagUnresolved(records);
    return host;
  }

  /** Record every persisted attempt left without a terminal outcome as unresolved (§6.3). */
  #flagUnresolved(records: readonly SealedRecord[]): void {
    const openAttempts = new Map<string, string>();
    for (const record of records) {
      const event = record.event;
      const sessionId = event[fields.SESSION_ID];
      if (typeof sessionId !== 'string' || event[fields.SPEC_VERSION] !== SPEC_VERSION) {
        continue;
      }
      const id = String(event[fields.ID]);
      const key = JSON.stringify([sessionId, id]);
      if (event[fields.OUTCOME] === Outcome.ATTEMPTED) {
        openAttempts.set(key, id);
      } else {
        openAttempts.delete(key);
      }
    }
    for (const id of openAttempts.values()) {
      this.#flag(id, reasons.UNRESOLVED_ATTEMPT, `host restarted with attempt ${id} unresolved`);
    }
  }

  get capability(): AuditCapability {
    return this.#capability;
  }

  /** The name this host's countersignatures give the partition's chain (§7.1). */
  get logId(): string {
    return this.#logId;
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

  /**
   * Issue a fresh audit session for a call this host audits (§6.3).
   *
   * @param sessionId The id to issue. A host mints its own when omitted; a tool acting as its own host
   *   in the degraded posture (§6.2) passes the one it minted for the call.
   * @returns The session id, to send with the call.
   * @throws {Error} The id was already issued, even for a session that has since ended. §6.3 requires one
   *   that was never issued before, and reusing one would let one call's events stand for another's.
   */
  openSession(sessionId?: string): string {
    const issued = sessionId ?? globalThis.crypto.randomUUID();
    if (this.#issued.has(issued)) {
      throw new Error(`audit session ${issued} was already issued (§6.3)`);
    }
    this.#issued.add(issued);
    this.#sessions.set(issued, { decided: new Map(), received: new Map(), accepted: new Set(), terminal: new Map() });
    return issued;
  }

  /**
   * Close an audit session because its call ended (§6.3).
   *
   * Every outcome of the session has been delivered by then (§6), so an attempt this host accepted that
   * has no sealed terminal outcome was never resolved; it is recorded `unresolved-attempt`. The session
   * accepts nothing further.
   */
  async closeSession(sessionId: string): Promise<void> {
    await this.#lock.run(async () => {
      const session = this.#sessions.get(sessionId);
      if (session === undefined) {
        return;
      }
      this.#sessions.delete(sessionId);
      for (const id of [...session.accepted].filter((accepted) => !session.terminal.has(accepted)).sort()) {
        this.#flag(id, reasons.UNRESOLVED_ATTEMPT, `call ended with attempt ${id} unresolved`);
      }
    });
  }

  /** Hold an audit session open for the span of one call (§6.3). */
  async withSession<T>(body: (sessionId: string) => Promise<T>, sessionId?: string): Promise<T> {
    const issued = this.openSession(sessionId);
    try {
      return await body(issued);
    } finally {
      await this.closeSession(issued);
    }
  }

  #flag(id: string, kind: reasons.Tier1Code, detail: string): void {
    this.#anomalies.push({ id, kind, detail });
  }

  /** Note a sealed record so that a repeat of it is recognized (§7.1, §8.3). */
  #remember(record: SealedRecord): void {
    this.#sealedDigests.add(digestOf(record.event));
    if (record.event[fields.OUTCOME] === Outcome.ATTEMPTED) {
      this.#sealedAttempts.set(eventId(record.event), record);
    }
  }

  /**
   * Settle a tail a failed `append` left in doubt, before sealing on top of it (§7.1).
   *
   * A `RepositoryError` does not say whether the record landed. The repository's tail says: the host's
   * own tail means it did not; the record after it means it did, and the host adopts it rather than seal
   * a second record at the same `seq`; anything else is a chain this host does not know, and it records
   * nothing more until that is resolved.
   *
   * @returns True when the chain is known and sealing may proceed.
   */
  async #settleTail(repository: LedgerRepository): Promise<boolean> {
    let tail: SealedRecord | null;
    try {
      tail = await repository.loadTail(this.#partition);
    } catch (error) {
      if (error instanceof RepositoryError) {
        return false;
      }
      throw error;
    }
    const length = this.#ledger.length;
    const digest = this.#ledger.digest();
    const unchanged = tail === null ? length === 0 : tail.seq === length - 1 && tail.record_hash === digest;
    if (!unchanged) {
      if (tail === null || tail.seq !== length || tail.previous_hash !== digest) {
        console.error(`auditable-mcp: the stored tail of partition ${this.#partition} does not continue this chain`);
        return false;
      }
      this.#ledger.commit(tail);
      this.#remember(tail);
      const event = tail.event;
      const session = this.#sessions.get(String(event[fields.SESSION_ID]));
      if (session !== undefined && event[fields.OUTCOME] === Outcome.ATTEMPTED) {
        session.accepted.add(eventId(event));
      }
    }
    this.#tailUncertain = false;
    return true;
  }

  /** True when the chain is known, settling a tail in doubt first; false leaves nothing to seal on. */
  async #chainKnown(): Promise<boolean> {
    return !this.#tailUncertain || this.#repository === undefined || this.#settleTail(this.#repository);
  }

  /** Seal `event`, persist it if a repository is configured, then commit; null on persistence failure. */
  async #seal(event: Record<string, unknown>, hostTs: string): Promise<SealedRecord | null> {
    let sealed = this.#ledger.seal(event, hostTs);
    // Sign before persisting, so the countersignature is stored with the record it covers (§7.1, §7.2).
    if (this.#countersigner !== undefined) {
      const payload = countersignaturePayload(
        sealed.seq,
        sealed.host_ts,
        this.#logId,
        sealed.previous_hash,
        sealed.record_hash,
      );
      let signature: string;
      try {
        signature = await this.#countersigner.sign(payload);
      } catch (error) {
        // A host that declared it countersigns cannot record conformantly without the countersignature,
        // so a signer failure is a host-internal failure and fails closed as `unavailable` (§7.1, §7.6
        // `internal-error`) - never an exception through the audit path. The catch is broad on purpose:
        // the signer is injected third-party code (an HSM or KMS client) whose error types this SDK
        // does not know, and letting any of them escape leaves the tool with no fail-closed signal.
        console.error(`auditable-mcp: countersigning failed for partition ${this.#partition}; failing closed`, error);
        return null;
      }
      sealed = { ...sealed, host_signature: signature, host_key_id: this.#countersigner.keyId, log_id: this.#logId };
    }
    if (this.#repository !== undefined) {
      try {
        await this.#repository.append(this.#partition, sealed);
      } catch (error) {
        if (error instanceof RepositoryError) {
          this.#tailUncertain = true;
          return null;
        }
        throw error;
      }
    }
    this.#ledger.commit(sealed);
    this.#remember(sealed);
    return sealed;
  }

  /** The open audit session the event names, if it is the one it arrived on (§6.3). */
  #sessionOf(event: Record<string, unknown>, expected: string | undefined): Session | null {
    const sessionId = event[fields.SESSION_ID];
    const session = typeof sessionId === 'string' ? this.#sessions.get(sessionId) : undefined;
    if (session === undefined || (expected !== undefined && sessionId !== expected)) {
      this.#flag(
        eventId(event),
        reasons.REPLAY_DETECTED,
        `session ${String(sessionId)} is not the one this call carries (§6.3)`,
      );
      return null;
    }
    return session;
  }

  /**
   * Verify an L2 signature (§7.1 step 3); return a reject reason, or null (no-op under L1).
   *
   * Once the signature verifies, the event counts as received: a value more than one past the highest
   * received - or a first value other than 0 - is flagged, and not rejected (§7.4).
   */
  async #verifySignature(event: Record<string, unknown>, session: Session): Promise<RejectReason | null> {
    if (this.#capability.level !== Level.L2) {
      return null;
    }
    // `unknown-key` and `l2-unsigned` are reject reasons, not anomaly kinds: a missing signature or an
    // unknown key is recorded as `signature-invalid` (§6, §7.6).
    const keyId = event[fields.KEY_ID];
    const signature = event[fields.SIGNATURE];
    const signerSeq = event[fields.SIGNER_SEQ];
    if (!signature || typeof keyId !== 'string' || typeof signerSeq !== 'number' || !Number.isInteger(signerSeq)) {
      this.#flag(eventId(event), reasons.SIGNATURE_INVALID, 'L2 requires signature, key_id, and signer_seq');
      return reasons.L2_UNSIGNED;
    }
    // A verifier is guaranteed present under L2 (enforced in the constructor).
    const reason = await (this.#verifier as SignatureVerifier).verify(event);
    if (reason !== null) {
      this.#flag(eventId(event), reasons.SIGNATURE_INVALID, `signature verification failed (${reason})`);
      return reason;
    }
    const received = session.received.get(keyId);
    const expected = received === undefined ? 0 : received + 1;
    if (signerSeq > expected) {
      this.#flag(eventId(event), reasons.SIGNER_SEQ_GAP, `expected signer_seq ${expected}, got ${signerSeq}`);
    }
    if (received === undefined || signerSeq > received) {
      session.received.set(keyId, signerSeq);
    }
    return null;
  }

  /** Reject a `signer_seq` the host already decided for its key in this session (§7.1 step 5, §7.4). */
  #checkReplay(event: Record<string, unknown>, session: Session): RejectReason | null {
    const keyId = event[fields.KEY_ID];
    const signerSeq = event[fields.SIGNER_SEQ];
    if (this.#capability.level !== Level.L2 || typeof keyId !== 'string' || typeof signerSeq !== 'number') {
      return null;
    }
    if (session.decided.get(keyId)?.has(signerSeq) === true) {
      this.#flag(eventId(event), reasons.REPLAY_DETECTED, `signer_seq ${signerSeq} was already decided`);
      return reasons.REPLAY_DETECTED;
    }
    return null;
  }

  /** Record a decision: the host sealed the event, or refused it after its signature verified (§7.4). */
  #decide(event: Record<string, unknown>, session: Session): void {
    const keyId = event[fields.KEY_ID];
    const signerSeq = event[fields.SIGNER_SEQ];
    if (this.#capability.level !== Level.L2 || typeof keyId !== 'string' || typeof signerSeq !== 'number') {
      return;
    }
    const decided = session.decided.get(keyId) ?? new Set<number>();
    decided.add(signerSeq);
    session.decided.set(keyId, decided);
  }

  /** Structure, the canonicalization domain, and the session (§7.1 steps 1 and 2). */
  #admit(event: Record<string, unknown>, expected: string | undefined, attempt: boolean): Session | RejectReason {
    const error = firstValidationError(event);
    if (error !== null) {
      this.#flag(eventId(event), reasons.SCHEMA_INVALID, error);
      return reasons.SCHEMA_INVALID;
    }
    // Not canonicalizable (§8.1): reject gracefully (rolls up to schema-invalid) instead of throwing.
    if (hasUnsafeNumber(event)) {
      this.#flag(eventId(event), reasons.SCHEMA_INVALID, 'a numeric value is not canonicalizable (§8.1)');
      return reasons.SCHEMA_INVALID;
    }
    // An attempt carries `attempted` and an outcome does not (§6); either way round is structural, which
    // §7.1 checks before the session. Tier-2 detail, Tier-1 `schema-invalid` (§7.6).
    if ((event[fields.OUTCOME] === Outcome.ATTEMPTED) !== attempt) {
      const detail = attempt ? 'an attempt must carry outcome=attempted' : 'an outcome carried outcome=attempted (§6)';
      this.#flag(eventId(event), reasons.SCHEMA_INVALID, detail);
      return reasons.SCHEMA_INVALID;
    }
    return this.#sessionOf(event, expected) ?? reasons.REPLAY_DETECTED;
  }

  /**
   * Validate and, if durable, seal an attempt; otherwise reject or fail closed (§7.1).
   *
   * Held under the partition's lock: §7.1 requires the assignment of `seq` and `previous_hash`, the
   * seal, and the commit to be atomic with respect to every other record being sealed into the same
   * partition. Signing and persistence sit between those steps, so without the lock two attempts read
   * the same chain tail and take the same position - and the host answers `accept` to both. The
   * attempt `id`-uniqueness check (§7.1) is inside the same section for the same reason.
   *
   * @param sessionId The audit session of the call the attempt arrived on, when the binding knows it;
   *   the event must carry it (§6.3).
   * @param deadline A time in `Date.now()` milliseconds after which the binding has already answered the
   *   tool `unavailable` (§6.4). Taken up after it, the attempt is answered `unavailable` and nothing is
   *   recorded: the call it belongs to may have ended, and deciding it then would seal an operation the
   *   tool was told was not recorded, or refuse it against a session that closed while it waited. A
   *   decision already under way is not undone.
   */
  async handleAttempt(event: Record<string, unknown>, sessionId?: string, deadline?: number): Promise<AttemptResponse> {
    return this.#lock.run(async () => {
      if (deadline !== undefined && Date.now() >= deadline) {
        return unavailable();
      }
      return this.#handleAttempt(event, sessionId);
    });
  }

  async #handleAttempt(event: Record<string, unknown>, expected: string | undefined): Promise<AttemptResponse> {
    // Settled before the uniqueness check, so a repeat of an attempt that did land is answered from it.
    if (!(await this.#chainKnown())) {
      return unavailable();
    }
    const admitted = this.#admit(event, expected, true);
    if (typeof admitted === 'string') {
      return reject(admitted);
    }
    const session = admitted;
    const id = eventId(event);
    const reason = await this.#verifySignature(event, session);
    if (reason !== null) {
      this.#rejectedIds.add(id);
      return reject(reason);
    }
    // §7.1 step 4: a sealed id answers a byte-identical repeat from the ledger, and is a replay otherwise.
    // The repeat is what makes an attempt safe to send again.
    const sealed = this.#sealedAttempts.get(id);
    if (sealed !== undefined) {
      if (canonicalize(sealed.event) === canonicalize(event)) {
        // Byte-identical, so the same session: the operation it clears is this session's to resolve.
        session.accepted.add(id);
        return acceptOf(sealed);
      }
      this.#rejectedIds.add(id);
      this.#decide(event, session);
      this.#flag(id, reasons.REPLAY_DETECTED, 'attempt id already sealed with a different event');
      return reject(reasons.REPLAY_DETECTED);
    }
    // The operation has concluded - its outcome is sealed - so no attempt is sealed after its own terminal
    // record, whether or not an attempt for it was ever accepted.
    if (session.terminal.has(id)) {
      this.#rejectedIds.add(id);
      this.#decide(event, session);
      this.#flag(id, reasons.REPLAY_DETECTED, 'the operation already has a sealed outcome');
      return reject(reasons.REPLAY_DETECTED);
    }
    const replay = this.#checkReplay(event, session);
    if (replay !== null) {
      this.#rejectedIds.add(id);
      this.#decide(event, session);
      return reject(replay);
    }
    if (!this.persistenceAvailable) {
      // Nothing is decided, so the identical attempt may come again (§7.1).
      return unavailable();
    }
    const record = await this.#seal(event, this.#clock.now());
    if (record === null) {
      // Persistence failed after validation: nothing is decided, and the tool must not act.
      return unavailable();
    }
    this.#decide(event, session);
    session.accepted.add(id);
    // Verifiable Accept (§7.1): the host-assigned fields the tool needs for Polluted Stop, and the
    // countersignature where the host countersigns.
    return acceptOf(record);
  }

  /**
   * Seal an outcome, or drop and record it (§7.2). An outcome has no response (§6).
   *
   * Held under the same lock as `handleAttempt`: an outcome seals into the same chain (§8.3).
   */
  async handleOutcome(event: unknown, sessionId?: string): Promise<void> {
    await this.#lock.run(async () => {
      if (event === null || typeof event !== 'object') {
        this.#flag('<unknown>', reasons.SCHEMA_INVALID, 'an event must be a JSON object (§4)');
        return;
      }
      // An array reaches `#admit` and fails the event schema there.
      await this.#handleOutcome(event as Record<string, unknown>, sessionId);
    });
  }

  /**
   * §7.2's order, which is §7.1's: structure and session (`#admit`), signature, uniqueness per operation,
   * sequence - and only then correlation. Each drop is recorded under the anomaly kind for its condition
   * (§6).
   */
  async #handleOutcome(event: Record<string, unknown>, expected: string | undefined): Promise<void> {
    if (!(await this.#chainKnown())) {
      console.error(`auditable-mcp: outcome id=${eventId(event)} not recorded; the chain tail is in doubt (§10.8)`);
      return;
    }
    const admitted = this.#admit(event, expected, false);
    if (typeof admitted === 'string') {
      return;
    }
    const session = admitted;
    const id = eventId(event);
    const outcome = event[fields.OUTCOME];
    if ((await this.#verifySignature(event, session)) !== null) {
      return;
    }
    // One terminal record per (session_id, id): a byte-identical repeat is not processed further (§8.3),
    // and one that differs is a replay (§7.2).
    const digest = digestOf(event);
    const terminal = session.terminal.get(id);
    if (this.#sealedDigests.has(digest) || terminal === digest) {
      return;
    }
    if (terminal !== undefined) {
      this.#decide(event, session);
      this.#flag(id, reasons.REPLAY_DETECTED, 'differs from the outcome already sealed for this operation');
      return;
    }
    if (this.#checkReplay(event, session) !== null) {
      return;
    }
    const correlated = session.accepted.has(id);
    // §7.2: a success or failed outcome with no accepted attempt is not sealed. Both never-accepted and
    // post-reject orphans roll up to orphaned-outcome; the distinction is a Tier-2 detail.
    if (!correlated && outcome !== Outcome.ABORTED) {
      this.#decide(event, session);
      const sub = this.#rejectedIds.has(id) ? 'for a rejected id' : 'without an accepted attempt';
      this.#flag(id, reasons.ORPHANED_OUTCOME, `outcome=${String(outcome)} ${sub}`);
      return;
    }
    // A correlated outcome is its operation's terminal record; an aborted outcome of an attempt the host
    // did not accept is the record of an operation the tool declined to perform (§7.2, §10.4).
    const record = this.persistenceAvailable ? await this.#seal(event, this.#clock.now()) : null;
    if (record === null) {
      // An outcome has no response, so a persistence failure cannot be returned. It is a completeness gap
      // (§10.8), not a ledger integrity anomaly, and `internal-error` is not a Tier-1 anomaly kind
      // (§7.6): log it rather than flag the anomaly set with an out-of-space code.
      // Failing to record is not a decision, as `unavailable` is not for an attempt (§7.4).
      console.error(`auditable-mcp: could not persist outcome id=${id}; outcome lost (completeness gap, §10.8)`);
      return;
    }
    this.#decide(event, session);
    session.terminal.set(id, digest);
  }
}
