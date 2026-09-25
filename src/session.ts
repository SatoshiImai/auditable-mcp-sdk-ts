/**
 * The tool-side audit-before-act session — the `await using` core.
 *
 * `AuditedAction` is the source of truth for the tool lifecycle, enforced at the language level via
 * explicit resource management:
 *
 * - Acquisition (`await session.action(...)`) emits the attempt, awaits the host response, and
 *   (under Level 2, or when opted in) performs the Polluted Stop check (§7.2). If the host does not
 *   `accept`, or the recomputed record hash does not match, it emits an `aborted` outcome and throws
 *   `AmcpAbortedError` — so under `await using` the block body never runs. This is the audit-before-act
 *   guarantee (§11.3).
 * - Disposal (`Symbol.asyncDispose`) emits the terminal outcome. Unlike Python's `__aexit__`, the
 *   disposer cannot observe whether the block threw, so it fails closed: it emits `failed` unless the
 *   caller explicitly called `succeeded()`. This makes a forgotten call or an escaping exception a
 *   `failed` record, never a silent `success`. The `withAudit` wrapper (with-audit.ts) restores the
 *   automatic success/failed mapping by wrapping the body in try/catch.
 *
 * `AmcpSession` is one audit session - one `tools/call` (§6.3). It binds a transport, the session's
 * id, id/time sources, and an optional Level-2 signer, and numbers the events it signs from 0 (§7.4).
 * Level 1 and Level 2 emission are identical; Level 2 only adds the signer.
 */

import { hashCanonical } from './canonical';
import { type Clock, nowIso } from './clock';
import { computeRecordHash, countersignaturePayload } from './hashing';
import {
  type AcceptResponse,
  type AttemptResponse,
  auditEventSchema,
  Outcome,
  SESSION_ID_PATTERN,
  SPEC_VERSION,
  Status,
  type TargetResource,
  targetResourceSchema,
} from './models';
import { Mutex } from './mutex';
import * as reasons from './reasons';
import { AmcpUsageError, type AuditTransport, unavailable } from './transport';

const SESSION_ID_REGEX = new RegExp(SESSION_ID_PATTERN);

/**
 * Stamps an event with `key_id`, `sequence`, and `signature` (Level 2, §5, §8.2).
 *
 * `sign` is async because a production signer typically calls a network HSM/KMS; a local signer just
 * resolves synchronously under the async signature.
 */
export interface EventSigner {
  /** The `key_id` this signer stamps, which names the sequence it advances in a session (§7.4). */
  readonly keyId: string;
  sign(event: Record<string, unknown>, signerSeq: number): Promise<Record<string, unknown>>;
}

/** A `Clock` that also mints event ids (the session's tool-side id/time source). */
export interface Deps extends Clock {
  newId(): string;
}

/** Production id/time source: a random UUIDv4 (Web Crypto) and the system clock. */
export class SystemDeps implements Deps {
  newId(): string {
    return globalThis.crypto.randomUUID();
  }
  now(): string {
    return nowIso();
  }
}

/** Mint an audit session id, for a tool acting as its own host in the degraded posture (§6.2, §6.3). */
export function newSessionId(): string {
  return globalThis.crypto.randomUUID();
}

/**
 * The `signer_seq` numbering of one audit session, and the section that numbers and emits atomically
 * (§7.4).
 *
 * It belongs to the session, not to one `AmcpSession` object: a transport that serves one call through
 * several requests or several `AmcpSession`s hands every one of them the same instance (`numbering` on
 * the transport), so the call is numbered once, from 0.
 */
export class SessionNumbering {
  readonly #lock = new Mutex();
  #next = 0;

  /** The `signer_seq` the next emitted event takes. */
  get next(): number {
    return this.#next;
  }

  /**
   * Hold the numbering across `body`'s emission, and advance it only if that emitted.
   *
   * A body that threw never reached the host, so the number it was given is still unused - advancing
   * anyway would leave a gap the host reads as a suppressed event (§7.4).
   */
  run<T>(body: (signerSeq: number) => Promise<T>): Promise<T> {
    return this.#lock.run(async () => {
      const signerSeq = this.#next;
      const result = await body(signerSeq);
      this.#next = signerSeq + 1;
      return result;
    });
  }
}

/** A transport that carries its session's numbering (§7.4). */
interface NumberedTransport {
  readonly numbering: SessionNumbering;
}

function numberingOf(transport: AuditTransport): SessionNumbering {
  const carried = (transport as Partial<NumberedTransport>).numbering;
  return carried instanceof SessionNumbering ? carried : new SessionNumbering();
}

/**
 * Number and emit under the session's section (Level 2), or emit unnumbered (Level 1).
 *
 * Level 1 numbers nothing, so it takes no section: serializing it would cost concurrency the
 * specification does not ask for.
 */
function numbering<T>(session: AmcpSession, body: (signerSeq?: number) => Promise<T>): Promise<T> {
  if (session._signer === undefined) {
    return body(undefined);
  }
  return session._numbering.run(body);
}

/**
 * The tool's own fail-closed halt: the domain action was not performed (outcome=aborted).
 *
 * Named for the tool's abort, not host "blocking" — the host never prevents a domain action (§2). A
 * tool surfaces this as a `tools/call` error result.
 */
export class AmcpAbortedError extends Error {
  readonly actionType: string;
  readonly targetRef: string;
  readonly reason: string;

  constructor(actionType: string, targetRef: string, reason: string) {
    super(`auditable-mcp aborted ${actionType} on ${targetRef}: ${reason}`);
    this.name = 'AmcpAbortedError';
    this.actionType = actionType;
    this.targetRef = targetRef;
    this.reason = reason;
  }
}

/**
 * Verifies a host's countersignature over the accept's host-assigned fields and `log_id` (§5.2, §7.1).
 *
 * The payload is supplied already canonical, so a verifier resolves the key and does cryptography
 * only. A `host_key_id` with no current registry entry - never registered, or revoked - returns
 * false: the countersignature is not established either way (§10.9).
 */
export interface CountersignatureVerifier {
  /** Return true if the signature verifies against the registered host key. */
  verify(hostKeyId: string, signature: string, payload: Uint8Array): Promise<boolean>;
}

/** The effect + confidentiality descriptors for one audited operation (§4.2, §4.3). */
export interface ActionOptions {
  mutates: boolean;
  egress: boolean;
  /** Cleartext context recorded on the event (§4.3). */
  disclose?: Record<string, unknown> | undefined;
  /** A value whose canonical hash is committed to, without disclosing it (§4.3). */
  commit?: unknown;
}

function toWire(event: Record<string, unknown>): Record<string, unknown> {
  // Emit the exact wire bytes with absent optionals omitted (the §8 canonical input).
  const wire: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(event)) {
    if (value !== undefined) {
      wire[key] = value;
    }
  }
  return wire;
}

/** One audit session: wraps a call's internal operations in audit-before-act (± a Level-2 signer). */
export class AmcpSession {
  /** @internal */ readonly _transport: AuditTransport;
  /** @internal */ readonly _sessionId: string;
  /** @internal */ readonly _deps: Deps;
  /** @internal */ readonly _pollutedStop: boolean;
  /** @internal */ readonly _countersignatureVerifier: CountersignatureVerifier | undefined;
  /** @internal */ readonly _requireCountersign: boolean;
  /** @internal */ readonly _signer: EventSigner | undefined;
  /** @internal */ readonly _numbering: SessionNumbering;

  /**
   * Bind the session to a transport, its audit session id, id/time deps, and optional L2 signer.
   *
   * `sessionId` is the one the host issued for this call (§6.3) - or, for a tool acting as its own host
   * in the degraded posture, the one it minted with `newSessionId`. Every event carries it.
   *
   * Polluted Stop runs whenever a signer is present (Level 2 MUST, §11.3); under Level 1 it is
   * optional and off by default. Pass `pollutedStop: true` to opt an L1 tool into the check.
   *
   * The session numbers the events it signs from 0 (§7.4), with the transport's `numbering` when it
   * carries one - so every `AmcpSession` of one call shares one sequence - and with its own otherwise.
   * Nothing is shared with another audit session, so one key serves any number of concurrent calls,
   * processes, and hosts without their coordinating.
   *
   * A tool that requires a countersignature performs Polluted Stop at either level (§7.2): the
   * countersignature binds the host-assigned fields to `record_hash` and no further.
   */
  constructor(
    transport: AuditTransport,
    sessionId: string,
    options: {
      signer?: EventSigner;
      deps?: Deps;
      pollutedStop?: boolean;
      countersignatureVerifier?: CountersignatureVerifier;
      requireCountersign?: boolean;
    } = {},
  ) {
    // Every event carries the session id and the host refuses one off the pattern (§6.3); checked here so
    // a wrong id fails where it was chosen, not as a schema error on the first action.
    if (typeof sessionId !== 'string' || !SESSION_ID_REGEX.test(sessionId)) {
      throw new AmcpUsageError(
        `sessionId ${JSON.stringify(sessionId)} is not a session id: it must be a lowercase RFC 9562 UUID, ` +
          'not the nil UUID - the one the host issued (McpAuditCall.sessionId) or one from newSessionId() (§6.3)',
      );
    }
    this._transport = transport;
    this._sessionId = sessionId;
    this._signer = options.signer;
    this._deps = options.deps ?? new SystemDeps();
    // Requiring a countersignature without the means to check one would accept any bytes as a signature,
    // which is worse than not requiring it at all (§11.3 Countersignature Enforcement).
    if (options.requireCountersign === true && options.countersignatureVerifier === undefined) {
      throw new Error('requireCountersign needs a CountersignatureVerifier');
    }
    // §11.3 makes Polluted Stop REQUIRED under Level 2 and OPTIONAL under Level 1. A signer is this
    // SDK's Level-2 marker, so switching the check off while signing is a configuration the
    // specification does not allow, and the default already does the right thing.
    if (options.pollutedStop === false && options.signer !== undefined) {
      throw new Error('Polluted Stop is REQUIRED under Level 2 (§7.2, §11.3)');
    }
    const requireCountersign = options.requireCountersign ?? false;
    if (options.pollutedStop === false && requireCountersign) {
      throw new Error('Polluted Stop is REQUIRED where a countersignature is required (§7.2, §11.3)');
    }
    this._pollutedStop = options.pollutedStop ?? (options.signer !== undefined || requireCountersign);
    this._numbering = numberingOf(transport);
    this._countersignatureVerifier = options.countersignatureVerifier;
    this._requireCountersign = requireCountersign;
  }

  /** The audit session every event of this call carries (§6.3). */
  get sessionId(): string {
    return this._sessionId;
  }

  /** @internal Sign the event under Level 2, or return it unchanged under Level 1. */
  async _stamp(event: Record<string, unknown>, signerSeq?: number): Promise<Record<string, unknown>> {
    return this._signer !== undefined && signerSeq !== undefined ? this._signer.sign(event, signerSeq) : event;
  }

  /**
   * Number and emit one terminal outcome inside §7.4's section.
   *
   * @internal Called by `action` and by the disposer; not part of the public API.
   */
  async _emitOutcome(action: AuditedAction, outcome: Outcome, reason?: string): Promise<void> {
    await numbering(this, async (signerSeq) => {
      await this._transport.sendOutcome(await action._build(outcome, signerSeq, reason));
    });
  }

  /**
   * Emit an aborted outcome without letting a failure to emit it mask the abort itself (§7.2).
   *
   * Every abort path goes through here. Building the outcome signs it under Level 2, so a dead
   * signer or a dead transport can fail the emission - and the abort is what the caller must act
   * on, not the second failure that happened while recording it.
   *
   * @internal
   */
  async _emitAbortedBestEffort(action: AuditedAction, reason: string): Promise<void> {
    try {
      await this._emitOutcome(action, Outcome.ABORTED, reason);
    } catch (error) {
      console.error('auditable-mcp: could not emit the aborted outcome', reason, error);
    }
  }

  /**
   * Acquire an audited action: emit the attempt, await accept, run Polluted Stop.
   *
   * Intended for `await using action = await session.action(...)`. If the host refuses or the record
   * hash does not match, an `aborted` outcome is emitted and `AmcpAbortedError` is thrown before the
   * action is returned, so the `await using` body never runs. On success the returned action's
   * disposer emits the terminal outcome; the caller must call `succeeded()` for a `success` record.
   *
   * @throws {AmcpAbortedError} If the host does not accept, or the Polluted Stop check fails.
   */
  async action(
    actionType: string,
    targetResource: TargetResource | Record<string, unknown>,
    options: ActionOptions,
  ): Promise<AuditedAction> {
    const target = targetResourceSchema.parse(targetResource);
    const action = new AuditedAction(this, this._deps.newId(), actionType, target, options);

    let attempt: Record<string, unknown>;
    let response: AttemptResponse;
    let fault: unknown;
    // §7.4: the numbering and the emission are one section, so two concurrent actions of one call
    // cannot leave in the order their signing happened to finish in. The section spans the host's
    // answer, not just the send, because a transport resolves `sendAttempt` only when the answer
    // arrives and gives no earlier point at which the frame is known to be on its way. It serializes
    // the attempts of one call under Level 2; calls share nothing, so it costs nothing across them.
    ({ attempt, response } = await numbering(this, async (signerSeq) => {
      // Building signs the event under Level 2, and a signer that fails is the tool's own failure,
      // not the host's. It stays outside the conversion below so it reaches the caller as itself
      // rather than as host-unavailable, which would send an operator to the host.
      const numbered = await action._build(Outcome.ATTEMPTED, signerSeq);
      try {
        return { attempt: numbered, response: await this._transport.sendAttempt(numbered) };
      } catch (error) {
        if (error instanceof AmcpUsageError) {
          // Not a failure to record: the SDK was used against its own contract, and no audit outcome
          // describes that. Filing host-unavailable for it would blame the host for the integrator's
          // error and bury the one thing they need to see (§6.2).
          throw error;
        }
        // §6/§11.3: a transport fault (as against an `unavailable` result) is a failure to record
        // and is handled exactly as `unavailable` - fail closed. The abort is emitted outside this
        // section, which the emission needs for itself.
        fault = error;
        return { attempt: numbered, response: unavailable() };
      }
    }));
    if (fault !== undefined) {
      await this._emitAbortedBestEffort(action, reasons.HOST_UNAVAILABLE);
      const aborted = new AmcpAbortedError(actionType, target.ref, reasons.HOST_UNAVAILABLE);
      // The transport fault is the diagnosis; the abort is only the verdict. The Python port chains
      // it with `raise ... from`, and `cause` is the same relation here.
      aborted.cause = fault;
      throw aborted;
    }

    if (response.status !== Status.ACCEPT) {
      // reject (invalid) or unavailable (not persisted): do not act; signal aborted (§11.3).
      const reason = response.status === Status.REJECT ? reasons.HOST_REJECTED : reasons.HOST_UNAVAILABLE;
      await this._emitAbortedBestEffort(action, reason);
      throw new AmcpAbortedError(actionType, target.ref, reason);
    }

    // §7.2 evaluates in precedence order: the response's status above, then the countersignature that
    // authenticates the host-assigned fields, then the hash computed over them. The reason is sealed
    // into the ledger and compared across implementations, so the order is not incidental.
    if (this._requireCountersign && response.host_signature === undefined) {
      await this._emitAbortedBestEffort(action, reasons.HOST_UNCOUNTERSIGNED);
      throw new AmcpAbortedError(actionType, target.ref, reasons.HOST_UNCOUNTERSIGNED);
    }
    if (response.host_signature !== undefined && this._countersignatureVerifier !== undefined) {
      // The triple is refined to appear together, so the key id and the ledger name are present (§7.1).
      const keyId = response.host_key_id as string;
      const payload = countersignaturePayload(
        response.seq,
        response.host_ts,
        response.log_id as string,
        response.previous_hash,
        response.record_hash,
      );
      if (!(await this._countersignatureVerifier.verify(keyId, response.host_signature, payload))) {
        await this._emitAbortedBestEffort(action, reasons.HOST_SIGNATURE_INVALID);
        throw new AmcpAbortedError(actionType, target.ref, reasons.HOST_SIGNATURE_INVALID);
      }
    }

    if (this._pollutedStop) {
      // Polluted Stop (§7.2): recompute the record hash over the exact attempt bytes; a mismatch means
      // the host sealed a different record, so the tool must not act.
      const expected = computeRecordHash(attempt, response.seq, response.host_ts, response.previous_hash);
      if (expected !== response.record_hash) {
        await this._emitAbortedBestEffort(action, reasons.HASH_MISMATCH);
        throw new AmcpAbortedError(actionType, target.ref, reasons.HASH_MISMATCH);
      }
    }

    action._markAccepted(response);
    return action;
  }
}

/** One audited operation as an async-disposable resource (see the module docstring). */
export class AuditedAction implements AsyncDisposable {
  /** The host-assigned accept once acquired; null while unaccepted. */
  accept: AcceptResponse | null = null;

  readonly #session: AmcpSession;
  readonly #id: string;
  readonly #actionType: string;
  readonly #target: TargetResource;
  readonly #options: ActionOptions;
  readonly #commitHash: string | undefined;
  #outcome: 'success' | 'failed' | undefined;
  #finished = false;

  /** @internal Constructed by {@link AmcpSession.action}; not part of the public API. */
  constructor(session: AmcpSession, id: string, actionType: string, target: TargetResource, options: ActionOptions) {
    this.#session = session;
    this.#id = id;
    this.#actionType = actionType;
    this.#target = target;
    this.#options = options;
    this.#commitHash = options.commit !== undefined ? hashCanonical(options.commit) : undefined;
  }

  /** Mark the operation successful; without this call the disposer fails closed with `failed`. */
  succeeded(): void {
    if (this.#outcome === undefined) {
      this.#outcome = 'success';
    }
  }

  /**
   * Mark the operation failed (§7.2).
   *
   * A `failed` outcome carries no wire `reason`: the event `reason` field is pinned to the Tier-1
   * abort codes (§7.6), and a domain-failure cause is a Tier-2 local diagnostic that is not sealed.
   */
  failed(): void {
    this.#outcome = 'failed';
  }

  async [Symbol.asyncDispose](): Promise<void> {
    if (this.#finished) {
      return;
    }
    this.#finished = true;
    const outcome = this.#outcome === 'success' ? Outcome.SUCCESS : Outcome.FAILED;
    try {
      await this.#session._emitOutcome(this, outcome);
    } catch (error) {
      // §6: an outcome has no response, so there is nothing to retry and nothing to tell the host; losing
      // it leaves an attempt the host records unresolved when the call ends (§10.8). Throwing from a disposer would replace the body's error with the audit layer's - as
      // a SuppressedError wrapping it - and the body's is the one the caller must act on.
      console.error(
        'auditable-mcp: could not emit the terminal outcome; the operation is left unresolved (§10.8)',
        error,
      );
    }
  }

  /** @internal Build and stamp the wire event for `outcome`, reusing the shared correlation id. */
  async _build(outcome: Outcome, signerSeq?: number, reason?: string): Promise<Record<string, unknown>> {
    const event = auditEventSchema.parse({
      id: this.#id,
      spec_version: SPEC_VERSION,
      ts: this.#session._deps.now(),
      session_id: this.#session._sessionId,
      action_type: this.#actionType,
      mutates: this.#options.mutates,
      egress: this.#options.egress,
      target_resource: this.#target,
      outcome,
      reason,
      action_context: this.#options.disclose,
      action_context_hash: this.#commitHash,
    });
    return this.#session._stamp(toWire(event as Record<string, unknown>), signerSeq);
  }

  /** @internal Record the host accept after a cleared acquisition. */
  _markAccepted(response: AcceptResponse): void {
    this.accept = response;
  }
}
