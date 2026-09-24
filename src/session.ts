/**
 * The tool-side audit-before-act session — the `await using` core.
 *
 * `AuditedAction` is the source of truth for the tool lifecycle, enforced at the language level via
 * explicit resource management:
 *
 * - Acquisition (`await session.action(...)`) emits `audit/attempt`, awaits the host response, and
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
 * `AmcpSession` binds a transport, a parent `call_id`, id/time sources, and an optional Level-2
 * signer. Level 1 and Level 2 emission are identical; Level 2 only adds the signer.
 */

import { hashCanonical } from './canonical';
import { type Clock, nowIso } from './clock';
import { computeRecordHash, witnessPayload } from './hashing';
import {
  type AcceptResponse,
  type AttemptResponse,
  auditEventSchema,
  Outcome,
  SPEC_VERSION,
  Status,
  type TargetResource,
  targetResourceSchema,
} from './models';
import { Mutex } from './mutex';
import * as reasons from './reasons';
import { AmcpUsageError, type AuditTransport } from './transport';

/**
 * Stamps an event with `key_id`, `sequence`, and `signature` (Level 2, §5, §8.2).
 *
 * `sign` is async because a production signer typically calls a network HSM/KMS; a local signer just
 * resolves synchronously under the async signature.
 */
export interface EventSigner {
  sign(event: Record<string, unknown>): Promise<Record<string, unknown>>;
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

/**
 * The tool's own fail-closed halt: the domain action was not performed (outcome=aborted).
 *
 * Named for the tool's abort, not host "blocking" — the host never prevents a domain action (§2). A
 * tool surfaces this as a `tools/call` error result.
 */
/** A section two callers cannot be inside at once. `Mutex` is one; pass-through is the other. */
interface Section {
  run<T>(body: () => Promise<T>): Promise<T>;
}

const PASS_THROUGH: Section = { run: (body) => body() };

/**
 * §7.4 requires a tool to assign `signer_seq` and emit the event atomically with respect to every
 * other event under the same `key_id`. The counter lives in the signer and the send lives here, so
 * neither alone can hold the invariant; the section is keyed on the signer because `signer_seq` is
 * per key, and sessions serving different `tools/call`s share one signer for one key. Weakly held,
 * so a signer that goes out of scope takes its section with it.
 */
const NUMBERING = new WeakMap<EventSigner, Mutex>();

function numberingSection(signer: EventSigner | undefined): Section {
  if (signer === undefined) {
    // Level 1 numbers nothing, so it takes no section: serializing it would cost concurrency the
    // specification does not ask for.
    return PASS_THROUGH;
  }
  let section = NUMBERING.get(signer);
  if (section === undefined) {
    section = new Mutex();
    NUMBERING.set(signer, section);
  }
  return section;
}

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

/** The effect + confidentiality descriptors for one audited operation (§4.2, §4.3). */
/**
 * Verifies a host's witness signature over the accept's host-assigned fields (§5.2, §7.1).
 *
 * The payload is supplied already canonical, so a verifier resolves the key and does cryptography
 * only. A `host_key_id` with no current registry entry - never registered, or revoked - returns
 * false: the witness is not established either way (§10.9).
 */
export interface WitnessVerifier {
  /** Return true if the signature verifies against the registered host key. */
  verify(hostKeyId: string, signature: string, payload: Uint8Array): Promise<boolean>;
}

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

/** Wraps internal operations in the audit-before-act lifecycle (± a Level-2 signer). */
export class AmcpSession {
  /** @internal */ readonly _transport: AuditTransport;
  /** @internal */ readonly _callId: string;
  /** @internal */ readonly _deps: Deps;
  /** @internal */ readonly _pollutedStop: boolean;
  /** @internal */ readonly _witnessVerifier: WitnessVerifier | undefined;
  /** @internal */ readonly _requireWitness: boolean;
  readonly #signer: EventSigner | undefined;
  readonly #numbering: Section;

  /**
   * Bind the session to a transport, parent call id, id/time deps, and optional L2 signer.
   *
   * Polluted Stop runs whenever a signer is present (Level 2 MUST, §11.3); under Level 1 it is
   * optional and off by default. Pass `pollutedStop: true` to opt an L1 tool into the check.
   */
  constructor(
    transport: AuditTransport,
    callId: string,
    options: {
      signer?: EventSigner;
      deps?: Deps;
      pollutedStop?: boolean;
      witnessVerifier?: WitnessVerifier;
      requireWitness?: boolean;
    } = {},
  ) {
    this._transport = transport;
    this._callId = callId;
    this.#signer = options.signer;
    this.#numbering = numberingSection(options.signer);
    this._deps = options.deps ?? new SystemDeps();
    // Requiring a witness without the means to check one would accept any bytes as a signature, which
    // is worse than not requiring it at all (§11.3 Witness Enforcement).
    if (options.requireWitness === true && options.witnessVerifier === undefined) {
      throw new Error('requireWitness needs a WitnessVerifier');
    }
    // §11.3 makes Polluted Stop REQUIRED under Level 2 and OPTIONAL under Level 1. A signer is this
    // SDK's Level-2 marker, so switching the check off while signing is a configuration the
    // specification does not allow, and the default already does the right thing.
    if (options.pollutedStop === false && options.signer !== undefined) {
      throw new Error('Polluted Stop is REQUIRED under Level 2 (§7.2, §11.3)');
    }
    this._pollutedStop = options.pollutedStop ?? options.signer !== undefined;
    this._witnessVerifier = options.witnessVerifier;
    this._requireWitness = options.requireWitness ?? false;
  }

  /** @internal Sign the event under Level 2, or return it unchanged under Level 1. */
  async _stamp(event: Record<string, unknown>): Promise<Record<string, unknown>> {
    return this.#signer !== undefined ? this.#signer.sign(event) : event;
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
  /**
   * Number and emit one terminal outcome inside §7.4's section.
   *
   * @internal Called by `action` and by the disposer; not part of the public API.
   */
  async _emitOutcome(action: AuditedAction, outcome: Outcome, reason?: string): Promise<void> {
    await this.#numbering.run(async () => {
      await this._transport.sendOutcome(await action._build(outcome, reason));
    });
  }

  async action(
    actionType: string,
    targetResource: TargetResource | Record<string, unknown>,
    options: ActionOptions,
  ): Promise<AuditedAction> {
    const target = targetResourceSchema.parse(targetResource);
    const action = new AuditedAction(this, this._deps.newId(), actionType, target, options);

    let attempt: Record<string, unknown>;
    let response: AttemptResponse;
    try {
      // §7.4: the numbering and the emission are one section, so two concurrent actions under one
      // key cannot leave in the order their signing happened to finish in. The section spans the
      // host's answer, not just the send: on a transport that carries each call on its own stream
      // (Streamable HTTP, §6), two frames sent in order have no mutual arrival order, so the
      // previous attempt has to be acknowledged before the next one is emitted. It costs the
      // overlap of the wire latency under Level 2, and it is what makes the ordering hold on a
      // transport that does not carry one.
      ({ attempt, response } = await this.#numbering.run(async () => {
        const numbered = await action._build(Outcome.ATTEMPTED);
        return { attempt: numbered, response: await this._transport.sendAttempt(numbered) };
      }));
    } catch (error) {
      if (error instanceof AmcpUsageError) {
        // Not a failure to record: the SDK was used against its own contract, and no audit outcome
        // describes that. Filing `host-unavailable` for it would blame the host for the integrator's
        // error and bury the one thing they need to see (§6.2).
        throw error;
      }
      // §6/§11.3: a JSON-RPC transport fault (vs an `unavailable` result) is handled exactly as
      // `unavailable` — fail closed. Emit a fail-closed aborted outcome for observability, best-effort
      // so a broken transport cannot mask the abort itself.
      try {
        await this._emitOutcome(action, Outcome.ABORTED, reasons.HOST_UNAVAILABLE);
      } catch (outcomeError) {
        console.error('auditable-mcp: failed to emit aborted outcome after a transport fault', outcomeError);
      }
      throw new AmcpAbortedError(actionType, target.ref, reasons.HOST_UNAVAILABLE);
    }

    if (response.status !== Status.ACCEPT) {
      // reject (invalid) or unavailable (not persisted): do not act; signal aborted (§11.3).
      const reason = response.status === Status.REJECT ? reasons.HOST_REJECTED : reasons.HOST_UNAVAILABLE;
      await this._emitOutcome(action, Outcome.ABORTED, reason);
      throw new AmcpAbortedError(actionType, target.ref, reason);
    }

    // §7.2 evaluates in precedence order: the response's status above, then the witness signature that
    // authenticates the host-assigned fields, then the hash computed over them. The reason is sealed
    // into the ledger and compared across implementations, so the order is not incidental.
    if (this._requireWitness && response.host_signature === undefined) {
      await this._emitOutcome(action, Outcome.ABORTED, reasons.HOST_UNWITNESSED);
      throw new AmcpAbortedError(actionType, target.ref, reasons.HOST_UNWITNESSED);
    }
    if (response.host_signature !== undefined && this._witnessVerifier !== undefined) {
      // The pair is refined to appear together, so the key id is present with the signature (§7.1).
      const keyId = response.host_key_id as string;
      const payload = witnessPayload(response.seq, response.host_ts, response.previous_hash, response.record_hash);
      if (!(await this._witnessVerifier.verify(keyId, response.host_signature, payload))) {
        await this._emitOutcome(action, Outcome.ABORTED, reasons.HOST_SIGNATURE_INVALID);
        throw new AmcpAbortedError(actionType, target.ref, reasons.HOST_SIGNATURE_INVALID);
      }
    }

    if (this._pollutedStop) {
      // Polluted Stop (§7.2): recompute the record hash over the exact attempt bytes; a mismatch means
      // the host sealed a different record, so the tool must not act.
      const expected = computeRecordHash(attempt, response.seq, response.host_ts, response.previous_hash);
      if (expected !== response.record_hash) {
        await this._emitOutcome(action, Outcome.ABORTED, reasons.HASH_MISMATCH);
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
    await this.#session._emitOutcome(this, outcome);
  }

  /** @internal Build and stamp the wire event for `outcome`, reusing the shared correlation id. */
  async _build(outcome: Outcome, reason?: string): Promise<Record<string, unknown>> {
    const event = auditEventSchema.parse({
      id: this.#id,
      spec_version: SPEC_VERSION,
      ts: this.#session._deps.now(),
      call_id: this.#session._callId,
      action_type: this.#actionType,
      mutates: this.#options.mutates,
      egress: this.#options.egress,
      target_resource: this.#target,
      outcome,
      reason,
      action_context: this.#options.disclose,
      action_context_hash: this.#commitHash,
    });
    return this.#session._stamp(toWire(event as Record<string, unknown>));
  }

  /** @internal Record the host accept after a cleared acquisition. */
  _markAccepted(response: AcceptResponse): void {
    this.accept = response;
  }
}
