/**
 * The audit transport seam and host-endpoint contract.
 *
 * Auditable MCP carries tool-to-host messages while a `tools/call` is in flight (§6). This module
 * defines the exchange's two abstract sides and keeps the core free of any concrete wire; a binding
 * (§6.4, §6.5) carries them:
 *
 * - `AuditTransport` — the tool's view, for one call. `sendAttempt` resolves with the host's answer
 *   (the tool must not act unless it is `accept`, §6); `sendOutcome` has no answer.
 * - `AuditEndpoint` — the host's view, i.e. what a transport delivers to. The host audit subsystem
 *   implements it; an in-process transport (`in-process.ts`) forwards straight to it.
 *
 * The per-operation calls are async because a real transport crosses the wire. Capability negotiation
 * is a local fit computation (§6.1), so it stays synchronous. Response construction helpers are
 * provided for host implementers. An integrator wires this seam over MCP; `InProcessTransport` embeds
 * the host in the tool's process.
 */

import type { NegotiationResult } from './capability';
import {
  type AcceptResponse,
  type AttemptResponse,
  type AuditCapability,
  type RejectResponse,
  Status,
  type UnavailableResponse,
} from './models';

/**
 * This SDK was driven into a state its own contract forbids.
 *
 * Distinct from a transport fault: a fault is a failure to record, which §7.2 turns into an
 * `aborted` outcome and a fail-closed halt, whereas this is an integrator error that no audit
 * outcome describes. The session's fail-closed catch rethrows it rather than filing an `aborted`
 * record that blames the host for it (§6.2, §11.3).
 */
export class AmcpUsageError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'AmcpUsageError';
  }
}

/** Build a Verifiable Accept, with the countersignature when the host countersigns (§7.1, §5.2). */
export function accept(
  seq: number,
  recordHash: string,
  hostTs: string,
  previousHash: string,
  countersign: {
    hostSignature?: string | undefined;
    hostKeyId?: string | undefined;
    logId?: string | undefined;
  } = {},
): AcceptResponse {
  const response: AcceptResponse = {
    status: Status.ACCEPT,
    seq,
    record_hash: recordHash,
    host_ts: hostTs,
    previous_hash: previousHash,
  };
  // The triple appears together or not at all (§7.1), so all three are set or none is.
  const { hostSignature, hostKeyId, logId } = countersign;
  if (hostSignature !== undefined && hostKeyId !== undefined && logId !== undefined) {
    return { ...response, host_signature: hostSignature, host_key_id: hostKeyId, log_id: logId };
  }
  return response;
}

/** Build a reject response with a Tier-1 reject `reason` (ledger integrity not guaranteed, §7.1). */
export function reject(reason: RejectResponse['reason']): RejectResponse {
  return { status: Status.REJECT, reason };
}

/** Build an unavailable response: nothing was decided (§7.1; `reason` is `internal-error`). */
export function unavailable(): UnavailableResponse {
  return { status: Status.UNAVAILABLE, reason: 'internal-error' };
}

/** The tool-side transport for one call: negotiate, then send attempts and outcomes (§6). */
export interface AuditTransport {
  /** Present the tool's offered capability and learn the host requirement and fit (§6.1). */
  negotiate(offered: AuditCapability): NegotiationResult;

  /** Send an attempt and resolve with the host's answer (§6). */
  sendAttempt(event: Record<string, unknown>): Promise<AttemptResponse>;

  /** Send an outcome, which has no answer (§6). */
  sendOutcome(event: Record<string, unknown>): Promise<void>;
}

/** The host-side audit subsystem a transport delivers to. */
export interface AuditEndpoint {
  /** The audit capability this host requires (§6.1). */
  readonly capability: AuditCapability;

  /** Issue a fresh audit session for a call the host audits, and return its id (§6.3). */
  openSession(sessionId?: string): string;

  /** Close an audit session because its call ended (§6.3). */
  closeSession(sessionId: string): Promise<void>;

  /**
   * Validate and, if durable, seal an attempt; otherwise reject/unavailable (§7.1).
   *
   * `sessionId`, when given, is the audit session of the call the attempt arrived on, which the event
   * must carry (§6.3). `deadline`, when given, is a time in `Date.now()` milliseconds after which the
   * binding has already answered the tool `unavailable` (§6.4): an attempt the endpoint takes up after it
   * is answered `unavailable` and records nothing.
   */
  handleAttempt(event: Record<string, unknown>, sessionId?: string, deadline?: number): Promise<AttemptResponse>;

  /**
   * Seal an outcome, or drop and record it (§7.2).
   *
   * `event` is whatever the binding received where an outcome belongs; one that is not a valid event,
   * a JSON object included, is recorded as `schema-invalid` rather than dropped silently (§6.4).
   */
  handleOutcome(event: unknown, sessionId?: string): Promise<void>;
}
