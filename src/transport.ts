/**
 * The audit transport seam and host-endpoint contract.
 *
 * Auditable MCP carries tool-to-host messages while a `tools/call` is in flight (§6). This module
 * defines two abstract sides and keeps the core free of any concrete wire:
 *
 * - `AuditTransport` — the tool's view. `sendAttempt` is a blocking request (the tool awaits it and
 *   must not act unless the response is `accept`, §6); `sendOutcome` is fire-and-forget.
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

/** Build a Verifiable Accept, with the witness signature when the host signs (§7.1, §5.2). */
export function accept(
  seq: number,
  recordHash: string,
  hostTs: string,
  previousHash: string,
  witness: { hostSignature?: string | undefined; hostKeyId?: string | undefined } = {},
): AcceptResponse {
  const response: AcceptResponse = {
    status: Status.ACCEPT,
    seq,
    record_hash: recordHash,
    host_ts: hostTs,
    previous_hash: previousHash,
  };
  // The pair appears together or not at all (§7.1), so both are set or neither is.
  if (witness.hostSignature !== undefined && witness.hostKeyId !== undefined) {
    return { ...response, host_signature: witness.hostSignature, host_key_id: witness.hostKeyId };
  }
  return response;
}

/** Build a reject response with a Tier-1 reject `reason` (ledger integrity not guaranteed, §7.1). */
export function reject(reason: RejectResponse['reason']): RejectResponse {
  return { status: Status.REJECT, reason };
}

/** Build a retryable unavailable response (a host-internal failure, §7.1; `reason` is `internal-error`). */
export function unavailable(): UnavailableResponse {
  return { status: Status.UNAVAILABLE, reason: 'internal-error', retryable: true };
}

/** The tool-side transport: negotiate once, then send attempts (blocking) and outcomes. */
export interface AuditTransport {
  /** Present the tool's offered capability and learn the host requirement and fit (§6.1). */
  negotiate(offered: AuditCapability): NegotiationResult;

  /** Send `audit/attempt` and block for the host response (§6). */
  sendAttempt(event: Record<string, unknown>): Promise<AttemptResponse>;

  /** Send `audit/outcome` (a notification, not a completeness gate, §6). */
  sendOutcome(event: Record<string, unknown>): Promise<void>;
}

/** The host-side audit subsystem a transport delivers to. */
export interface AuditEndpoint {
  /** The audit capability this host requires (§6.1). */
  readonly capability: AuditCapability;

  /** Validate and, if durable, seal an attempt; otherwise reject/unavailable (§7.1). */
  handleAttempt(event: Record<string, unknown>): Promise<AttemptResponse>;

  /** Seal a correlated outcome, or flag it as an anomaly (§7.2). */
  handleOutcome(event: Record<string, unknown>): Promise<void>;
}
