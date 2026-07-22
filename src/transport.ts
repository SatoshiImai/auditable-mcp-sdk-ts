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

/** Build a Verifiable Accept carrying the fields the tool needs for Polluted Stop (§7.1). */
export function accept(seq: number, recordHash: string, hostTs: string, previousHash: string): AcceptResponse {
  return { status: Status.ACCEPT, seq, record_hash: recordHash, host_ts: hostTs, previous_hash: previousHash };
}

/** Build a reject response (ledger integrity could not be guaranteed, §7.1). */
export function reject(reason: string): RejectResponse {
  return { status: Status.REJECT, reason };
}

/** Build a retryable unavailable response (transient persistence failure, §7.1). */
export function unavailable(reason: string): UnavailableResponse {
  return { status: Status.UNAVAILABLE, reason, retryable: true };
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
