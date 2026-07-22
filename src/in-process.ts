/**
 * An in-process transport: the tool and host share a process, no wire.
 *
 * This forwards `AuditTransport` calls straight to an `AuditEndpoint`. It is the transport used for
 * tests and for embedding the audit host in the same process as the tool. A wire transport over MCP
 * is wired by the integrator against the same `AuditTransport` seam.
 */

import { type NegotiationResult, negotiate } from './capability';
import type { AttemptResponse, AuditCapability } from './models';
import type { AuditEndpoint, AuditTransport } from './transport';

/** Forwards audit messages directly to an in-process `AuditEndpoint` (implements `AuditTransport`). */
export class InProcessTransport implements AuditTransport {
  #endpoint: AuditEndpoint;

  constructor(endpoint: AuditEndpoint) {
    this.#endpoint = endpoint;
  }

  negotiate(offered: AuditCapability): NegotiationResult {
    return negotiate(this.#endpoint.capability, offered);
  }

  async sendAttempt(event: Record<string, unknown>): Promise<AttemptResponse> {
    return this.#endpoint.handleAttempt(event);
  }

  async sendOutcome(event: Record<string, unknown>): Promise<void> {
    await this.#endpoint.handleOutcome(event);
  }
}
