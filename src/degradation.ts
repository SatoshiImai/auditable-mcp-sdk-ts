/**
 * What a tool does with a call that is not audit-negotiated (§6.2).
 *
 * A tool that speaks this extension has to stay usable by hosts that do not, which is nearly every
 * MCP host today. For an unnegotiated call it sends no audit message at all - an ordinary host has no
 * way to answer one, so a tool that sends anyway fails closed against a peer that has done nothing
 * wrong - and serves `tools/call` exactly as a build without this extension would.
 *
 * Two postures are admissible. Under **degraded** (the default) the tool serves the call and records
 * into an audit host it provides for itself, under an audit session it mints (`newSessionId`): the
 * recording does not stop, the host's countersignature does, and §5.2 makes that legible in the records. Under **mandatory** the tool declines to serve, which
 * [SEP-2133] permits for an extension a deployment treats as required.
 *
 * A third posture - serving the call while recording nothing and reporting nothing about the
 * omission - is not conformant, so `transportFor` refuses to return a transport for it: taking the
 * degraded posture requires somewhere to record.
 */

import type { NegotiationResult } from './capability';
import { Countersign } from './models';
import type { AuditTransport } from './transport';

/** How a tool spends an audit obligation it cannot discharge against the host (§6.2). */
export const Posture = {
  /** Serve the call, and record into an audit host the tool provides for itself. */
  DEGRADED: 'degraded',
  /** Decline to serve, as [SEP-2133] permits for a mandatory extension. */
  MANDATORY: 'mandatory',
} as const;
export type Posture = (typeof Posture)[keyof typeof Posture];

/** The call is not audit-negotiated and the tool's posture is `mandatory` (§6.2). */
export class UnnegotiatedCallError extends Error {
  readonly negotiation: NegotiationResult;

  constructor(negotiation: NegotiationResult) {
    super(`call is not audit-negotiated (${negotiation.outcome}); posture is mandatory`);
    this.name = 'UnnegotiatedCallError';
    this.negotiation = negotiation;
  }
}

/**
 * Return the transport §6.2 permits for this call, or refuse to serve it.
 *
 * @param negotiation The result of comparing the host's declaration against the tool's (§6.1).
 * @param options.negotiated The transport to the host, used only when the call is audit-negotiated.
 * @param options.fallback A transport over an audit host the tool provides for itself, required by the
 *   degraded posture. An `InProcessTransport` over a tool-local `AuditHost` is the usual one.
 * @param options.posture What to do when the call is not audit-negotiated. Degraded by default.
 * @returns `negotiated` for an audit-negotiated call, otherwise `fallback`.
 * @throws {UnnegotiatedCallError} The call is not audit-negotiated and the posture is mandatory.
 * @throws {Error} The posture is degraded and no `fallback` was given. Serving a call while neither
 *   recording the operations nor reporting the omission is not conformant (§6.2), so the degraded
 *   posture is not available without somewhere to record.
 */
export function transportFor(
  negotiation: NegotiationResult,
  options: { negotiated: AuditTransport; fallback?: AuditTransport; posture?: Posture },
): AuditTransport {
  if (negotiation.negotiated) {
    return options.negotiated;
  }
  if ((options.posture ?? Posture.DEGRADED) === Posture.MANDATORY) {
    throw new UnnegotiatedCallError(negotiation);
  }
  // A tool that requires a countersignature cannot take the degraded posture: the audit host it provides for
  // itself holds no key a verifier's registry binds to a host (§5.2), so every action would abort
  // `host-uncountersigned` (§7.2) and the tool would serve while doing nothing. The coherent posture for a
  // tool with that requirement is mandatory, and saying so beats an unusable degraded call.
  if (negotiation.tool.countersign === Countersign.HOST) {
    throw new Error('a tool that requires countersign "host" cannot degrade; use Posture.MANDATORY (§5.2, §6.2)');
  }
  if (options.fallback === undefined) {
    throw new Error('the degraded posture needs a fallback transport to record into (§6.2)');
  }
  return options.fallback;
}
