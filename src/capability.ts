/**
 * Audit capability negotiation (§6.1, §6.2).
 *
 * Both parties declare the capability object under the `extensions` member of their MCP capabilities,
 * keyed by the extension identifier. Negotiation is a local fit computation — a declaration's
 * truthfulness is not verified — so this module only answers whether the two declarations fit, and on
 * which axis they do not.
 *
 * The two axes run in opposite directions. On `level` the tool produces and the host requires, so a
 * tool offering L2 satisfies an L1 host. On `countersign` the host produces and the tool requires, so a
 * host offering `host` satisfies a tool that requires `none`. Each party enforces the axis on which
 * it is the one requiring.
 *
 * A host that declared nothing is not a failed negotiation but an absent one, which §6.2 governs
 * differently: the tool must send no audit message at all and serve the call as an ordinary MCP tool.
 * `NegotiationOutcome` keeps the two apart, because a caller that collapsed them would either brick
 * the tool against ordinary hosts or paper over a real mismatch.
 */

import { type AuditCapability, Countersign, Level } from './models';

// L2 obligations are a superset of L1, so an L2 tool satisfies an L1 requirement (a safe downgrade),
// while an L1-only tool does not satisfy an L2 requirement.
const LEVEL_RANK: Record<string, number> = { [Level.L1]: 1, [Level.L2]: 2 };

// A host that signs satisfies a tool that requires a signature and one that does not; a host that
// does not sign satisfies only the latter.
const COUNTERSIGN_RANK: Record<string, number> = { [Countersign.NONE]: 1, [Countersign.HOST]: 2 };

/** Why a call is or is not audit-negotiated (§6.2). */
export const NegotiationOutcome = {
  NEGOTIATED: 'negotiated',
  /** The peer declared no auditable-mcp capability. Not a mismatch: nothing was offered to compare. */
  UNDECLARED: 'undeclared',
  MISMATCH: 'mismatch',
  /**
   * The declarations fit, and the host issued no audit session for this call: it did not ask to audit
   * it (§6.3). Like UNDECLARED, nothing is wrong with either party.
   */
  NO_SESSION: 'no-session',
} as const;
export type NegotiationOutcome = (typeof NegotiationOutcome)[keyof typeof NegotiationOutcome];

/** The outcome of a capability exchange, and which axis decided it. */
export interface NegotiationResult {
  tool: AuditCapability;
  /** The host's declaration, or undefined if it declared no auditable-mcp extension. */
  host: AuditCapability | undefined;
  outcome: NegotiationOutcome;
  /** True only for an audit-negotiated call; §6.2 governs every other case. */
  negotiated: boolean;
  /** True if both sides declare the same `spec_version` (§6.1). */
  versionMatch: boolean;
  /** True if the tool offers at least the level the host requires. */
  levelFit: boolean;
  /** True if the host provides at least the countersign the tool requires. */
  countersignFit: boolean;
}

/** Return true if the tool offers at least the level the host requires (§6.1). */
export function levelSatisfies(tool: AuditCapability, host: AuditCapability): boolean {
  return (LEVEL_RANK[tool.level] ?? 0) >= (LEVEL_RANK[host.level] ?? 0);
}

/** Return true if the host provides at least the countersign the tool requires (§5.2, §6.1). */
export function countersignSatisfies(host: AuditCapability, tool: AuditCapability): boolean {
  return (COUNTERSIGN_RANK[host.countersign] ?? 0) >= (COUNTERSIGN_RANK[tool.countersign] ?? 0);
}

/**
 * Compare a host and a tool declaration (§6.1).
 *
 * A `0.x` draft has no on-the-wire compatibility window, so a fit requires an exact `spec_version`
 * match as well as both axes; the per-axis flags surface which one failed. Pass `undefined` for
 * `host` when it declared no auditable-mcp extension — that is `UNDECLARED`, not `MISMATCH`.
 */
export function negotiate(host: AuditCapability | undefined, tool: AuditCapability): NegotiationResult {
  if (host === undefined) {
    return {
      tool,
      host: undefined,
      outcome: NegotiationOutcome.UNDECLARED,
      negotiated: false,
      versionMatch: false,
      levelFit: false,
      countersignFit: false,
    };
  }
  const versionMatch = tool.spec_version === host.spec_version;
  const levelFit = levelSatisfies(tool, host);
  const countersignFit = countersignSatisfies(host, tool);
  const fits = versionMatch && levelFit && countersignFit;
  return {
    tool,
    host,
    outcome: fits ? NegotiationOutcome.NEGOTIATED : NegotiationOutcome.MISMATCH,
    negotiated: fits,
    versionMatch,
    levelFit,
    countersignFit,
  };
}
