/**
 * Audit capability negotiation (§6.1).
 *
 * The capability object (`AuditCapability`, models.ts) is exchanged bidirectionally during the MCP
 * `initialize` phase: the host declares the level it requires, the tool declares the level it
 * supports. Negotiation here is a local fit computation — a declaration's truthfulness is not
 * verified (the host enforces the required level at runtime, §7), so this only answers "does the
 * offer meet the requirement".
 */

import { type AuditCapability, Level } from './models';

// L2 obligations are a superset of L1, so an L2 tool satisfies an L1 requirement (a safe downgrade),
// while an L1-only tool does not satisfy an L2 requirement.
const LEVEL_RANK: Record<string, number> = { [Level.L1]: 1, [Level.L2]: 2 };

/** The outcome of a capability exchange: the requirement, the offer, and the fit. */
export interface NegotiationResult {
  required: AuditCapability;
  offered: AuditCapability;
  /** True if the offered level meets the requirement and the spec versions match. */
  satisfied: boolean;
  /** True if both sides declare the same `spec_version` (§6.1). */
  versionMatch: boolean;
}

/** Return true if `offered` supports at least the `required` level. */
export function capabilitySatisfies(offered: AuditCapability, required: AuditCapability): boolean {
  return (LEVEL_RANK[offered.level] ?? 0) >= (LEVEL_RANK[required.level] ?? 0);
}

/**
 * Compare a tool's offered capability against a host requirement (§6.1).
 *
 * A `0.x` draft has no on-the-wire compatibility window, so `satisfied` requires both a level fit and
 * an exact `spec_version` match; `versionMatch` surfaces a version mismatch on its own.
 */
export function negotiate(required: AuditCapability, offered: AuditCapability): NegotiationResult {
  const versionMatch = offered.spec_version === required.spec_version;
  return { required, offered, satisfied: capabilitySatisfies(offered, required) && versionMatch, versionMatch };
}
