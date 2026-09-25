/**
 * Declaring and reading this extension at MCP `initialize` (§6.1).
 *
 * [SEP-2133] carries an extension's settings object in the `extensions` member of the capabilities
 * each party sends at `initialize` — `ClientCapabilities` for the host, `ServerCapabilities` for the
 * tool — keyed by the extension identifier. These helpers put the audit capability there and take a
 * peer's back out. They work on any capabilities-shaped object rather than on the official MCP types,
 * so one pair of calls serves both sides and neither drags in the MCP package.
 *
 * A declaration that does not validate is not a declaration: `capabilityOf` returns undefined for it,
 * and §6.2 then governs the session exactly as it governs a peer that declared nothing. An operator
 * reading the wire can tell the two apart; the protocol cannot and need not, because in both cases
 * nothing was agreed, so nothing may be sent.
 */

import { type AuditCapability, auditCapabilitySchema, EXTENSION_ID } from '../models';

/** The capabilities member [SEP-2133] reserves for extension settings objects (§6.1). */
export const EXTENSIONS_MEMBER = 'extensions';

/** A capabilities object as it appears on the wire, with the extensions member this SDK reads. */
export interface WithExtensions {
  [EXTENSIONS_MEMBER]?: Record<string, unknown> | undefined;
  [key: string]: unknown;
}

/** Return the `extensions` entry that declares this extension (§6.1). */
export function auditExtension(capability: AuditCapability): Record<string, AuditCapability> {
  return { [EXTENSION_ID]: capability };
}

/**
 * Return a copy of `capabilities` declaring this extension, keeping any others it declares (§6.1).
 *
 * The original is left untouched, so a caller's own object never gains a declaration behind its back.
 */
export function declare<T extends WithExtensions>(capabilities: T, capability: AuditCapability): T {
  return {
    ...capabilities,
    [EXTENSIONS_MEMBER]: { ...extensionsOf(capabilities), ...auditExtension(capability) },
  };
}

/**
 * Declare this extension in a capabilities object already serialized for the wire, in place (§6.1).
 *
 * The MCP session builds its own capabilities and offers no hook for an extension to add to them, so
 * the binding merges the declaration in as the handshake passes. Other extensions are kept.
 */
export function declareInto(capabilities: WithExtensions, capability: AuditCapability): void {
  capabilities[EXTENSIONS_MEMBER] = { ...extensionsOf(capabilities), ...auditExtension(capability) };
}

/**
 * Return the peer's declared audit capability, or undefined if it declared none this SDK can read.
 *
 * Absent and malformed both read as undefined: neither agreed anything, so neither permits a send.
 */
export function capabilityOf(capabilities: unknown): AuditCapability | undefined {
  const declared = extensionsOf(capabilities)[EXTENSION_ID];
  if (declared === undefined) {
    return undefined;
  }
  const parsed = auditCapabilitySchema.safeParse(declared);
  return parsed.success ? parsed.data : undefined;
}

function extensionsOf(capabilities: unknown): Record<string, unknown> {
  if (typeof capabilities !== 'object' || capabilities === null) {
    return {};
  }
  const member = (capabilities as WithExtensions)[EXTENSIONS_MEMBER];
  return typeof member === 'object' && member !== null ? (member as Record<string, unknown>) : {};
}
