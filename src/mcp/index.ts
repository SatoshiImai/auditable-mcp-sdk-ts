/**
 * The MCP binding: this extension's two methods on a real MCP connection (§6).
 *
 * This entry point declares the MCP transport surface structurally, so importing it pulls in no MCP
 * package at all — an official `Transport` satisfies it, and a seam satisfies what a session requires
 * of a transport.
 */

export {
  auditExtension,
  capabilityOf,
  declare,
  declareInto,
  EXTENSIONS_MEMBER,
  type WithExtensions,
} from './declaration';
export {
  ATTEMPT_METHOD,
  DEFAULT_REQUEST_TIMEOUT_MS,
  HandshakeNotSeenError,
  ID_PREFIX,
  INITIALIZE_METHOD,
  type JsonRpcFrame,
  McpAuditReceiver,
  McpAuditTransport,
  McpBindingError,
  type McpTransport,
  OUTCOME_METHOD,
  UnnegotiatedSendError,
} from './seam';
