/**
 * The MCP bindings: the §6 exchange on a real MCP connection (§6.4, §6.5).
 *
 * This entry point declares the MCP transport surface structurally, so importing it pulls in no MCP
 * package at all — an official `Transport` satisfies it, and a seam satisfies what a session requires
 * of a transport.
 *
 * The tool's Streamable HTTP entry, which does depend on the official server package, is the separate
 * entry point `auditable-mcp-sdk/mcp/http`.
 */

export {
  AFFINITY_HEADER,
  FORWARDED_HEADER,
  FORWARDED_VALUE,
  HEADER_MISMATCH,
  INSTANCE_PATTERN,
  instanceOfToken,
  isInstanceId,
  mintRoundToken,
  newInstanceId,
  PROCESS_INSTANCE,
} from './affinity';

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
  DISCOVER_METHOD,
  HandshakeNotSeenError,
  ID_PREFIX,
  INITIALIZE_METHOD,
  type JsonRpcFrame,
  MAX_IDLE_SESSIONS,
  MAX_ROUNDS_PER_CALL,
  McpAuditCall,
  McpAuditReceiver,
  McpAuditTransport,
  McpBindingError,
  type McpTransport,
  NO_OPEN_ROUND_MESSAGE,
  OUTCOME_METHOD,
  ROUND_TOKEN_PREFIX,
  UnknownCallError,
  UnnegotiatedSendError,
} from './seam';
