/**
 * Node adapters bundled with the SDK.
 *
 * The core (`.`) is runtime-agnostic; this entry point supplies the Node-specific implementations of
 * the injection seams — ambient session binding (`AsyncLocalStorage`) here, and the `node:crypto`
 * signer/verifier engine alongside it. Importing `auditable-mcp-sdk/node` pulls in `node:*`; a
 * universal consumer imports only the core and injects its own adapters.
 */

export { audited, currentSession, runWithSession } from './context';
export { nodeEd25519Engine } from './crypto';
