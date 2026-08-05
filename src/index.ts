/**
 * Auditable MCP SDK — a protocol machine for tool self-attestation into a tamper-evident ledger.
 *
 * This entry point is runtime-agnostic: canonicalization, hashing, signing, and the state machine,
 * with storage, transport, and crypto behind injection seams. Node-specific adapters (ambient session,
 * `node:crypto` engine) live in `auditable-mcp-sdk/node`; the default L2 crypto engine is the
 * universal noble engine, also exported from `auditable-mcp-sdk/noble`.
 *
 * The `spec_version` implemented is `auditable-mcp/0.2`.
 */

export {
  CanonicalizationError,
  CONTEXT_HASH_PREFIX,
  canonicalize,
  hashCanonical,
  hasUnsafeNumber,
  MAX_SAFE_INTEGER,
  sha256Hex,
} from './canonical';
export { capabilitySatisfies, type NegotiationResult, negotiate } from './capability';
export { type Clock, nowIso, SystemClock } from './clock';
export type { EcdsaVerify, Ed25519Engine, Ed25519KeyPair } from './crypto/engine';
export { computeRecordHash, GENESIS_HASH } from './hashing';
export {
  type AuditCapabilityInput,
  AuditHost,
  type AuditHostOptions,
  type IntegrityAnomaly,
  type SignatureVerifier,
} from './host';
export { InProcessTransport } from './in-process';
export {
  BoundaryObserver,
  Ed25519Signer,
  type EgressObservation,
  generateToolKey,
  KeyRegistry,
  KeyRegistryVerifier,
  type ReconcileAnomaly,
  type RegisteredKey,
  reconcile,
  SignatureAlgorithm,
  signaturePayload,
  signEvent,
  type ToolKey,
  verifyEcdsaSignature,
  verifyEd25519Signature,
} from './l2';
export { Ledger, type SealedRecord } from './ledger';
export {
  type AcceptResponse,
  type AttemptResponse,
  type AuditCapability,
  type AuditEvent,
  acceptResponseSchema,
  attemptResponseSchema,
  auditCapabilitySchema,
  auditEventSchema,
  firstValidationError,
  Level,
  Outcome,
  type RejectReason,
  type RejectResponse,
  rejectResponseSchema,
  SPEC_VERSION,
  Status,
  type TargetResource,
  targetResourceSchema,
  type UnavailableResponse,
  unavailableResponseSchema,
} from './models';
export {
  type ActionOptions,
  AmcpAbortedError,
  AmcpSession,
  AuditedAction,
  type Deps,
  type EventSigner,
  SystemDeps,
} from './session';
export { InMemoryLedgerRepository, type LedgerRepository, RepositoryError } from './storage';
export { type AuditEndpoint, type AuditTransport, accept, reject, unavailable } from './transport';
export { type VerifyIssue, type VerifyReport, verifyChain, verifyLedger } from './verify';
export { type AuditSpec, withAudit } from './with-audit';

export const VERSION = '0.1.0';
