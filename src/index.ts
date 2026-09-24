/**
 * Auditable MCP SDK — a protocol machine for tool self-attestation into a tamper-evident ledger.
 *
 * This entry point is runtime-agnostic: canonicalization, hashing, signing, and the state machine,
 * with storage, transport, and crypto behind injection seams. Node-specific adapters (ambient session,
 * `node:crypto` engine) live in `auditable-mcp-sdk/node`; the default L2 crypto engine is the
 * universal noble engine, also exported from `auditable-mcp-sdk/noble`.
 *
 * The `spec_version` implemented is `auditable-mcp/0.3`.
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
export {
  levelSatisfies,
  NegotiationOutcome,
  type NegotiationResult,
  negotiate,
  witnessSatisfies,
} from './capability';
export { type Clock, nowIso, SystemClock } from './clock';
export type { EcdsaVerify, Ed25519Engine, Ed25519KeyPair } from './crypto/engine';
export { Posture, transportFor, UnnegotiatedSessionError } from './degradation';
export {
  computeRecordHash,
  GENESIS_HASH,
  witnessPayload,
} from './hashing';
export {
  type AuditCapabilityInput,
  AuditHost,
  type AuditHostOptions,
  type IntegrityAnomaly,
  type SignatureVerifier,
  type WitnessSigner,
} from './host';
export { InProcessTransport } from './in-process';
export {
  BoundaryObserver,
  Ed25519Signer,
  Ed25519WitnessSigner,
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
  verifyDetachedSignature,
  verifyEcdsaSignature,
  verifyEd25519Signature,
  WitnessRegistryVerifier,
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
  EXTENSION_ID,
  firstSealedValidationError,
  firstValidationError,
  KNOWN_SPEC_VERSIONS,
  Level,
  Outcome,
  type RejectReason,
  type RejectResponse,
  rejectResponseSchema,
  SPEC_VERSION,
  Status,
  sealedAuditEventSchema,
  type TargetResource,
  targetResourceSchema,
  type UnavailableResponse,
  unavailableResponseSchema,
  Witness,
} from './models';
export {
  type ActionOptions,
  AmcpAbortedError,
  AmcpSession,
  AuditedAction,
  type Deps,
  type EventSigner,
  SystemDeps,
  type WitnessVerifier,
} from './session';
export { InMemoryLedgerRepository, type LedgerRepository, RepositoryError } from './storage';
export { type AuditEndpoint, type AuditTransport, accept, reject, unavailable } from './transport';
export {
  DEFAULT_ADAPTER,
  type RecordAdapter,
  type SignatureChecker,
  type VerifyIssue,
  type VerifyReport,
  verifyChain,
  verifyLedger,
  type WitnessChecker,
} from './verify';
export { type AuditSpec, withAudit } from './with-audit';

export const VERSION = '0.2.1';
