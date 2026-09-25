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
  hasLoneSurrogate,
  hasUnsafeNumber,
  MAX_SAFE_INTEGER,
  sha256Hex,
} from './canonical';
export {
  countersignSatisfies,
  levelSatisfies,
  NegotiationOutcome,
  type NegotiationResult,
  negotiate,
} from './capability';
export { type Clock, nowIso, SystemClock } from './clock';
export type { EcdsaVerify, Ed25519Engine, Ed25519KeyPair } from './crypto/engine';
export { Posture, transportFor, UnnegotiatedCallError } from './degradation';
export {
  computeRecordHash,
  countersignaturePayload,
  GENESIS_HASH,
} from './hashing';
export {
  type AuditCapabilityInput,
  AuditHost,
  type AuditHostOptions,
  type Countersigner,
  type IntegrityAnomaly,
  type SignatureVerifier,
} from './host';
export { InProcessTransport } from './in-process';
export {
  assertRegistriesDisjoint,
  BoundaryObserver,
  CountersignatureRegistryVerifier,
  Ed25519Countersigner,
  Ed25519Signer,
  type EgressObservation,
  generateToolKey,
  type Jwk,
  type JwkEntry,
  type JwkSet,
  jwkThumbprint,
  KeyRegistry,
  KeyRegistryVerifier,
  KeyRole,
  loadToolKey,
  publicJwk,
  publicKeyOf,
  REVOKED_MEMBER,
  type ReconcileAnomaly,
  type RegisteredKey,
  ROLE_MEMBER,
  reconcile,
  SignatureAlgorithm,
  signaturePayload,
  signEvent,
  type ToolKey,
  toolKeyPkcs8,
  verifyDetachedSignature,
  verifyEcdsaSignature,
  verifyEd25519Signature,
} from './l2';
export { Ledger, type SealedRecord } from './ledger';
export {
  type AcceptResponse,
  type AttemptResponse,
  type AuditCapability,
  type AuditEvent,
  type AuditRequestMeta,
  type AuditResultMeta,
  acceptResponseSchema,
  attemptResponseSchema,
  auditCapabilitySchema,
  auditEventSchema,
  auditRequestMetaSchema,
  auditResultMetaSchema,
  Countersign,
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
  type TargetResource,
  targetResourceSchema,
  type UnavailableResponse,
  unavailableResponseSchema,
} from './models';
export type { AbortReason } from './reasons';
export {
  type ActionOptions,
  AmcpAbortedError,
  AmcpSession,
  AuditedAction,
  type CountersignatureVerifier,
  type Deps,
  type EventSigner,
  newSessionId,
  SessionNumbering,
  SystemDeps,
} from './session';
export { InMemoryLedgerRepository, type LedgerRepository, RepositoryError } from './storage';
export { AmcpUsageError, type AuditEndpoint, type AuditTransport, accept, reject, unavailable } from './transport';
export {
  type CountersignatureChecker,
  DEFAULT_ADAPTER,
  type ExpectedIdentity,
  type RecordAdapter,
  type SignatureChecker,
  type UnaccountedSignerSeq,
  unaccountedSignerSeq,
  type VerifyIssue,
  type VerifyLedgerOptions,
  type VerifyOptions,
  type VerifyReport,
  verifyChain,
  verifyLedger,
} from './verify';
export { type AuditSpec, withAudit } from './with-audit';

export const VERSION = '0.3.0';
