/**
 * Level 2: Ed25519 signing, verification, key material, and boundary reconciliation.
 *
 * L1 and L2 share one event schema and one lifecycle; L2 only adds the signer (tool side) and the
 * signature verifier (host side), which `AmcpSession` and `AuditHost` already accept via injection.
 */

export { generateToolKey, KeyRegistry, type ToolKey } from './keys';
export {
  BoundaryObserver,
  type EgressObservation,
  type ReconcileAnomaly,
  reconcile,
} from './reconcile';
export { Ed25519Signer, signaturePayload, signEvent } from './signing';
export {
  EcdsaSignatureVerifier,
  Ed25519SignatureVerifier,
  verifyEcdsaSignature,
  verifyEd25519Signature,
} from './verification';
