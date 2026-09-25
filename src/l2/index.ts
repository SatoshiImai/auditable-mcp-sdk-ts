/**
 * Level 2: Ed25519 / ECDSA signing, verification, key material, and boundary reconciliation.
 *
 * L1 and L2 share one event schema and one lifecycle; L2 only adds the signer (tool side) and the
 * signature verifier (host side), which `AmcpSession` and `AuditHost` already accept via injection.
 */

export {
  type Jwk,
  type JwkEntry,
  type JwkSet,
  jwkThumbprint,
  publicJwk,
  publicKeyOf,
  REVOKED_MEMBER,
  ROLE_MEMBER,
} from './jwk';
export {
  assertRegistriesDisjoint,
  generateToolKey,
  KeyRegistry,
  KeyRole,
  loadToolKey,
  type RegisteredKey,
  SignatureAlgorithm,
  type ToolKey,
  toolKeyPkcs8,
} from './keys';
export {
  BoundaryObserver,
  type EgressObservation,
  type ReconcileAnomaly,
  reconcile,
} from './reconcile';
export { Ed25519Countersigner, Ed25519Signer, signaturePayload, signEvent } from './signing';
export {
  CountersignatureRegistryVerifier,
  KeyRegistryVerifier,
  verifyDetachedSignature,
  verifyEcdsaSignature,
  verifyEd25519Signature,
} from './verification';
