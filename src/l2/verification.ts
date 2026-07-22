/**
 * Level-2 verification (host side).
 *
 * Two detached-signature primitives over canonical(event − signature) (§8.2): Ed25519 and ECDSA
 * (AWS KMS does not offer Ed25519, so ECDSA covers the KMS/HSM case). `Ed25519SignatureVerifier` and
 * `EcdsaSignatureVerifier` are the symmetric host `SignatureVerifier` implementations: each resolves
 * the `key_id` in a `KeyRegistry` and returns a reject reason (`unknown-key` / `signature-invalid`)
 * or null. Verification is local — the public key is public, onboarded once — so no per-event KMS
 * call is needed.
 */

import { base64ToBytes } from '../crypto/base64';
import type { EcdsaVerify, Ed25519Engine } from '../crypto/engine';
import { nobleEcdsaVerify, nobleEd25519Engine } from '../crypto/noble';
import * as fields from '../fields';
import type { SignatureVerifier } from '../host';
import * as reasons from '../reasons';
import type { KeyRegistry } from './keys';
import { signaturePayload } from './signing';

function decodeSignature(event: Record<string, unknown>): Uint8Array | null {
  const signature = event[fields.SIGNATURE];
  if (typeof signature !== 'string') {
    return null;
  }
  try {
    return base64ToBytes(signature);
  } catch {
    return null;
  }
}

/** Return true if the event's base64 Ed25519 signature verifies against `publicKey`. */
export function verifyEd25519Signature(
  event: Record<string, unknown>,
  publicKey: Uint8Array,
  engine: Ed25519Engine = nobleEd25519Engine,
): boolean {
  const signature = decodeSignature(event);
  if (signature === null) {
    return false;
  }
  try {
    return engine.verify(signaturePayload(event), signature, publicKey);
  } catch {
    return false;
  }
}

/** Return true if the event's base64 DER-ECDSA signature verifies against the raw EC point. */
export function verifyEcdsaSignature(
  event: Record<string, unknown>,
  publicKeyPoint: Uint8Array,
  ecdsaVerify: EcdsaVerify = nobleEcdsaVerify,
): boolean {
  const signature = decodeSignature(event);
  if (signature === null) {
    return false;
  }
  try {
    return ecdsaVerify(signaturePayload(event), signature, publicKeyPoint);
  } catch {
    return false;
  }
}

/** A host `SignatureVerifier` backed by an Ed25519 public-key registry. */
export class Ed25519SignatureVerifier implements SignatureVerifier {
  readonly #registry: KeyRegistry;
  readonly #engine: Ed25519Engine;

  constructor(registry: KeyRegistry, engine: Ed25519Engine = nobleEd25519Engine) {
    this.#registry = registry;
    this.#engine = engine;
  }

  async verify(event: Record<string, unknown>): Promise<string | null> {
    const keyId = event[fields.KEY_ID];
    const publicKey = typeof keyId === 'string' ? this.#registry.get(keyId) : undefined;
    if (publicKey === undefined) {
      return reasons.UNKNOWN_KEY;
    }
    if (!verifyEd25519Signature(event, publicKey, this.#engine)) {
      return reasons.SIGNATURE_INVALID;
    }
    return null;
  }
}

/**
 * A host `SignatureVerifier` backed by an elliptic-curve public-key registry (ECDSA).
 *
 * The symmetric counterpart to `Ed25519SignatureVerifier` for keys held in a KMS/HSM or elsewhere;
 * populate its registry with raw EC points (e.g. loaded from KMS, see `l2/adapters/aws-kms.ts`).
 */
export class EcdsaSignatureVerifier implements SignatureVerifier {
  readonly #registry: KeyRegistry;
  readonly #ecdsaVerify: EcdsaVerify;

  constructor(registry: KeyRegistry, options: { ecdsaVerify?: EcdsaVerify } = {}) {
    this.#registry = registry;
    this.#ecdsaVerify = options.ecdsaVerify ?? nobleEcdsaVerify;
  }

  async verify(event: Record<string, unknown>): Promise<string | null> {
    const keyId = event[fields.KEY_ID];
    const publicKey = typeof keyId === 'string' ? this.#registry.get(keyId) : undefined;
    if (publicKey === undefined) {
      return reasons.UNKNOWN_KEY;
    }
    if (!verifyEcdsaSignature(event, publicKey, this.#ecdsaVerify)) {
      return reasons.SIGNATURE_INVALID;
    }
    return null;
  }
}
