/**
 * Level-2 verification (host side).
 *
 * Two detached-signature primitives over canonical(event − signature) (§8.2): Ed25519 and ECDSA
 * P-256/SHA-256 (AWS KMS does not offer Ed25519, so ECDSA covers the KMS/HSM case). `KeyRegistryVerifier`
 * is the host `SignatureVerifier`: it resolves the `key_id` in a `KeyRegistry`, dispatches to the
 * algorithm bound to that key (§5.1), and returns a Tier-1 reject reason (`unknown-key` /
 * `signature-invalid`) or null. Verification is local — the public key is public, onboarded once — so
 * no per-event KMS call is needed. One verifier handles a heterogeneous fleet.
 */

import { base64ToBytes } from '../crypto/base64';
import type { EcdsaVerify, Ed25519Engine } from '../crypto/engine';
import { nobleEcdsaVerify, nobleEd25519Engine } from '../crypto/noble';
import * as fields from '../fields';
import type { SignatureVerifier } from '../host';
import type { RejectReason } from '../models';
import * as reasons from '../reasons';
import { type KeyRegistry, SignatureAlgorithm } from './keys';
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

/**
 * Return true if the event's base64 signature verifies as ECDSA P-256/SHA-256 against the raw EC point.
 *
 * The signature is the fixed-length IEEE P1363 `r || s` form (§5.1), not DER; a wrong-length or
 * undecodable value verifies false (mapped to `signature-invalid` by the caller).
 */
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

/**
 * A host `SignatureVerifier` backed by an algorithm-bound `KeyRegistry`.
 *
 * Per event it resolves `key_id` to its registry entry and dispatches to the bound algorithm's
 * primitive, so Ed25519 and ECDSA P-256 tools verify through one instance (§5.1). The crypto engines
 * are injectable (noble by default).
 */
export class KeyRegistryVerifier implements SignatureVerifier {
  readonly #registry: KeyRegistry;
  readonly #ed25519Engine: Ed25519Engine;
  readonly #ecdsaVerify: EcdsaVerify;

  constructor(registry: KeyRegistry, options: { ed25519Engine?: Ed25519Engine; ecdsaVerify?: EcdsaVerify } = {}) {
    this.#registry = registry;
    this.#ed25519Engine = options.ed25519Engine ?? nobleEd25519Engine;
    this.#ecdsaVerify = options.ecdsaVerify ?? nobleEcdsaVerify;
  }

  async verify(event: Record<string, unknown>): Promise<RejectReason | null> {
    const keyId = event[fields.KEY_ID];
    const entry = typeof keyId === 'string' ? this.#registry.get(keyId) : undefined;
    if (entry === undefined) {
      return reasons.UNKNOWN_KEY;
    }
    const verified =
      entry.algorithm === SignatureAlgorithm.ED25519
        ? verifyEd25519Signature(event, entry.publicKey, this.#ed25519Engine)
        : verifyEcdsaSignature(event, entry.publicKey, this.#ecdsaVerify);
    return verified ? null : reasons.SIGNATURE_INVALID;
  }
}
