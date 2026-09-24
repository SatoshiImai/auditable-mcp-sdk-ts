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
import { type KeyRegistry, KeyRole, type RegisteredKey, SignatureAlgorithm } from './keys';
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

  /** @throws {Error} If `registry` holds host keys (§10.9). */
  constructor(registry: KeyRegistry, options: { ed25519Engine?: Ed25519Engine; ecdsaVerify?: EcdsaVerify } = {}) {
    if (registry.role !== KeyRole.TOOL) {
      throw new Error('a Level-2 verifier needs a tool-key registry (§10.9)');
    }
    this.#registry = registry;
    this.#ed25519Engine = options.ed25519Engine ?? nobleEd25519Engine;
    this.#ecdsaVerify = options.ecdsaVerify ?? nobleEcdsaVerify;
  }

  /** Return true if the event's own Level-2 signature verifies (synchronous, §7.4). */
  readonly check = (event: Record<string, unknown>): boolean => this.rejectReason(event) === null;

  async verify(event: Record<string, unknown>): Promise<RejectReason | null> {
    return this.rejectReason(event);
  }

  private rejectReason(event: Record<string, unknown>): RejectReason | null {
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

/**
 * Return true if a detached base64 signature over already-canonical `payload` verifies.
 *
 * Unlike the event-level helpers above, the payload is supplied rather than derived, so this serves a
 * signature whose preimage is not an event - the witness signature over the host-assigned fields
 * (§7.1). The algorithm comes from the registry entry, as for events (§5.1).
 */
export function verifyDetachedSignature(
  payload: Uint8Array,
  signatureB64: string,
  entry: RegisteredKey,
  engines: { ed25519Engine?: Ed25519Engine; ecdsaVerify?: EcdsaVerify } = {},
): boolean {
  let signature: Uint8Array;
  try {
    signature = base64ToBytes(signatureB64);
  } catch {
    return false;
  }
  try {
    return entry.algorithm === SignatureAlgorithm.ED25519
      ? (engines.ed25519Engine ?? nobleEd25519Engine).verify(payload, signature, entry.publicKey)
      : (engines.ecdsaVerify ?? nobleEcdsaVerify)(payload, signature, entry.publicKey);
  } catch {
    return false;
  }
}

/**
 * A tool-side witness verifier backed by the out-of-band registry of host keys (§7.1, §10.9).
 *
 * The witness registry has the same shape and the same algorithm identifiers as the Level-2 one and
 * never shares an entry with it. A `host_key_id` with no current entry - never registered, or revoked
 * - does not establish the witness, which maps onto `host-signature-invalid` rather than earning a
 * code of its own (§7.6, §10.9).
 */
export class WitnessRegistryVerifier {
  readonly #registry: KeyRegistry;
  readonly #engines: { ed25519Engine?: Ed25519Engine; ecdsaVerify?: EcdsaVerify };

  /**
   * @throws {Error} If `registry` holds tool keys. A tool that can be found in the registry a verifier
   *   resolves `host_key_id` against can sign a witness payload with its own key and manufacture the
   *   host-witnessed state §5.2 says it cannot (§10.9).
   */
  constructor(registry: KeyRegistry, options: { ed25519Engine?: Ed25519Engine; ecdsaVerify?: EcdsaVerify } = {}) {
    if (registry.role !== KeyRole.HOST) {
      throw new Error('a witness verifier needs a host-key registry (§10.9)');
    }
    this.#registry = registry;
    this.#engines = options;
  }

  /**
   * Return true if the signature verifies against the registered host key (synchronous).
   *
   * Offline ledger verification (§11.4) is synchronous and reads stored records, so it uses this
   * directly; `verify` is the async form the tool-side seam expects.
   */
  readonly check = (hostKeyId: string, signature: string, payload: Uint8Array): boolean => {
    const entry = this.#registry.get(hostKeyId);
    if (entry === undefined) {
      return false;
    }
    return verifyDetachedSignature(payload, signature, entry, this.#engines);
  };

  /** Return true if the signature verifies against the registered host key (local, no I/O). */
  async verify(hostKeyId: string, signature: string, payload: Uint8Array): Promise<boolean> {
    return this.check(hostKeyId, signature, payload);
  }
}
