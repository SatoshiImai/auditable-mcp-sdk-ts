/**
 * Level-2 verification (host side).
 *
 * Two detached-signature primitives over canonical(event − signature) (§8.2): `Ed25519` and `ES256`
 * (which every HSM and KMS offers). `KeyRegistryVerifier`
 * is the host `SignatureVerifier`: it resolves the `key_id` in a `KeyRegistry`, dispatches to the
 * algorithm bound to that key (§5.1), and returns a Tier-1 reject reason (`unknown-key` /
 * `signature-invalid`) or null. Verification is local — the public key is public, onboarded once — so
 * no per-event KMS call is needed. One verifier handles a heterogeneous fleet.
 */

import { base64ToBytes, base64urlToBytes } from '../crypto/base64';
import type { EcdsaVerify, Ed25519Engine } from '../crypto/engine';
import { ES256_SIGNATURE_BYTES, nobleEcdsaVerify, nobleEd25519Engine } from '../crypto/noble';
import * as fields from '../fields';
import type { SignatureVerifier } from '../host';
import { isEarlierSpecVersion, type RejectReason } from '../models';
import * as reasons from '../reasons';
import { type KeyRegistry, KeyRole, type RegisteredKey, SignatureAlgorithm } from './keys';
import { signaturePayload } from './signing';

/** Both algorithms of §5.1 produce a fixed 64-byte raw signature. */
const RAW_SIGNATURE_BYTES = { [SignatureAlgorithm.ED25519]: 64, [SignatureAlgorithm.ES256]: ES256_SIGNATURE_BYTES };

/**
 * Decode the event's signature as its own version encoded it (§11.4): base64url without padding from
 * v0.3, standard padded base64 before it.
 */
function decodeSignature(event: Record<string, unknown>): Uint8Array | null {
  const encoded = event[fields.SIGNATURE];
  if (isEarlierSpecVersion(event[fields.SPEC_VERSION])) {
    if (typeof encoded !== 'string') {
      return null;
    }
    try {
      return base64ToBytes(encoded);
    } catch {
      return null;
    }
  }
  return base64urlToBytes(encoded) ?? null;
}

/** Run a primitive only on a signature of the algorithm's fixed length; anything else fails (§5.1). */
function verifyRaw(algorithm: SignatureAlgorithm, signature: Uint8Array, verify: () => boolean): boolean {
  if (signature.length !== RAW_SIGNATURE_BYTES[algorithm]) {
    return false;
  }
  try {
    return verify();
  } catch {
    return false;
  }
}

/** Return true if the event's base64url Ed25519 signature verifies against `publicKey`. */
export function verifyEd25519Signature(
  event: Record<string, unknown>,
  publicKey: Uint8Array,
  engine: Ed25519Engine = nobleEd25519Engine,
): boolean {
  const signature = decodeSignature(event);
  if (signature === null) {
    return false;
  }
  return verifyRaw(SignatureAlgorithm.ED25519, signature, () =>
    engine.verify(signaturePayload(event), signature, publicKey),
  );
}

/**
 * Return true if the event's base64url signature verifies as ES256 against the raw EC point.
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
  return verifyRaw(SignatureAlgorithm.ES256, signature, () =>
    ecdsaVerify(signaturePayload(event), signature, publicKeyPoint),
  );
}

/**
 * A host `SignatureVerifier` backed by an algorithm-bound `KeyRegistry`.
 *
 * Per event it resolves `key_id` to its registry entry and dispatches to the bound algorithm's
 * primitive, so Ed25519 and ECDSA P-256 tools verify through one instance (§5.1). The crypto engines
 * are injectable (noble by default).
 *
 * The two entry points read revocation differently (§10.9). `verify` is the host's: an event arriving
 * under a revoked key is `unknown-key`. `check` is the ledger verifier's: a record sealed while the key
 * was valid still verifies against the revoked entry.
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

  /** Return true if a sealed event's Level-2 signature verifies, revoked keys included (§10.9, §11.4). */
  readonly check = (event: Record<string, unknown>): boolean => this.rejectReason(event, true) === null;

  /** The host's check: a revoked key is `unknown-key` for every event that arrives now (§10.9). */
  async verify(event: Record<string, unknown>): Promise<RejectReason | null> {
    return this.rejectReason(event, false);
  }

  private rejectReason(event: Record<string, unknown>, includeRevoked: boolean): RejectReason | null {
    const keyId = event[fields.KEY_ID];
    const entry = typeof keyId === 'string' ? this.#registry.get(keyId) : undefined;
    if (entry === undefined || (!includeRevoked && this.#registry.isRevoked(keyId as string))) {
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
 * Return true if a detached base64url signature over already-canonical `payload` verifies.
 *
 * Unlike the event-level helpers above, the payload is supplied rather than derived, so this serves a
 * signature whose preimage is not an event - the countersignature over the host-assigned fields
 * (§7.1). The algorithm comes from the registry entry, as for events (§5.1).
 */
export function verifyDetachedSignature(
  payload: Uint8Array,
  encodedSignature: string,
  entry: RegisteredKey,
  engines: { ed25519Engine?: Ed25519Engine; ecdsaVerify?: EcdsaVerify } = {},
): boolean {
  const signature = base64urlToBytes(encodedSignature);
  if (signature === undefined) {
    return false;
  }
  return verifyRaw(entry.algorithm, signature, () =>
    entry.algorithm === SignatureAlgorithm.ED25519
      ? (engines.ed25519Engine ?? nobleEd25519Engine).verify(payload, signature, entry.publicKey)
      : (engines.ecdsaVerify ?? nobleEcdsaVerify)(payload, signature, entry.publicKey),
  );
}

/**
 * A tool-side countersign verifier backed by the out-of-band registry of host keys (§7.1, §10.9).
 *
 * The countersign registry has the same shape and the same algorithm identifiers as the Level-2 one and
 * never shares a key with it (`assertRegistriesDisjoint`). A `host_key_id` with no entry does not
 * establish the countersignature, which maps onto `host-signature-invalid` rather than earning a code of
 * its own (§7.6, §10.9).
 *
 * As for `KeyRegistryVerifier`, the two entry points read revocation differently (§10.9): `verify` is the
 * tool's check of a live accept, and a revoked key confirms nothing new; `check` is the ledger verifier's,
 * and a record countersigned while the key was valid still verifies against the revoked entry.
 */
export class CountersignatureRegistryVerifier {
  readonly #registry: KeyRegistry;
  readonly #engines: { ed25519Engine?: Ed25519Engine; ecdsaVerify?: EcdsaVerify };

  /**
   * @throws {Error} If `registry` holds tool keys. A tool that can be found in the registry a verifier
   *   resolves `host_key_id` against can sign a countersign payload with its own key and manufacture the
   *   host-countersigned state §5.2 says it cannot (§10.9).
   */
  constructor(registry: KeyRegistry, options: { ed25519Engine?: Ed25519Engine; ecdsaVerify?: EcdsaVerify } = {}) {
    if (registry.role !== KeyRole.HOST) {
      throw new Error('a countersign verifier needs a host-key registry (§10.9)');
    }
    this.#registry = registry;
    this.#engines = options;
  }

  /**
   * Return true if a sealed record's countersignature verifies, revoked keys included (synchronous).
   *
   * Offline ledger verification (§11.4) is synchronous and reads stored records, so it uses this
   * directly.
   */
  readonly check = (hostKeyId: string, signature: string, payload: Uint8Array): boolean => {
    const entry = this.#registry.get(hostKeyId);
    if (entry === undefined) {
      return false;
    }
    return verifyDetachedSignature(payload, signature, entry, this.#engines);
  };

  /** The tool's check of a live accept: false under a revoked or unknown host key (§7.2, §10.9). */
  async verify(hostKeyId: string, signature: string, payload: Uint8Array): Promise<boolean> {
    return !this.#registry.isRevoked(hostKeyId) && this.check(hostKeyId, signature, payload);
  }
}
