/**
 * Level-2 key material: Ed25519 tool keys and the host's public-key registry.
 *
 * A tool holds a private key and signs its self-attestations; the host verifies against a public key
 * registered out-of-band at onboarding (the trust anchor). The signature gives non-repudiation, not
 * real-time control (§5, §10.2). Keys are raw bytes (engine-neutral): a 32-byte Ed25519 key, or an
 * uncompressed EC point for ECDSA.
 *
 * §5.1 binds the signature algorithm to the `key_id` through this registry (the event carries no
 * algorithm), so one host verifies a heterogeneous fleet — Ed25519 tools alongside KMS ECDSA P-256
 * tools. §10.9 governs lifecycle: a `key_id` maps to exactly one key for life (re-registering it with
 * a different key is forbidden — rotation uses a fresh `key_id`), and revocation is forward-only.
 */

import { p256 } from '@noble/curves/nist';
import type { Ed25519Engine } from '../crypto/engine';
import { nobleEd25519Engine } from '../crypto/noble';

/** The signature algorithms defined by this version (§5.1). */
export const SignatureAlgorithm = {
  ED25519: 'Ed25519',
  ECDSA_P256_SHA256: 'ECDSA_P256_SHA256',
} as const;
export type SignatureAlgorithm = (typeof SignatureAlgorithm)[keyof typeof SignatureAlgorithm];

/** A tool's Ed25519 key pair and its identity (raw bytes). */
export interface ToolKey {
  keyId: string;
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

/** A registered public key and the algorithm bound to its `key_id` (§5.1). */
export interface RegisteredKey {
  algorithm: SignatureAlgorithm;
  publicKey: Uint8Array;
}

/** Ed25519 public keys are 32 raw bytes [RFC-8032]. */
const ED25519_PUBLIC_KEY_BYTES = 32;
/** P-256 points are SEC1: 65 bytes uncompressed (0x04) or 33 compressed (0x02/0x03) [FIPS-186-5]. */
const P256_UNCOMPRESSED_BYTES = 65;
const P256_COMPRESSED_BYTES = 33;

function keyLengthFits(publicKey: Uint8Array, algorithm: SignatureAlgorithm): boolean {
  if (algorithm === SignatureAlgorithm.ED25519) {
    return publicKey.length === ED25519_PUBLIC_KEY_BYTES;
  }
  if (publicKey.length === P256_UNCOMPRESSED_BYTES) {
    return publicKey[0] === 0x04;
  }
  return publicKey.length === P256_COMPRESSED_BYTES && (publicKey[0] === 0x02 || publicKey[0] === 0x03);
}

/** Generate a fresh Ed25519 tool key under `key_id` (using the injected engine; noble by default). */
export function generateToolKey(keyId: string, engine: Ed25519Engine = nobleEd25519Engine): ToolKey {
  const { publicKey, privateKey } = engine.generateKeyPair();
  return { keyId, publicKey, privateKey };
}

/**
 * Whether two entries hold the same public key.
 *
 * Compared as keys, not as bytes: §5.1 admits both SEC1 forms of a P-256 point, so the compressed
 * and uncompressed encodings of one key are one key, and re-registering it is the idempotent case
 * §10.9 permits rather than the different-key case it forbids. The Python port compares the DER
 * form for the same reason.
 */
function sameKey(a: Uint8Array, b: Uint8Array, algorithm: SignatureAlgorithm): boolean {
  if (algorithm === SignatureAlgorithm.ED25519) {
    return bytesEqual(a, b);
  }
  try {
    return bytesEqual(p256.Point.fromBytes(a).toBytes(false), p256.Point.fromBytes(b).toBytes(false));
  } catch {
    // A point neither form parses is not a key this registry can hold; the §5.1 guard above refuses
    // it at registration, so reaching here means the stored entry predates that guard.
    return bytesEqual(a, b);
  }
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}

/**
 * Maps `key_id` to its bound algorithm and public key, established out-of-band at onboarding (§5.1).
 *
 * Public keys are raw bytes for both schemes — a 32-byte Ed25519 key or an uncompressed EC point for
 * ECDSA — so one registry serves the unified verifier.
 */
/**
 * Whose keys a registry holds (§5.1 for a tool's, §7.1 for a host's).
 *
 * §10.9 requires the two registries to share no entry, and the only way an SDK can hold that is to
 * make one registry serve one role. Without it a single registry serves both, a tool's own key
 * resolves as a `host_key_id`, and the tool manufactures the host-witnessed state §5.2 says it cannot
 * — defeating the axis rather than degrading it.
 */
export const KeyRole = {
  TOOL: 'tool',
  HOST: 'host',
} as const;
export type KeyRole = (typeof KeyRole)[keyof typeof KeyRole];

export class KeyRegistry {
  /** Whose keys this registry holds; the two roles never share an entry (§10.9). */
  readonly role: KeyRole;

  #keys = new Map<string, RegisteredKey>();

  constructor(role: KeyRole = KeyRole.TOOL) {
    this.role = role;
  }

  /**
   * Register a public key and its algorithm under `key_id`.
   *
   * @throws {Error} If `key_id` is already bound to a different key or algorithm (§10.9: rotation must
   *   use a fresh `key_id`). Re-registering the same key is idempotent.
   */
  register(keyId: string, publicKey: Uint8Array, algorithm: SignatureAlgorithm): void {
    if (keyId.length === 0) {
      throw new Error('a registry entry binds a non-empty key_id (§5.1)');
    }
    // §5.1: the public key MUST be a key of the entry's algorithm, and a disagreeing entry is refused
    // here rather than carried to verification time, where every event bound to it would be rejected
    // signature-invalid - a forged signature, which is not what went wrong.
    if (!keyLengthFits(publicKey, algorithm)) {
      throw new Error(`a ${algorithm} entry does not bind a ${publicKey.length}-byte key (§5.1)`);
    }
    const existing = this.#keys.get(keyId);
    if (
      existing !== undefined &&
      (existing.algorithm !== algorithm || !sameKey(existing.publicKey, publicKey, algorithm))
    ) {
      throw new Error(`key_id '${keyId}' is already registered with a different key (§10.9)`);
    }
    this.#keys.set(keyId, { algorithm, publicKey });
  }

  /** Register the public half of a generated Ed25519 tool key. */
  registerToolKey(toolKey: ToolKey): void {
    this.register(toolKey.keyId, toolKey.publicKey, SignatureAlgorithm.ED25519);
  }

  /** Revoke `key_id`; it is thereafter `unknown-key` (forward-only, §10.9). Sealed records stay valid. */
  revoke(keyId: string): void {
    this.#keys.delete(keyId);
  }

  /** Return the registered key + algorithm for `key_id`, or undefined if unknown. */
  get(keyId: string): RegisteredKey | undefined {
    return this.#keys.get(keyId);
  }
}
