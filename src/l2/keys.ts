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

/** Generate a fresh Ed25519 tool key under `key_id` (using the injected engine; noble by default). */
export function generateToolKey(keyId: string, engine: Ed25519Engine = nobleEd25519Engine): ToolKey {
  const { publicKey, privateKey } = engine.generateKeyPair();
  return { keyId, publicKey, privateKey };
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
export class KeyRegistry {
  #keys = new Map<string, RegisteredKey>();

  /**
   * Register a public key and its algorithm under `key_id`.
   *
   * @throws {Error} If `key_id` is already bound to a different key or algorithm (§10.9: rotation must
   *   use a fresh `key_id`). Re-registering the same key is idempotent.
   */
  register(keyId: string, publicKey: Uint8Array, algorithm: SignatureAlgorithm): void {
    const existing = this.#keys.get(keyId);
    if (existing !== undefined && (existing.algorithm !== algorithm || !bytesEqual(existing.publicKey, publicKey))) {
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
