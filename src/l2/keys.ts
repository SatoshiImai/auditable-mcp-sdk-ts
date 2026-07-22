/**
 * Level-2 key material: Ed25519 tool keys and the host's public-key registry.
 *
 * A tool holds a private key and signs its self-attestations; the host verifies against a public key
 * registered out-of-band at onboarding (the trust anchor). The signature gives non-repudiation, not
 * real-time control (§5, §10.2). Keys are raw bytes (engine-neutral); a `key_id` the host has never
 * onboarded is untrusted and its events are rejected as unverifiable.
 */

import type { Ed25519Engine } from '../crypto/engine';
import { nobleEd25519Engine } from '../crypto/noble';

/** A tool's Ed25519 key pair and its identity (raw bytes). */
export interface ToolKey {
  keyId: string;
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

/** Generate a fresh Ed25519 tool key under `key_id` (using the injected engine; noble by default). */
export function generateToolKey(keyId: string, engine: Ed25519Engine = nobleEd25519Engine): ToolKey {
  const { publicKey, privateKey } = engine.generateKeyPair();
  return { keyId, publicKey, privateKey };
}

/**
 * Maps `key_id` to a registered public key, established out-of-band at onboarding.
 *
 * Public keys are raw bytes for both schemes — a 32-byte Ed25519 key or an uncompressed EC point for
 * ECDSA — so one registry type serves both verifiers.
 */
export class KeyRegistry {
  #keys = new Map<string, Uint8Array>();

  /** Register a public key under its `key_id`. */
  register(keyId: string, publicKey: Uint8Array): void {
    this.#keys.set(keyId, publicKey);
  }

  /** Register the public half of a generated Ed25519 tool key. */
  registerToolKey(toolKey: ToolKey): void {
    this.#keys.set(toolKey.keyId, toolKey.publicKey);
  }

  /** Return the registered public key for `key_id`, or undefined if unknown. */
  get(keyId: string): Uint8Array | undefined {
    return this.#keys.get(keyId);
  }
}
