/**
 * The Level-2 crypto seam.
 *
 * The L2 protocol logic (signature payload = canonical(event − signature), the key registry, the
 * per-key sequence) is crypto-primitive-agnostic. The actual Ed25519 / ECDSA operations sit behind
 * these injectable interfaces, so the SDK stays runtime-agnostic: the bundled noble engine
 * (`crypto/noble.ts`) is universal and the default; a `node:crypto` engine (`node/crypto.ts`) is a
 * drop-in Node alternative; and AWS KMS plugs in the same way (`l2/adapters/aws-kms.ts`).
 *
 * Keys are raw bytes so they are engine-neutral: a 32-byte Ed25519 seed / public key, and an
 * uncompressed EC point for ECDSA. Both engines produce interchangeable signatures.
 */

/** A raw Ed25519 key pair: 32-byte seed and 32-byte public key. */
export interface Ed25519KeyPair {
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

/** The Ed25519 primitive: keygen, detached sign, and verify over raw keys. */
export interface Ed25519Engine {
  generateKeyPair(): Ed25519KeyPair;
  sign(message: Uint8Array, privateKey: Uint8Array): Uint8Array;
  verify(message: Uint8Array, signature: Uint8Array, publicKey: Uint8Array): boolean;
}

/**
 * Verify an ECDSA (P-256 / SHA-256) signature over `payload` against a raw uncompressed EC point. The
 * signature is the fixed-length IEEE P1363 `r || s` form (§5.1), not DER. This is the KMS/HSM
 * verification primitive; signing there happens remotely in the adapter.
 */
export type EcdsaVerify = (payload: Uint8Array, signatureRaw: Uint8Array, publicKeyPoint: Uint8Array) => boolean;
