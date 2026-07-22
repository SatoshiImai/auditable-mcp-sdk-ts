/**
 * The default, universal Level-2 crypto engine, backed by @noble/curves.
 *
 * noble runs in every JavaScript runtime (Node, browsers, Deno, edge/Workers), so it is the SDK's
 * out-of-the-box engine and needs no configuration. Import this module directly (`auditable-mcp-sdk/
 * noble`) only when you want to pass the engine explicitly.
 */

import { ed25519 } from '@noble/curves/ed25519';
import { p256 } from '@noble/curves/nist';
import { sha256 } from '@noble/hashes/sha2';
import type { EcdsaVerify, Ed25519Engine } from './engine';

/** The universal Ed25519 engine used by default across the L2 layer. */
export const nobleEd25519Engine: Ed25519Engine = {
  generateKeyPair() {
    const { secretKey, publicKey } = ed25519.keygen();
    return { privateKey: secretKey, publicKey };
  },
  sign(message, privateKey) {
    return ed25519.sign(message, privateKey);
  },
  verify(message, signature, publicKey) {
    return ed25519.verify(signature, message, publicKey);
  },
};

/** The universal ECDSA (P-256 / SHA-256) verify primitive used by default for KMS/HSM keys. */
export const nobleEcdsaVerify: EcdsaVerify = (payload, signatureRaw, publicKeyPoint) => {
  const digest = sha256(payload);
  // The wire signature is the fixed 64-byte IEEE P1363 r||s form (§5.1), which noble accepts directly.
  // lowS:false — a KMS ECDSA_SHA_256 signature may be high-S; it still authenticates.
  return p256.verify(signatureRaw, digest, publicKeyPoint, { lowS: false });
};
