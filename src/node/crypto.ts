/**
 * A `node:crypto` Ed25519 engine — the Node-native alternative to the default noble engine.
 *
 * It speaks the same raw-bytes contract (32-byte seed / public key), so it is a drop-in replacement
 * that produces interchangeable signatures. Raw keys are wrapped in the fixed Ed25519 PKCS#8 / SPKI
 * DER framing to build the `KeyObject`s `node:crypto` requires. Inject it via the signer/verifier
 * `engine` option when you prefer the platform crypto over a bundled implementation.
 */

import { createPrivateKey, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';
import type { Ed25519Engine, Ed25519KeyPair } from '../crypto/engine';

// Fixed ASN.1 DER framing for a raw 32-byte Ed25519 seed (PKCS#8) and public key (SPKI).
const PKCS8_PREFIX = Buffer.from('302e020100300506032b657004220420', 'hex');
const SPKI_PREFIX = Buffer.from('302a300506032b6570032100', 'hex');

function privateKeyFromSeed(seed: Uint8Array) {
  return createPrivateKey({ key: Buffer.concat([PKCS8_PREFIX, Buffer.from(seed)]), format: 'der', type: 'pkcs8' });
}

function publicKeyFromRaw(publicKey: Uint8Array) {
  return createPublicKey({ key: Buffer.concat([SPKI_PREFIX, Buffer.from(publicKey)]), format: 'der', type: 'spki' });
}

/** The Node-native Ed25519 engine (raw-key compatible with the noble engine). */
export const nodeEd25519Engine: Ed25519Engine = {
  generateKeyPair(): Ed25519KeyPair {
    const { publicKey, privateKey } = generateKeyPairSync('ed25519');
    const publicJwk = publicKey.export({ format: 'jwk' }) as { x: string };
    const privateJwk = privateKey.export({ format: 'jwk' }) as { d: string };
    return {
      publicKey: new Uint8Array(Buffer.from(publicJwk.x, 'base64url')),
      privateKey: new Uint8Array(Buffer.from(privateJwk.d, 'base64url')),
    };
  },
  sign(message, privateKey) {
    return new Uint8Array(sign(null, message, privateKeyFromSeed(privateKey)));
  },
  verify(message, signature, publicKey) {
    return verify(null, message, publicKeyFromRaw(publicKey), signature);
  },
};
