/**
 * base64 over bytes, using the universal `btoa`/`atob` globals (Node 16+, browsers, edge).
 *
 * A signature (§5.1) and a JWK member (RFC 7517) are base64url without padding, the way JWS writes a
 * signature (RFC 7515 §2). The decoder is strict: a value outside the alphabet, carrying padding, or with
 * stray bits in its last character is refused, because two decoders that forgive different things turn
 * one signature into two byte strings. Standard base64 remains for the PKCS#8 a deployment stores.
 */

function toBinary(bytes: Uint8Array): string {
  let binary = '';
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  return binary;
}

function fromBinary(binary: string): Uint8Array {
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

/** Encode bytes as a standard base64 string. */
export function bytesToBase64(bytes: Uint8Array): string {
  return btoa(toBinary(bytes));
}

// Standard base64 as RFC 4648 §4 has it: the alphabet, padded to a multiple of four. `atob` alone is
// laxer - it tolerates whitespace and missing padding - so the shape is checked before decoding.
const STANDARD_BASE64 = /^[A-Za-z0-9+/]*={0,2}$/;

/** Decode a standard base64 string to bytes. Throws if the input is not valid standard base64. */
export function base64ToBytes(text: string): Uint8Array {
  if (text.length % 4 !== 0 || !STANDARD_BASE64.test(text)) {
    throw new TypeError('not standard base64 (RFC 4648 §4, padded)');
  }
  return fromBinary(atob(text));
}

/** Encode bytes as base64url without padding. */
export function bytesToBase64url(bytes: Uint8Array): string {
  return bytesToBase64(bytes).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

const BASE64URL = /^[A-Za-z0-9_-]*$/;

/** Decode strict base64url without padding, or return undefined for anything else. */
export function base64urlToBytes(value: unknown): Uint8Array | undefined {
  if (typeof value !== 'string' || !BASE64URL.test(value) || value.length % 4 === 1) {
    return undefined;
  }
  const padded = value.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (value.length % 4)) % 4);
  let raw: Uint8Array;
  try {
    raw = fromBinary(atob(padded));
  } catch {
    return undefined;
  }
  // The round trip rejects stray bits in the last character, which the decoder would drop.
  return bytesToBase64url(raw) === value ? raw : undefined;
}
