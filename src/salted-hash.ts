/**
 * The salted hash of an internal context (§4.3): `action_context_salted_hash`.
 *
 * The construction of SD-JWT (RFC 9901 §4.2.2, §4.2.3) applied to the whole context as one
 * array-element Disclosure: the Disclosure is base64url(UTF-8(JSON `[salt, context]`)) and the salted
 * hash is base64url(SHA-256(ASCII(Disclosure))). The digest is taken over the Disclosure string as the
 * tool encoded it, so the JSON inside need not be canonical (§8): whoever opens the hash is handed that
 * exact string. A tool that may be asked to open it retains the Disclosure (§4.3); this module only
 * computes and checks, it keeps nothing.
 *
 * Runtime-agnostic: SHA-256 from `@noble/hashes`, randomness from the Web Crypto global.
 */

import { sha256 } from '@noble/hashes/sha2';
import { base64urlToBytes, bytesToBase64url } from './crypto/base64';

/** The salted hash's shape: base64url without padding of a 32-byte SHA-256 digest (§4.3). */
export const SALTED_HASH_PATTERN = '^[A-Za-z0-9_-]{43}$';

const saltedHashRegex = new RegExp(SALTED_HASH_PATTERN);

/** RFC 9901 §4.2.1 recommends at least 128 bits of salt. */
const SALT_BYTES = 16;

/** Return a fresh base64url salt of 128 bits from a cryptographically secure source. */
export function newSalt(): string {
  return bytesToBase64url(crypto.getRandomValues(new Uint8Array(SALT_BYTES)));
}

/** Return the Disclosure of `context` under `salt` (§4.3). */
export function disclosureOf(salt: string, context: Record<string, unknown>): string {
  return bytesToBase64url(new TextEncoder().encode(JSON.stringify([salt, context])));
}

/** Return the salted hash of a Disclosure: base64url of the SHA-256 of its ASCII bytes (§4.3). */
export function saltedHashOf(disclosure: string): string {
  return bytesToBase64url(sha256(new TextEncoder().encode(disclosure)));
}

/**
 * Return the context `disclosure` opens if it is the one `saltedHash` commits to, otherwise undefined.
 *
 * A Disclosure that is not base64url, does not hash to `saltedHash`, or does not decode to a
 * two-element array of a string salt and an object opens nothing.
 */
export function openSaltedHash(disclosure: string, saltedHash: string): Record<string, unknown> | undefined {
  if (!saltedHashRegex.test(saltedHash)) {
    return undefined;
  }
  const bytes = base64urlToBytes(disclosure);
  if (bytes === undefined || saltedHashOf(disclosure) !== saltedHash) {
    return undefined;
  }
  let decoded: unknown;
  try {
    decoded = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  } catch {
    return undefined;
  }
  if (!Array.isArray(decoded) || decoded.length !== 2 || typeof decoded[0] !== 'string') {
    return undefined;
  }
  const context: unknown = decoded[1];
  if (context === null || typeof context !== 'object' || Array.isArray(context)) {
    return undefined;
  }
  return context as Record<string, unknown>;
}
