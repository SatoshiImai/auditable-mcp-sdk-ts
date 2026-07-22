/**
 * RFC 8785 (JCS) canonical JSON serialization, the numeric-domain guard, and SHA-256 hashing.
 *
 * This is the cross-language bedrock of ledger integrity (spec §8). Serialization is delegated to
 * the `canonicalize` package rather than a hand-rolled serializer; the Python SDK uses `rfc8785`.
 * Both implement RFC 8785 and produce byte-identical output, verified against the shared conformance
 * vectors under `spec/vectors/`.
 *
 * The numeric guard matters more here than in Python: JavaScript has only IEEE-754 `number`, so an
 * integer beyond the safe range has already lost precision by the time it reaches this module. The
 * guard fails closed before canonicalization so a lossy value can never be sealed into the chain.
 */

import { sha256 } from '@noble/hashes/sha2';
import { bytesToHex } from '@noble/hashes/utils';
import jcsCanonicalize from 'canonicalize';

// §8.1: JCS serializes numbers as IEEE-754 doubles, so integer-valued numbers must stay within the
// safe-integer range or canonicalization diverges across runtimes. Equal to 2^53 - 1.
export const MAX_SAFE_INTEGER = Number.MAX_SAFE_INTEGER;

// The action_context_hash commitment (§4.3) names its algorithm; only SHA-256 is defined in this version.
export const CONTEXT_HASH_PREFIX = 'sha256:';

/** A value cannot be canonicalized under the §8.1 numeric domain. */
export class CanonicalizationError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'CanonicalizationError';
  }
}

/**
 * Report whether any number in `value` falls outside the §8.1 canonicalization domain.
 *
 * Rejected values are non-finite numbers (`NaN`, `±Infinity`, which have no JCS form) and
 * integer-valued numbers whose magnitude exceeds `MAX_SAFE_INTEGER` — such a value has already lost
 * precision as a double, so sealing it would break cross-language identity. `bigint` is rejected
 * outright: it is outside the JSON number domain the spec is defined over. A host uses this to reject
 * an event gracefully (§7.1) instead of letting canonicalization throw at seal time.
 */
export function hasUnsafeNumber(value: unknown): boolean {
  if (typeof value === 'number') {
    return !Number.isFinite(value) || (Number.isInteger(value) && Math.abs(value) > MAX_SAFE_INTEGER);
  }
  if (typeof value === 'bigint') {
    return true;
  }
  if (Array.isArray(value)) {
    return value.some(hasUnsafeNumber);
  }
  if (value !== null && typeof value === 'object') {
    return Object.values(value).some(hasUnsafeNumber);
  }
  return false;
}

/**
 * Serialize a JSON-compatible value to its RFC 8785 (JCS) canonical string.
 *
 * @throws {CanonicalizationError} If any contained number is outside the §8.1 domain, or the value
 *   has no JSON form.
 */
export function canonicalize(value: unknown): string {
  if (hasUnsafeNumber(value)) {
    throw new CanonicalizationError('a numeric value is not canonicalizable (non-finite or outside ±(2^53-1)) (§8.1)');
  }
  const canonical = jcsCanonicalize(value as Parameters<typeof jcsCanonicalize>[0]);
  if (canonical === undefined) {
    throw new CanonicalizationError('value has no canonical JSON form');
  }
  return canonical;
}

/** Return the lowercase hex-encoded SHA-256 of `data` encoded as UTF-8. */
export function sha256Hex(data: string): string {
  return bytesToHex(sha256(new TextEncoder().encode(data)));
}

/**
 * Return the `sha256:<hex>` commitment over the canonical form of `value` (§4.3).
 *
 * This is the `action_context_hash` construction: a tool-authored commitment carrying an algorithm
 * prefix, distinct from the bare-hex chain hashes of §8.2.
 */
export function hashCanonical(value: unknown): string {
  return `${CONTEXT_HASH_PREFIX}${sha256Hex(canonicalize(value))}`;
}
