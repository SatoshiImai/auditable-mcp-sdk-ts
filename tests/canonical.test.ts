import { describe, expect, it } from 'vitest';
import {
  CanonicalizationError,
  canonicalize,
  hashCanonical,
  hasUnsafeNumber,
  MAX_SAFE_INTEGER,
  sha256Hex,
} from '../src/canonical';
import { canonicalizationVectors, eventVectors } from './vectors';

describe('canonicalize reproduces the golden vectors byte-for-byte', () => {
  for (const vector of canonicalizationVectors) {
    it(`${vector.name}: canonical string matches`, () => {
      expect(canonicalize(vector.value)).toBe(vector.canonical);
    });

    it(`${vector.name}: sha256 matches`, () => {
      expect(sha256Hex(canonicalize(vector.value))).toBe(vector.sha256);
    });
  }
});

describe('canonicalize reproduces every audit event byte-for-byte', () => {
  for (const vector of eventVectors) {
    it(`${vector.name}: canonical and sha256 match`, () => {
      expect(canonicalize(vector.event)).toBe(vector.canonical);
      expect(sha256Hex(canonicalize(vector.event))).toBe(vector.sha256);
    });
  }
});

describe('hasUnsafeNumber detects values outside the §8.1 numeric domain', () => {
  it('treats safe integers, finite floats, and nested structures as safe', () => {
    expect(hasUnsafeNumber({ a: 0, b: -5, c: 1.5, d: 1e-7, e: MAX_SAFE_INTEGER })).toBe(false);
    expect(hasUnsafeNumber([1, [2, { x: 3 }], 'str', true, null])).toBe(false);
  });

  it('treats non-finite, above-safe integers, and bigint as unsafe', () => {
    expect(hasUnsafeNumber(Number.POSITIVE_INFINITY)).toBe(true);
    expect(hasUnsafeNumber(Number.NaN)).toBe(true);
    expect(hasUnsafeNumber(MAX_SAFE_INTEGER + 1)).toBe(true);
    expect(hasUnsafeNumber(-(MAX_SAFE_INTEGER + 1))).toBe(true);
    expect(hasUnsafeNumber(10n)).toBe(true);
    expect(hasUnsafeNumber({ nested: [{ n: Number.POSITIVE_INFINITY }] })).toBe(true);
  });
});

describe('canonicalize fails closed on a numeric-domain violation', () => {
  it('throws CanonicalizationError on a non-finite value', () => {
    expect(() => canonicalize({ n: Number.POSITIVE_INFINITY })).toThrow(CanonicalizationError);
    expect(() => canonicalize({ n: Number.NaN })).toThrow(CanonicalizationError);
  });

  it('throws CanonicalizationError on an integer beyond the safe range', () => {
    expect(() => canonicalize({ n: MAX_SAFE_INTEGER + 1 })).toThrow(CanonicalizationError);
  });
});

describe('hashCanonical returns a sha256:-prefixed commitment', () => {
  it('returns the prefix plus 64 hex chars', () => {
    const digest = hashCanonical({ dialect: 'postgres' });
    expect(digest).toMatch(/^sha256:[0-9a-f]{64}$/);
  });

  it('yields the same commitment regardless of key order (same canonical form)', () => {
    expect(hashCanonical({ a: 1, b: 2 })).toBe(hashCanonical({ b: 2, a: 1 }));
  });
});
