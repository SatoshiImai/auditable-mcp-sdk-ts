/** Level-2 primitives and registries: the strictness two implementations must share (§5.1, §10.9). */

import { p256 } from '@noble/curves/nist';
import { sha256 } from '@noble/hashes/sha2';
import { describe, expect, it } from 'vitest';
import { bytesToBase64, bytesToBase64url } from '../src/crypto/base64';
import { nobleEcdsaVerify, nobleEd25519Engine } from '../src/crypto/noble';
import { countersignaturePayload } from '../src/hashing';
import {
  assertRegistriesDisjoint,
  CountersignatureRegistryVerifier,
  Ed25519Countersigner,
  generateToolKey,
  KeyRegistry,
  KeyRegistryVerifier,
  KeyRole,
  publicJwk,
  publicKeyOf,
  SignatureAlgorithm,
  signaturePayload,
  signEvent,
  verifyDetachedSignature,
  verifyEcdsaSignature,
} from '../src/l2';
import { nodeEd25519Engine } from '../src/node/crypto';
import { eventIdAt, makeAttempt } from './helpers';

function p256Pair(): { secret: Uint8Array; point: Uint8Array } {
  const secret = p256.utils.randomSecretKey();
  return { secret, point: p256.getPublicKey(secret, false) };
}

describe('ES256 accepts only the 64-byte r || s form (§5.1)', () => {
  it('a DER signature of a valid ECDSA signature does not verify', () => {
    const { secret, point } = p256Pair();
    const payload = new TextEncoder().encode('payload');
    const signature = p256.sign(sha256(payload), secret);
    expect(nobleEcdsaVerify(payload, signature.toBytes('compact'), point)).toBe(true);
    expect(nobleEcdsaVerify(payload, signature.toBytes('der'), point)).toBe(false);
  });

  it('an event whose signature is DER is refused on every verification path', () => {
    const { secret, point } = p256Pair();
    const base = { ...makeAttempt(eventIdAt(1)), key_id: 'kms-1', signer_seq: 0 };
    const der = p256.sign(sha256(signaturePayload(base)), secret).toBytes('der');
    const event = { ...base, signature: bytesToBase64url(der) };
    // An injected primitive that would accept DER is never reached with a signature of the wrong length.
    const lenient = (): boolean => true;
    expect(verifyEcdsaSignature(event, point, lenient)).toBe(false);
    expect(
      verifyDetachedSignature(new Uint8Array(1), bytesToBase64url(der), {
        algorithm: SignatureAlgorithm.ES256,
        publicKey: point,
      }),
    ).toBe(false);
    const registry = new KeyRegistry();
    registry.register('kms-1', point, SignatureAlgorithm.ES256);
    expect(new KeyRegistryVerifier(registry).check(event)).toBe(false);
  });
});

describe('Ed25519 verification is strict RFC 8032 in both engines', () => {
  it('a small-order key with a non-canonical R verifies under neither engine', () => {
    const publicKey = new Uint8Array(32);
    publicKey[0] = 0x01;
    const signature = new Uint8Array(64);
    signature[0] = 0xee;
    signature.fill(0xff, 1, 31);
    signature[31] = 0x7f;
    const message = new TextEncoder().encode('any message');
    expect(nobleEd25519Engine.verify(message, signature, publicKey)).toBe(false);
    expect(nodeEd25519Engine.verify(message, signature, publicKey)).toBe(false);
  });
});

describe('JWK `alg` (§5.1, RFC 7517)', () => {
  const key = generateToolKey('tool-1');
  const jwk = publicJwk('tool-1', key.publicKey, SignatureAlgorithm.ED25519, KeyRole.TOOL);

  it('an `alg` that is not a string is refused', () => {
    expect(() => publicKeyOf({ ...jwk, alg: ['Ed25519'] })).toThrow(/alg/);
  });

  it('the polymorphic `EdDSA` is not an identifier of this specification', () => {
    expect(() => publicKeyOf({ ...jwk, alg: 'EdDSA' })).toThrow(/alg/);
  });

  it('the fully-specified `Ed25519`, or no `alg`, is read', () => {
    expect(publicKeyOf(jwk).algorithm).toBe(SignatureAlgorithm.ED25519);
    const { alg: _alg, ...withoutAlg } = jwk;
    expect(publicKeyOf(withoutAlg).algorithm).toBe(SignatureAlgorithm.ED25519);
  });
});

describe('the registry refuses an entry whose key is not of its algorithm (§5.1)', () => {
  it('a P-256 point off the curve is refused', () => {
    const { point } = p256Pair();
    const off = Uint8Array.from(point);
    off[64] = (off[64] as number) ^ 0x01;
    expect(() => new KeyRegistry().register('kms-1', off, SignatureAlgorithm.ES256)).toThrow(/§5\.1/);
  });

  it('an Ed25519 key that decodes to no curve point is refused', () => {
    // y = 2 has no x on edwards25519.
    const notAPoint = new Uint8Array(32);
    notAPoint[0] = 0x02;
    expect(() => new KeyRegistry().register('tool-1', notAPoint, SignatureAlgorithm.ED25519)).toThrow(/§5\.1/);
  });

  it('an Ed25519 key registered as ES256, and the other way round, is refused', () => {
    const ed = generateToolKey('tool-1').publicKey;
    expect(() => new KeyRegistry().register('k', ed, SignatureAlgorithm.ES256)).toThrow(/§5\.1/);
    expect(() => new KeyRegistry().register('k', p256Pair().point, SignatureAlgorithm.ED25519)).toThrow(/§5\.1/);
  });
});

describe('revocation keeps the entry (§10.9)', () => {
  it('the host refuses a new event under a revoked key as unknown-key; the verifier still checks it', async () => {
    const key = generateToolKey('tool-1');
    const registry = new KeyRegistry();
    registry.registerToolKey(key);
    const event = signEvent(makeAttempt(eventIdAt(1)), key.keyId, 0, key.privateKey);
    const verifier = new KeyRegistryVerifier(registry);
    expect(await verifier.verify(event)).toBeNull();
    registry.revoke(key.keyId);
    expect(await verifier.verify(event)).toBe('unknown-key');
    expect(verifier.check(event)).toBe(true);
    expect(verifier.check({ ...event, action_type: 'db.write' })).toBe(false);
  });

  it('a tool refuses an accept countersigned under a revoked host key; the verifier still checks it', async () => {
    const hostKey = generateToolKey('host-1');
    const registry = new KeyRegistry(KeyRole.HOST);
    registry.register(hostKey.keyId, hostKey.publicKey, SignatureAlgorithm.ED25519);
    const payload = countersignaturePayload(0, '2026-07-15T00:00:01.000Z', 'tenant-a', '0'.repeat(64), 'a'.repeat(64));
    const signature = await new Ed25519Countersigner(hostKey.keyId, hostKey.privateKey).sign(payload);
    const verifier = new CountersignatureRegistryVerifier(registry);
    expect(await verifier.verify(hostKey.keyId, signature, payload)).toBe(true);
    registry.revoke(hostKey.keyId);
    expect(await verifier.verify(hostKey.keyId, signature, payload)).toBe(false);
    expect(verifier.check(hostKey.keyId, signature, payload)).toBe(true);
    expect(await verifier.verify('never-registered', signature, payload)).toBe(false);
  });
});

describe('the tool and host registries share no key (§10.9)', () => {
  it('one key registered in both is refused, under any key_id and either SEC1 form', () => {
    const shared = generateToolKey('tool-1');
    const tool = new KeyRegistry(KeyRole.TOOL);
    const host = new KeyRegistry(KeyRole.HOST);
    tool.registerToolKey(shared);
    host.register('host-1', generateToolKey('host-1').publicKey, SignatureAlgorithm.ED25519);
    expect(() => assertRegistriesDisjoint(tool, host)).not.toThrow();
    host.register('host-2', shared.publicKey, SignatureAlgorithm.ED25519);
    expect(() => assertRegistriesDisjoint(tool, host)).toThrow(/one key/);

    const { point } = p256Pair();
    const tool2 = new KeyRegistry(KeyRole.TOOL);
    const host2 = new KeyRegistry(KeyRole.HOST);
    tool2.register('kms-tool', point, SignatureAlgorithm.ES256);
    host2.register('kms-host', p256.Point.fromBytes(point).toBytes(true), SignatureAlgorithm.ES256);
    expect(() => assertRegistriesDisjoint(tool2, host2)).toThrow(/one key/);
  });

  it('the roles must be tool and host', () => {
    expect(() => assertRegistriesDisjoint(new KeyRegistry(KeyRole.HOST), new KeyRegistry(KeyRole.HOST))).toThrow();
  });
});

describe('earlier-version signatures are decoded as their version encoded them (§11.4)', () => {
  it('a 0.2 record signed in standard padded base64 verifies; the same bytes as base64url in 0.3 do not', () => {
    const key = generateToolKey('tool-1');
    const registry = new KeyRegistry();
    registry.registerToolKey(key);
    const { session_id: _session, ...rest } = makeAttempt(eventIdAt(1));
    const earlier = { ...rest, spec_version: 'auditable-mcp/0.2', call_id: 'call-1', key_id: key.keyId, signer_seq: 0 };
    const raw = nobleEd25519Engine.sign(signaturePayload(earlier), key.privateKey);
    const verifier = new KeyRegistryVerifier(registry);
    expect(verifier.check({ ...earlier, signature: bytesToBase64(raw) })).toBe(true);
    expect(verifier.check({ ...earlier, signature: bytesToBase64url(raw) })).toBe(false);
  });
});
