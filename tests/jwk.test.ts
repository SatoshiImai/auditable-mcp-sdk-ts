/** M1/M2: the interchange form two implementations hand each other keys in (§5.1, RFC 7517). */

import { p256 } from '@noble/curves/nist';
import { describe, expect, it } from 'vitest';
import { base64urlToBytes, bytesToBase64url } from '../src/crypto/base64';
import { type Jwk, jwkThumbprint, publicJwk, publicKeyOf, REVOKED_MEMBER, ROLE_MEMBER } from '../src/l2/jwk';
import { generateToolKey, KeyRegistry, KeyRole, loadToolKey, SignatureAlgorithm, toolKeyPkcs8 } from '../src/l2/keys';

/** A P-256 public key as SEC1 bytes, standing in for one held in a KMS. */
function p256Key(): Uint8Array {
  return p256.getPublicKey(p256.utils.randomSecretKey(), false);
}

function edJwk(keyId = 'tool-1'): Jwk {
  return publicJwk(keyId, generateToolKey(keyId).publicKey, SignatureAlgorithm.ED25519, KeyRole.TOOL);
}

describe('the interchange form (§5.1)', () => {
  it('an Ed25519 entry survives the round trip', () => {
    const key = generateToolKey('tool-1');
    const entry = publicKeyOf(publicJwk('tool-1', key.publicKey, SignatureAlgorithm.ED25519, KeyRole.TOOL));
    expect(entry.keyId).toBe('tool-1');
    expect(entry.algorithm).toBe(SignatureAlgorithm.ED25519);
    expect(entry.role).toBe(KeyRole.TOOL);
    expect([...entry.publicKey]).toEqual([...key.publicKey]);
  });

  it('a P-256 entry survives the round trip', () => {
    const original = p256Key();
    const entry = publicKeyOf(publicJwk('host-1', original, SignatureAlgorithm.ES256, KeyRole.HOST));
    expect(entry.algorithm).toBe(SignatureAlgorithm.ES256);
    expect(entry.role).toBe(KeyRole.HOST);
    expect([...entry.publicKey]).toEqual([...original]);
  });

  it('the parameters are the standard ones', () => {
    // A peer reads this with an ordinary JWK library, not with this SDK (RFC 7517, RFC 8037).
    const jwk = edJwk();
    expect([jwk.kty, jwk.crv, jwk.alg]).toEqual(['OKP', 'Ed25519', 'Ed25519']);
    expect(jwk.kid).toBe('tool-1');
  });

  it.each(['x', 'y'])('key material of the wrong length is refused at registration (%s)', (member) => {
    // A fixed length is what stops a wrong encoding surfacing later as a forged signature.
    const jwk = publicJwk('host-1', p256Key(), SignatureAlgorithm.ES256, KeyRole.HOST);
    // Re-encoding a shortened coordinate keeps the member valid base64url, so only the length is wrong.
    const material = base64urlToBytes(String(jwk[member])) ?? new Uint8Array();
    jwk[member] = bytesToBase64url(material.slice(0, -3));
    expect(() => publicKeyOf(jwk)).toThrow(/32 bytes/);
  });

  it('an algorithm this version does not define is refused', () => {
    // §12.1 fixes the algorithm set; a new one arrives with a new spec_version, not in a key file.
    expect(() => publicKeyOf({ ...edJwk(), crv: 'Ed448' })).toThrow(/§12.1/);
  });

  it('a key that names no role is refused', () => {
    // A set that does not say whose keys it holds can be loaded into the wrong registry (§5.2).
    const jwk = edJwk();
    delete jwk[ROLE_MEMBER];
    expect(() => publicKeyOf(jwk)).toThrow(new RegExp(ROLE_MEMBER));
  });
});

describe('the thumbprint (RFC 7638)', () => {
  it('ignores everything but the required members', () => {
    // A person comparing a key out of band must not see it change because a `kid` changed.
    const key = generateToolKey('tool-1').publicKey;
    const first = publicJwk('tool-1', key, SignatureAlgorithm.ED25519, KeyRole.TOOL);
    const second = publicJwk('another-id', key, SignatureAlgorithm.ED25519, KeyRole.HOST);
    expect(jwkThumbprint(first)).toBe(jwkThumbprint(second));
  });

  it('two keys do not share a thumbprint', () => {
    expect(jwkThumbprint(edJwk('a'))).not.toBe(jwkThumbprint(edJwk('b')));
  });
});

describe('provisioning a registry (§5.1)', () => {
  it('a set written by one registry loads into another', () => {
    const source = new KeyRegistry(KeyRole.TOOL);
    source.registerToolKey(generateToolKey('tool-1'));
    source.registerToolKey(generateToolKey('tool-2'));
    const target = new KeyRegistry(KeyRole.TOOL);
    target.loadJwks(source.toJwks());
    expect(target.toJwks()).toEqual(source.toJwks());
  });

  it('loading adds rather than replaces', () => {
    // Rotation mints a fresh key_id (§10.9); dropping the old one breaks history, not rotates it.
    const registry = new KeyRegistry(KeyRole.TOOL);
    registry.registerToolKey(generateToolKey('tool-v1'));
    const second = new KeyRegistry(KeyRole.TOOL);
    second.registerToolKey(generateToolKey('tool-v2'));
    registry.loadJwks(second.toJwks());
    expect(registry.get('tool-v1')).toBeDefined();
    expect(registry.get('tool-v2')).toBeDefined();
  });

  it('a tool set is refused by a host registry', () => {
    // A tool key held as a host's lets a tool sign itself into the countersigned state (§5.2).
    const tools = new KeyRegistry(KeyRole.TOOL);
    tools.registerToolKey(generateToolKey('tool-1'));
    expect(() => new KeyRegistry(KeyRole.HOST).loadJwks(tools.toJwks())).toThrow(/holds host keys/);
  });

  it('one bad key leaves the registry untouched', () => {
    // A half-provisioned registry verifies some records and rejects others, for no stated reason.
    const source = new KeyRegistry(KeyRole.TOOL);
    source.registerToolKey(generateToolKey('tool-1'));
    const document = source.toJwks();
    document.keys.push({ ...document.keys[0], kid: 'tool-2', [ROLE_MEMBER]: 'host' });
    const target = new KeyRegistry(KeyRole.TOOL);
    expect(() => target.loadJwks(document)).toThrow();
    expect(target.get('tool-1')).toBeUndefined();
  });

  it('a document that is not a set is refused', () => {
    expect(() => new KeyRegistry(KeyRole.TOOL).loadJwks({ kty: 'OKP' } as never)).toThrow(/`keys`/);
  });
});

describe('revocation travels with the set (§10.9)', () => {
  it('a key revoked at the source is revoked at the peer provisioned from its set', () => {
    const source = new KeyRegistry(KeyRole.TOOL);
    source.registerToolKey(generateToolKey('tool-1'));
    source.registerToolKey(generateToolKey('tool-2'));
    source.revoke('tool-1');
    const document = source.toJwks();
    expect(document.keys.map((key) => key[REVOKED_MEMBER])).toEqual([true, undefined]);

    const peer = new KeyRegistry(KeyRole.TOOL);
    peer.loadJwks(document);
    expect(peer.isRevoked('tool-1')).toBe(true);
    expect(peer.isRevoked('tool-2')).toBe(false);
    expect(peer.get('tool-1')).toBeDefined();
  });

  it('loading an unrevoked copy of a revoked key does not unrevoke it', () => {
    // Revocation is forward-only; a stale set must not bring a revoked key back.
    const key = generateToolKey('tool-1');
    const stale = new KeyRegistry(KeyRole.TOOL);
    stale.registerToolKey(key);
    const registry = new KeyRegistry(KeyRole.TOOL);
    registry.registerToolKey(key);
    registry.revoke('tool-1');
    registry.loadJwks(stale.toJwks());
    expect(registry.isRevoked('tool-1')).toBe(true);
  });

  it('the member reads back through publicKeyOf, and a non-boolean is refused', () => {
    const key = generateToolKey('tool-1');
    const jwk = publicJwk('tool-1', key.publicKey, 'Ed25519', KeyRole.TOOL, true);
    expect(publicKeyOf(jwk).revoked).toBe(true);
    expect(publicKeyOf({ ...jwk, [REVOKED_MEMBER]: undefined }).revoked).toBe(false);
    expect(() => publicKeyOf({ ...jwk, [REVOKED_MEMBER]: 'yes' })).toThrow(new RegExp(REVOKED_MEMBER));
  });

  it('revoking a key_id with no entry still throws', () => {
    expect(() => new KeyRegistry(KeyRole.TOOL).revoke('never-registered')).toThrow(/no registry entry/);
  });
});

describe('the stored private key (M2)', () => {
  it('a key survives being written and read', () => {
    // A key that does not survive the process leaves every signature it made uncheckable (§10.9).
    const original = generateToolKey('tool-1');
    const restored = loadToolKey('tool-1', toolKeyPkcs8(original));
    expect([...restored.publicKey]).toEqual([...original.publicKey]);
  });

  it('the rendered key is the fixed 48-byte PKCS#8 structure', () => {
    // Pinned so a deployment does not invent an encoding, as this SDK's own walk once did.
    expect(toolKeyPkcs8(generateToolKey('tool-1'))).toHaveLength(48);
  });

  it('bytes that are not a private key are refused', () => {
    expect(() => loadToolKey('tool-1', new Uint8Array([1, 2, 3]))).toThrow(/PKCS#8/);
  });

  it('an empty key id is refused', () => {
    // A registry entry binds a non-empty key_id (§5.1), so a key cannot carry an empty one.
    expect(() => loadToolKey('', toolKeyPkcs8(generateToolKey('tool-1')))).toThrow(/key_id/);
  });
});
