import { p256 } from '@noble/curves/nist';
import { sha256 } from '@noble/hashes/sha2';
import { describe, expect, it } from 'vitest';
import { bytesToBase64url } from '../src/crypto/base64';
import { AuditHost } from '../src/host';
import { InProcessTransport } from '../src/in-process';
import {
  Ed25519Signer,
  generateToolKey,
  KeyRegistry,
  KeyRegistryVerifier,
  KeyRole,
  SignatureAlgorithm,
  signaturePayload,
  signEvent,
  verifyDetachedSignature,
  verifyEd25519Signature,
} from '../src/l2';
import { nodeEd25519Engine } from '../src/node/crypto';
import { AmcpSession } from '../src/session';
import { verifyLedger } from '../src/verify';
import { withAudit } from '../src/with-audit';
import { eventIdAt, L2_CAPABILITY, makeAttempt, SESSION } from './helpers';

const TABLE = { kind: 'table', ref: 'orders' };

// Sign an event as ECDSA P-256 (the KMS scheme) with a local key, using the wire r||s form (§5.1).
function ecdsaSign(event: Record<string, unknown>, keyId: string, signerSeq: number, priv: Uint8Array) {
  const base = { ...event, key_id: keyId, signer_seq: signerSeq };
  const raw = p256.sign(sha256(signaturePayload(base)), priv).toBytes('compact');
  return { ...base, signature: bytesToBase64url(raw) };
}

describe('Ed25519 signing round-trip', () => {
  it('signEvent produces a signature that verifies, and tampering breaks it', () => {
    const key = generateToolKey('tool-1');
    const signed = signEvent(makeAttempt(eventIdAt(1)), key.keyId, 0, key.privateKey);
    expect(verifyEd25519Signature(signed, key.publicKey)).toBe(true);
    expect(verifyEd25519Signature({ ...signed, action_type: 'db.write' }, key.publicKey)).toBe(false);
  });
});

describe('KeyRegistryVerifier dispatches by the bound algorithm (§5.1)', () => {
  it('returns null / unknown-key / signature-invalid for Ed25519 keys', async () => {
    const key = generateToolKey('tool-1');
    const registry = new KeyRegistry();
    registry.registerToolKey(key);
    const verifier = new KeyRegistryVerifier(registry);

    expect(await verifier.verify(signEvent(makeAttempt(eventIdAt(1)), key.keyId, 0, key.privateKey))).toBeNull();
    expect(await verifier.verify(signEvent(makeAttempt(eventIdAt(2)), 'other', 0, key.privateKey))).toBe('unknown-key');
    const forged = signEvent(makeAttempt(eventIdAt(3)), key.keyId, 1, generateToolKey('x').privateKey);
    expect(await verifier.verify(forged)).toBe('signature-invalid');
  });

  it('verifies a heterogeneous fleet (Ed25519 and ECDSA) through one verifier', async () => {
    const ed = generateToolKey('ed-tool');
    const ecPriv = p256.utils.randomSecretKey();
    const ecPoint = p256.getPublicKey(ecPriv, false);

    const registry = new KeyRegistry();
    registry.registerToolKey(ed);
    registry.register('ec-tool', ecPoint, SignatureAlgorithm.ES256);
    const verifier = new KeyRegistryVerifier(registry);

    expect(await verifier.verify(signEvent(makeAttempt(eventIdAt(1)), ed.keyId, 0, ed.privateKey))).toBeNull();
    expect(await verifier.verify(ecdsaSign(makeAttempt(eventIdAt(2)), 'ec-tool', 0, ecPriv))).toBeNull();
    expect(
      await verifier.verify(ecdsaSign(makeAttempt(eventIdAt(3)), 'ec-tool', 1, p256.utils.randomSecretKey())),
    ).toBe('signature-invalid');
  });
});

describe('KeyRegistry lifecycle (§10.9)', () => {
  it('forbids re-registering a key_id with a different key, and revokes forward-only', () => {
    const registry = new KeyRegistry();
    const a = generateToolKey('tool-1');
    const b = generateToolKey('tool-1');
    registry.registerToolKey(a);
    registry.registerToolKey(a); // idempotent
    expect(() => registry.registerToolKey(b)).toThrow(/already registered/);

    registry.revoke('tool-1');
    // The entry is kept, marked revoked: it still verifies what was sealed under it (§10.9).
    expect(registry.isRevoked('tool-1')).toBe(true);
    expect(registry.get('tool-1')?.publicKey).toEqual(a.publicKey);
    expect(() => registry.registerToolKey(b)).toThrow(/already registered/);
    expect(() => registry.revoke('never-registered')).toThrow(/no registry entry/);
  });
});

describe('node and noble engines are interchangeable', () => {
  it('a node-signed event verifies under noble and vice versa', () => {
    const key = generateToolKey('tool-1', nodeEd25519Engine);
    const nodeSigned = signEvent(makeAttempt(eventIdAt(1)), key.keyId, 0, key.privateKey, nodeEd25519Engine);
    expect(verifyEd25519Signature(nodeSigned, key.publicKey)).toBe(true);

    const nobleSigned = signEvent(makeAttempt(eventIdAt(2)), key.keyId, 1, key.privateKey);
    expect(verifyEd25519Signature(nobleSigned, key.publicKey, nodeEd25519Engine)).toBe(true);
  });
});

describe('Level 2 tool-to-host with real crypto', () => {
  it('signs, passes Polluted Stop, and seals a verifiable chain', async () => {
    const key = generateToolKey('tool-1');
    const registry = new KeyRegistry();
    registry.registerToolKey(key);

    const host = new AuditHost('tenant-a', L2_CAPABILITY, {
      verifier: new KeyRegistryVerifier(registry),
      clock: { now: () => '2026-07-15T00:00:01.000Z' },
    });
    host.openSession(SESSION);
    const session = new AmcpSession(new InProcessTransport(host), SESSION, {
      signer: Ed25519Signer.fromToolKey(key),
    });

    const result = await withAudit(
      session,
      { actionType: 'db.query', targetResource: TABLE, mutates: false, egress: true },
      () => 'done',
    );
    expect(result).toBe('done');
    expect(host.records()).toHaveLength(2);
    expect(verifyLedger(host.records(), host.digest()).ok).toBe(true);
  });
});

describe('registry entries are conforming (§5.1)', () => {
  it('an entry cannot bind a key of another algorithm', () => {
    const registry = new KeyRegistry(KeyRole.HOST);
    const ecPoint = p256.getPublicKey(p256.utils.randomSecretKey(), false);
    expect(() => registry.register('k1', ecPoint, SignatureAlgorithm.ED25519)).toThrow('§5.1');
    expect(() => registry.register('k2', generateToolKey('t').publicKey, SignatureAlgorithm.ES256)).toThrow('§5.1');
  });

  it('an entry cannot bind an empty key_id', () => {
    const registry = new KeyRegistry();
    expect(() => registry.register('', generateToolKey('t').publicKey, SignatureAlgorithm.ED25519)).toThrow(
      'non-empty',
    );
  });

  it('an entry cannot bind key material of the wrong length', () => {
    const registry = new KeyRegistry();
    expect(() => registry.register('k', new Uint8Array(0), SignatureAlgorithm.ED25519)).toThrow('§5.1');
    expect(() => registry.register('k', new Uint8Array(64), SignatureAlgorithm.ED25519)).toThrow('§5.1');
  });

  it('a conforming entry still registers, compressed point included', () => {
    const registry = new KeyRegistry();
    const tool = generateToolKey('t');
    registry.registerToolKey(tool);
    const secret = p256.utils.randomSecretKey();
    registry.register('ec', p256.getPublicKey(secret, false), SignatureAlgorithm.ES256);
    registry.register('ec-compressed', p256.getPublicKey(secret, true), SignatureAlgorithm.ES256);
    expect(registry.get(tool.keyId)).toBeDefined();
    expect(registry.get('ec')).toBeDefined();
    expect(registry.get('ec-compressed')).toBeDefined();
  });
});

describe('a signature of the wrong shape (§5.1)', () => {
  it('a non-string signature does not verify', () => {
    const key = generateToolKey('k');
    expect(verifyEd25519Signature({ ...makeAttempt(eventIdAt(1)), signature: 12345 }, key.publicKey)).toBe(false);
  });

  it('an undecodable signature does not verify', () => {
    const key = generateToolKey('k');
    expect(verifyEd25519Signature({ ...makeAttempt(eventIdAt(1)), signature: 'not base64!' }, key.publicKey)).toBe(
      false,
    );
  });

  it('an undecodable detached signature does not verify', () => {
    const registry = new KeyRegistry(KeyRole.HOST);
    const key = generateToolKey('h1');
    registry.register('h1', key.publicKey, SignatureAlgorithm.ED25519);
    const entry = registry.get('h1');
    expect(entry).toBeDefined();
    expect(verifyDetachedSignature(new Uint8Array([1]), 'not base64!', entry as never)).toBe(false);
  });

  it('an ECDSA countersignature verifies against its registry entry', () => {
    // A heterogeneous fleet countersignes with KMS keys too, so the detached path runs both algorithms.
    const secret = p256.utils.randomSecretKey();
    const registry = new KeyRegistry(KeyRole.HOST);
    registry.register('h-ec', p256.getPublicKey(secret, false), SignatureAlgorithm.ES256);
    const entry = registry.get('h-ec');
    expect(entry).toBeDefined();
    const payload = new TextEncoder().encode('{"host_ts":"2026-07-15T00:00:01.000Z"}');
    const raw = p256.sign(sha256(payload), secret).toBytes('compact');
    expect(verifyDetachedSignature(payload, bytesToBase64url(raw), entry as never)).toBe(true);
    expect(verifyDetachedSignature(new TextEncoder().encode('other'), bytesToBase64url(raw), entry as never)).toBe(
      false,
    );
  });

  it('the offline signature checker matches the host-side verdict (§11.4)', async () => {
    const key = generateToolKey('k1');
    const registry = new KeyRegistry();
    registry.registerToolKey(key);
    const checker = new KeyRegistryVerifier(registry);
    const signed = signEvent(makeAttempt(eventIdAt(1)), 'k1', 0, key.privateKey);
    expect(checker.check(signed)).toBe(true);
    expect(checker.check({ ...signed, signature: bytesToBase64url(new Uint8Array(64)) })).toBe(false);
  });
});

describe('registry re-registration (§10.9)', () => {
  it('refuses a key_id already bound to a different key', () => {
    const registry = new KeyRegistry();
    registry.registerToolKey(generateToolKey('k1'));
    expect(() =>
      registry.register('k1', p256.getPublicKey(p256.utils.randomSecretKey(), false), SignatureAlgorithm.ED25519),
    ).toThrow('§5.1');
    expect(() => registry.register('k1', generateToolKey('other').publicKey, SignatureAlgorithm.ED25519)).toThrow(
      '§10.9',
    );
  });

  it('re-registering the same key read again is idempotent', () => {
    // §10.9 forbids binding a key_id to a different key, not to the same one held twice: a registry
    // reloaded from disk holds new bytes for the same key.
    const registry = new KeyRegistry();
    const key = generateToolKey('k1');
    registry.registerToolKey(key);
    registry.register('k1', Uint8Array.from(key.publicKey), SignatureAlgorithm.ED25519);
    expect(registry.get('k1')).toBeDefined();
  });

  it('the same P-256 point in two encodings is the same key', () => {
    // §5.1 admits both SEC1 forms, so the compressed and uncompressed point are one key (§10.9).
    const registry = new KeyRegistry(KeyRole.HOST);
    const secret = p256.utils.randomSecretKey();
    registry.register('h1', p256.getPublicKey(secret, false), SignatureAlgorithm.ES256);
    registry.register('h1', p256.getPublicKey(secret, true), SignatureAlgorithm.ES256);
    expect(registry.get('h1')).toBeDefined();
    expect(() =>
      registry.register('h1', p256.getPublicKey(p256.utils.randomSecretKey(), false), SignatureAlgorithm.ES256),
    ).toThrow('§10.9');
  });
});

describe('KeyRegistry.register names the algorithms it accepts', () => {
  it('refuses an algorithm that is not a SignatureAlgorithm', () => {
    const key = generateToolKey('tool-1');
    expect(() => new KeyRegistry().register('tool-1', key.publicKey, 'EdDSA' as SignatureAlgorithm)).toThrow(
      /"EdDSA" is not a SignatureAlgorithm; use one of 'Ed25519', 'ES256'/,
    );
  });
});
