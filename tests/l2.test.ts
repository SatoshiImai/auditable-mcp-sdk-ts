import { p256 } from '@noble/curves/nist';
import { sha256 } from '@noble/hashes/sha2';
import { describe, expect, it } from 'vitest';
import { bytesToBase64 } from '../src/crypto/base64';
import { AuditHost } from '../src/host';
import { InProcessTransport } from '../src/in-process';
import {
  Ed25519Signer,
  generateToolKey,
  KeyRegistry,
  KeyRegistryVerifier,
  SignatureAlgorithm,
  signaturePayload,
  signEvent,
  verifyEd25519Signature,
} from '../src/l2';
import { nodeEd25519Engine } from '../src/node/crypto';
import { AmcpSession } from '../src/session';
import { verifyLedger } from '../src/verify';
import { withAudit } from '../src/with-audit';
import { eventIdAt, L2_CAPABILITY, makeAttempt } from './helpers';

const TABLE = { kind: 'table', ref: 'orders' };

// Sign an event as ECDSA P-256 (the KMS scheme) with a local key, using the wire r||s form (§5.1).
function ecdsaSign(event: Record<string, unknown>, keyId: string, signerSeq: number, priv: Uint8Array) {
  const base = { ...event, key_id: keyId, signer_seq: signerSeq };
  const raw = p256.sign(sha256(signaturePayload(base)), priv).toBytes('compact');
  return { ...base, signature: bytesToBase64(raw) };
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
    registry.register('ec-tool', ecPoint, SignatureAlgorithm.ECDSA_P256_SHA256);
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
    expect(registry.get('tool-1')).toBeUndefined();
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
    const session = new AmcpSession(new InProcessTransport(host), 'call-1', {
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
