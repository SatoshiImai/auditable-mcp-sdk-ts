import { describe, expect, it } from 'vitest';
import { AuditHost } from '../src/host';
import { InProcessTransport } from '../src/in-process';
import {
  Ed25519SignatureVerifier,
  Ed25519Signer,
  generateToolKey,
  KeyRegistry,
  signEvent,
  verifyEd25519Signature,
} from '../src/l2';
import { type AuditCapability, Level } from '../src/models';
import { nodeEd25519Engine } from '../src/node/crypto';
import { AmcpSession } from '../src/session';
import { verifyLedger } from '../src/verify';
import { withAudit } from '../src/with-audit';
import { FixedDeps, MonotonicClock, makeAttempt } from './helpers';

const L2: AuditCapability = { level: Level.L2, attempt: 'request' };
const TABLE = { kind: 'table', ref: 'orders' };

describe('Ed25519 signing round-trip', () => {
  it('signEvent produces a signature that verifies, and tampering breaks it', () => {
    const key = generateToolKey('tool-1');
    const signed = signEvent(makeAttempt('00000000-0000-4000-8000-000000000001'), key.keyId, 0, key.privateKey);
    expect(verifyEd25519Signature(signed, key.publicKey)).toBe(true);

    const tampered = { ...signed, action_type: 'db.write' };
    expect(verifyEd25519Signature(tampered, key.publicKey)).toBe(false);
  });

  it('Ed25519SignatureVerifier returns unknown-key / signature-invalid / null', async () => {
    const key = generateToolKey('tool-1');
    const registry = new KeyRegistry();
    registry.registerToolKey(key);
    const verifier = new Ed25519SignatureVerifier(registry);

    const signed = signEvent(makeAttempt('00000000-0000-4000-8000-000000000001'), key.keyId, 0, key.privateKey);
    expect(await verifier.verify(signed)).toBeNull();

    const unknown = signEvent(makeAttempt('00000000-0000-4000-8000-000000000002'), 'other', 0, key.privateKey);
    expect(await verifier.verify(unknown)).toBe('unknown-key');

    const forged = { ...signed, signature: signEvent(signed, key.keyId, 1, generateToolKey('x').privateKey).signature };
    expect(await verifier.verify(forged)).toBe('signature-invalid');
  });
});

describe('node and noble engines are interchangeable', () => {
  it('a node-signed event verifies under noble and vice versa', () => {
    const key = generateToolKey('tool-1', nodeEd25519Engine);
    const nodeSigned = signEvent(
      makeAttempt('00000000-0000-4000-8000-000000000001'),
      key.keyId,
      0,
      key.privateKey,
      nodeEd25519Engine,
    );
    // verify with the default noble engine
    expect(verifyEd25519Signature(nodeSigned, key.publicKey)).toBe(true);

    const nobleSigned = signEvent(makeAttempt('00000000-0000-4000-8000-000000000002'), key.keyId, 1, key.privateKey);
    // verify with the node engine
    expect(verifyEd25519Signature(nobleSigned, key.publicKey, nodeEd25519Engine)).toBe(true);
  });
});

describe('Level 2 tool-to-host with real crypto', () => {
  it('signs, passes Polluted Stop, and seals a verifiable chain', async () => {
    const key = generateToolKey('tool-1');
    const registry = new KeyRegistry();
    registry.registerToolKey(key);

    const host = new AuditHost('tenant-a', L2, {
      verifier: new Ed25519SignatureVerifier(registry),
      clock: new MonotonicClock(),
    });
    const session = new AmcpSession(new InProcessTransport(host), 'call-1', {
      deps: new FixedDeps(),
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
