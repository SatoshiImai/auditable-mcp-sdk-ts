import { p256 } from '@noble/curves/nist';
import { describe, expect, it } from 'vitest';
import { AuditHost } from '../src/host';
import { InProcessTransport } from '../src/in-process';
import { AwsKmsSigner, AwsKmsVerifier, type KmsClient, loadKmsPublicKey } from '../src/l2/adapters/aws-kms';
import { type AuditCapability, Level } from '../src/models';
import { AmcpSession } from '../src/session';
import { verifyLedger } from '../src/verify';
import { withAudit } from '../src/with-audit';
import { FixedDeps, MonotonicClock } from './helpers';

// The fixed P-256 SubjectPublicKeyInfo prefix; the uncompressed point follows it.
const P256_SPKI_PREFIX = Uint8Array.from(Buffer.from('3059301306072a8648ce3d020106082a8648ce3d030107034200', 'hex'));

/** A fake KMS backed by a local P-256 key, exercising the DIGEST sign + DER/SPKI wire shapes. */
class FakeKms implements KmsClient {
  readonly #privateKey = p256.utils.randomSecretKey();
  readonly #publicPoint = p256.getPublicKey(this.#privateKey, false);

  async sign(input: { Message: Uint8Array }): Promise<{ Signature?: Uint8Array }> {
    // Message is the precomputed SHA-256 digest (MessageType=DIGEST).
    const signature = p256.sign(input.Message, this.#privateKey);
    return { Signature: signature.toBytes('der') };
  }

  async getPublicKey(): Promise<{ PublicKey?: Uint8Array }> {
    const der = new Uint8Array(P256_SPKI_PREFIX.length + this.#publicPoint.length);
    der.set(P256_SPKI_PREFIX);
    der.set(this.#publicPoint, P256_SPKI_PREFIX.length);
    return { PublicKey: der };
  }
}

const L2: AuditCapability = { level: Level.L2, attempt: 'request' };
const TABLE = { kind: 'table', ref: 'orders' };

describe('AWS KMS adapter (ECDSA P-256)', () => {
  it('loadKmsPublicKey extracts the raw uncompressed point from the SPKI', async () => {
    const point = await loadKmsPublicKey(new FakeKms(), 'arn:key');
    expect(point).toHaveLength(65);
    expect(point[0]).toBe(0x04);
  });

  it('a KMS-signed attempt verifies through the KMS verifier end-to-end', async () => {
    const kms = new FakeKms();
    const verifier = await AwsKmsVerifier.fromKms(kms, { 'tool-1': 'arn:key' });

    const host = new AuditHost('tenant-a', L2, { verifier, clock: new MonotonicClock() });
    const session = new AmcpSession(new InProcessTransport(host), 'call-1', {
      deps: new FixedDeps(),
      signer: new AwsKmsSigner(kms, 'arn:key', { eventKeyId: 'tool-1' }),
    });

    const result = await withAudit(
      session,
      { actionType: 'db.query', targetResource: TABLE, mutates: false, egress: true },
      () => 'ok',
    );
    expect(result).toBe('ok');
    expect(host.records()).toHaveLength(2);
    expect(verifyLedger(host.records(), host.digest()).ok).toBe(true);
  });
});
