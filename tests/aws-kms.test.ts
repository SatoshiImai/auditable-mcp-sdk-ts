import { p256 } from '@noble/curves/nist';
import { describe, expect, it } from 'vitest';
import { AuditHost } from '../src/host';
import { InProcessTransport } from '../src/in-process';
import { AwsKmsSigner, AwsKmsVerifier, type KmsClient, loadKmsPublicKey } from '../src/l2/adapters/aws-kms';
import { AmcpSession } from '../src/session';
import { verifyLedger } from '../src/verify';
import { withAudit } from '../src/with-audit';
import { eventIdAt, FixedDeps, L2_CAPABILITY, MonotonicClock, makeAttempt, SESSION } from './helpers';

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

  async getPublicKey(): Promise<{ PublicKey?: Uint8Array; KeySpec?: string }> {
    const der = new Uint8Array(P256_SPKI_PREFIX.length + this.#publicPoint.length);
    der.set(P256_SPKI_PREFIX);
    der.set(this.#publicPoint, P256_SPKI_PREFIX.length);
    return { PublicKey: der, KeySpec: 'ECC_NIST_P256' };
  }
}

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

    const host = new AuditHost('tenant-a', L2_CAPABILITY, { verifier, clock: new MonotonicClock() });
    host.openSession(SESSION);
    const session = new AmcpSession(new InProcessTransport(host), SESSION, {
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

describe('a KMS client that answers badly', () => {
  it('names the missing field rather than indexing into nothing', async () => {
    const client = {
      sign: async () => ({}),
      getPublicKey: async () => ({}),
    };
    await expect(
      new AwsKmsSigner(client as never, 'arn:aws:kms:::key/x').sign(makeAttempt(eventIdAt(1)), 0),
    ).rejects.toThrow('Signature');
  });

  it('refuses a KMS key the adapter cannot sign with', async () => {
    // §5.1 defines P-256 and Ed25519; a key of no stated spec, such as RSA, is a provisioning error.
    const client = { getPublicKey: async () => ({ PublicKey: new Uint8Array([1, 2, 3]) }) };
    await expect(loadKmsPublicKey(client as never, 'arn:aws:kms:::key/x')).rejects.toThrow();
  });
});
