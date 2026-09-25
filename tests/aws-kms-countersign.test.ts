/**
 * M4: signing through KMS, for a countersign and for a tool, on both algorithms §5.1 defines.
 *
 * No AWS: the client is a fake holding a real private key that answers the way KMS does, so the
 * signatures are genuine and the SDK's own verifiers check them.
 */

import { ed25519 } from '@noble/curves/ed25519';
import { p256 } from '@noble/curves/nist';
import { describe, expect, it } from 'vitest';
import { countersignaturePayload } from '../src/hashing';
import {
  AwsKmsCountersigner,
  AwsKmsSigner,
  AwsKmsVerifier,
  KEY_SPEC_ED25519,
  KEY_SPEC_P256,
  type KmsClient,
  kmsRegistryEntry,
  loadKmsPublicKey,
  MAX_RAW_MESSAGE_BYTES,
  SIGNING_ALGORITHM_ED25519,
} from '../src/l2/adapters/aws-kms';
import { publicKeyOf } from '../src/l2/jwk';
import { KeyRegistry, KeyRole, SignatureAlgorithm } from '../src/l2/keys';
import { signaturePayload } from '../src/l2/signing';
import { CountersignatureRegistryVerifier, verifyDetachedSignature } from '../src/l2/verification';

/** An Ed25519 SubjectPublicKeyInfo: the fixed 12-byte prefix, then the 32-byte key [RFC-8410]. */
const SPKI_ED25519_PREFIX = Uint8Array.from([0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00]);

class FakeKms implements KmsClient {
  readonly seen: { MessageType: string; SigningAlgorithm: string; length: number }[] = [];
  keySpec: string;
  readonly #secret: Uint8Array;

  constructor(keySpec: string) {
    this.keySpec = keySpec;
    this.#secret = keySpec === KEY_SPEC_ED25519 ? ed25519.utils.randomSecretKey() : p256.utils.randomSecretKey();
  }

  async getPublicKey(_input: { KeyId: string }): Promise<{ PublicKey?: Uint8Array; KeySpec?: string }> {
    if (this.keySpec === KEY_SPEC_ED25519) {
      const raw = ed25519.getPublicKey(this.#secret);
      const der = new Uint8Array(SPKI_ED25519_PREFIX.length + raw.length);
      der.set(SPKI_ED25519_PREFIX, 0);
      der.set(raw, SPKI_ED25519_PREFIX.length);
      return { KeySpec: this.keySpec, PublicKey: der };
    }
    // Only the trailing point matters to the adapter, which slices it off the DER.
    const point = p256.getPublicKey(this.#secret, false);
    const der = new Uint8Array(26 + point.length);
    der.set(point, 26);
    return { KeySpec: this.keySpec, PublicKey: der };
  }

  async sign(input: {
    KeyId: string;
    Message: Uint8Array;
    MessageType: string;
    SigningAlgorithm: string;
  }): Promise<{ Signature?: Uint8Array }> {
    this.seen.push({
      MessageType: input.MessageType,
      SigningAlgorithm: input.SigningAlgorithm,
      length: input.Message.length,
    });
    if (this.keySpec === KEY_SPEC_ED25519) {
      return { Signature: ed25519.sign(input.Message, this.#secret) };
    }
    return { Signature: p256.sign(input.Message, this.#secret, { prehash: false }).toBytes('der') };
  }
}

function payload(): Uint8Array {
  return countersignaturePayload(3, '2026-07-15T00:00:01.000Z', 'tenant-a', '0'.repeat(64), 'a'.repeat(64));
}

describe('the countersign signs through KMS (§5.2)', () => {
  it.each([
    KEY_SPEC_P256,
    KEY_SPEC_ED25519,
  ])('a signature verifies against the key KMS published (%s)', async (keySpec) => {
    // The whole loop: KMS signs, its public half provisions a registry, the verifier agrees.
    const client = new FakeKms(keySpec);
    const signer = await AwsKmsCountersigner.fromKms(client, 'arn:aws:kms:host', { keyId: 'odin-host-1' });
    const signature = await signer.sign(payload());

    const registry = new KeyRegistry(KeyRole.HOST);
    registry.loadJwks({
      keys: [await kmsRegistryEntry(client, 'arn:aws:kms:host', { keyId: 'odin-host-1', role: KeyRole.HOST })],
    });
    const entry = registry.get('odin-host-1');
    expect(entry).toBeDefined();
    expect(verifyDetachedSignature(payload(), signature, entry as never)).toBe(true);
  });

  it.each([
    [KEY_SPEC_P256, 'DIGEST'],
    [KEY_SPEC_ED25519, 'RAW'],
  ])('the message reaches KMS in the form the algorithm takes (%s)', async (keySpec, messageType) => {
    // ECDSA signs a digest; Ed25519 hashes internally and must see the message itself (§5.1).
    const client = new FakeKms(keySpec);
    const signer = await AwsKmsCountersigner.fromKms(client, 'arn:aws:kms:host');
    await signer.sign(payload());
    expect(client.seen[0]?.MessageType).toBe(messageType);
  });

  it('uses the plain Ed25519 signing algorithm', async () => {
    // `ED25519_PH_SHA_512` pre-hashes, and its signatures do not verify under a plain verifier.
    const client = new FakeKms(KEY_SPEC_ED25519);
    await (await AwsKmsCountersigner.fromKms(client, 'arn:aws:kms:host')).sign(payload());
    expect(client.seen[0]?.SigningAlgorithm).toBe(SIGNING_ALGORITHM_ED25519);
  });

  it('refuses a key spec this version does not define, at onboarding', async () => {
    // An RSA key signs happily and produces something no §5.1 verifier can check.
    const client = new FakeKms(KEY_SPEC_P256);
    client.keySpec = 'RSA_2048';
    await expect(AwsKmsCountersigner.fromKms(client, 'arn:aws:kms:host')).rejects.toThrow(/§5.1/);
  });

  it('refuses a payload over what KMS signs whole, by name', async () => {
    const client = new FakeKms(KEY_SPEC_ED25519);
    const signer = await AwsKmsCountersigner.fromKms(client, 'arn:aws:kms:host');
    await expect(signer.sign(new Uint8Array(MAX_RAW_MESSAGE_BYTES + 1))).rejects.toThrow(
      new RegExp(String(MAX_RAW_MESSAGE_BYTES)),
    );
  });

  it('the countersign verifier accepts what KMS signed', async () => {
    // The tool's side of §7.2: it checks the countersign with the registry, not with the adapter.
    const client = new FakeKms(KEY_SPEC_ED25519);
    const signer = await AwsKmsCountersigner.fromKms(client, 'arn:aws:kms:host', { keyId: 'odin-host-1' });
    const registry = new KeyRegistry(KeyRole.HOST);
    registry.loadJwks({
      keys: [await kmsRegistryEntry(client, 'arn:aws:kms:host', { keyId: 'odin-host-1', role: KeyRole.HOST })],
    });
    const signature = await signer.sign(payload());
    expect(await new CountersignatureRegistryVerifier(registry).verify('odin-host-1', signature, payload())).toBe(true);
  });
});

describe('the tool signs through KMS', () => {
  it.each([
    KEY_SPEC_P256,
    KEY_SPEC_ED25519,
  ])('an event signed through KMS verifies against the published key (%s)', async (keySpec) => {
    const client = new FakeKms(keySpec);
    const signer = await AwsKmsSigner.fromKms(client, 'arn:aws:kms:tool', { eventKeyId: 'janus-menu-1' });
    const signed = await signer.sign({ id: '00000000-0000-4000-8000-000000000001', action_type: 'db.read' }, 7);
    expect(signed.signer_seq).toBe(7);
    expect(signed.key_id).toBe('janus-menu-1');

    const registry = new KeyRegistry(KeyRole.TOOL);
    registry.loadJwks({
      keys: [await kmsRegistryEntry(client, 'arn:aws:kms:tool', { keyId: 'janus-menu-1', role: KeyRole.TOOL })],
    });
    const { signature, ...unsigned } = signed;
    expect(
      verifyDetachedSignature(signaturePayload(unsigned), String(signature), registry.get('janus-menu-1') as never),
    ).toBe(true);
  });

  it.each([
    KEY_SPEC_P256,
    KEY_SPEC_ED25519,
  ])('AwsKmsVerifier.fromKms binds each key under the algorithm its KeySpec names (%s)', async (keySpec) => {
    const client = new FakeKms(keySpec);
    const signer = await AwsKmsSigner.fromKms(client, 'arn:aws:kms:tool', { eventKeyId: 'janus-menu-1' });
    const verifier = await AwsKmsVerifier.fromKms(client, { 'janus-menu-1': 'arn:aws:kms:tool' });
    const signed = await signer.sign({ id: '00000000-0000-4000-8000-000000000001', action_type: 'db.read' }, 0);

    expect(await verifier.verify(signed)).toBeNull();
    expect(verifier.check({ ...signed, action_type: 'db.write' })).toBe(false);
  });

  it('AwsKmsVerifier.fromKms refuses a key spec §5.1 does not define, at onboarding', async () => {
    await expect(AwsKmsVerifier.fromKms(new FakeKms('RSA_2048'), { k: 'arn:aws:kms:tool' })).rejects.toThrow(
      'RSA_2048',
    );
  });

  it('the published entry is the form a peer is provisioned from', async () => {
    // A key whose private half never leaves KMS is useless to a peer until its public half does.
    const client = new FakeKms(KEY_SPEC_ED25519);
    const jwk = await kmsRegistryEntry(client, 'arn:aws:kms:tool', { keyId: 'janus-menu-1', role: KeyRole.TOOL });
    const entry = publicKeyOf(jwk);
    expect([entry.keyId, entry.algorithm, entry.role]).toEqual([
      'janus-menu-1',
      SignatureAlgorithm.ED25519,
      KeyRole.TOOL,
    ]);
  });

  it.each([
    [KEY_SPEC_P256, 65],
    [KEY_SPEC_ED25519, 32],
  ])('loadKmsPublicKey returns the raw public key of either algorithm (%s)', async (keySpec, length) => {
    const client = new FakeKms(keySpec);
    const raw = await loadKmsPublicKey(client, 'arn:aws:kms:tool');
    expect(raw).toHaveLength(length);
    const jwk = await kmsRegistryEntry(client, 'arn:aws:kms:tool', { keyId: 'k', role: KeyRole.TOOL });
    expect(publicKeyOf(jwk).publicKey).toEqual(raw);
  });

  it('a signer and a verifier built with fromKms agree on an Ed25519 key, as the README builds them', async () => {
    // The constructor defaults to ECDSA P-256, which KMS refuses for an Ed25519 key; fromKms reads it.
    const client = new FakeKms(KEY_SPEC_ED25519);
    const signer = await AwsKmsSigner.fromKms(client, 'arn:aws:kms:tool', { eventKeyId: 'tool-1' });
    const verifier = await AwsKmsVerifier.fromKms(client, { 'tool-1': 'arn:aws:kms:tool' });
    const signed = await signer.sign({ id: '00000000-0000-4000-8000-000000000001', action_type: 'db.read' }, 0);
    expect(client.seen[0]).toMatchObject({ MessageType: 'RAW', SigningAlgorithm: SIGNING_ALGORITHM_ED25519 });
    expect(await verifier.verify(signed)).toBeNull();
  });
});
