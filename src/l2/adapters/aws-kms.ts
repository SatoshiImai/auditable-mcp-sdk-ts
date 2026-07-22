/**
 * AWS KMS signing/verification adapter (Level 2).
 *
 * The tool's private key never leaves KMS: `AwsKmsSigner` calls `kms:Sign` to produce a detached
 * ECDSA signature over the §8.2 payload (AWS KMS does not offer Ed25519, so this is ECDSA P-256 by
 * default). `AwsKmsVerifier` fetches the public key once via `kms:GetPublicKey` and verifies locally —
 * public keys are public, so per-event KMS calls are unnecessary.
 *
 * This module never imports an AWS SDK; it takes an injected, duck-typed `KmsClient`, so it is fully
 * testable with a fake client and the `@aws-sdk/client-kms` peer dependency only has to be adapted to
 * this small interface by the integrator.
 */

import { p256 } from '@noble/curves/nist';
import { sha256 } from '@noble/hashes/sha2';
import { bytesToBase64 } from '../../crypto/base64';
import * as fields from '../../fields';
import type { EventSigner } from '../../session';
import { KeyRegistry, SignatureAlgorithm } from '../keys';
import { signaturePayload } from '../signing';
import { KeyRegistryVerifier } from '../verification';

// KMS asymmetric signing algorithm for an ECC_NIST_P256 key; the digest is SHA-256.
const DEFAULT_SIGNING_ALGORITHM = 'ECDSA_SHA_256';
// KMS request field value (AWS API surface, not the audit wire): the Message is a precomputed digest.
const MESSAGE_TYPE_DIGEST = 'DIGEST';
// An uncompressed EC point (0x04 || X || Y) is the last 65 bytes of a P-256 SubjectPublicKeyInfo.
const P256_POINT_LENGTH = 65;
const UNCOMPRESSED_POINT_TAG = 0x04;

/** The `kms:Sign` request shape (a subset of the AWS API). */
export interface KmsSignInput {
  KeyId: string;
  Message: Uint8Array;
  MessageType: string;
  SigningAlgorithm: string;
}

/** The subset of an AWS KMS client this adapter uses; adapt an `@aws-sdk/client-kms` client to it. */
export interface KmsClient {
  sign(input: KmsSignInput): Promise<{ Signature?: Uint8Array }>;
  getPublicKey(input: { KeyId: string }): Promise<{ PublicKey?: Uint8Array }>;
}

function requireBytes(value: Uint8Array | undefined, field: string): Uint8Array {
  if (value === undefined) {
    throw new Error(`KMS response is missing the bytes field '${field}'`);
  }
  return value;
}

/** Fetch and parse a KMS key's public half as a raw uncompressed EC point (onboarding step). */
export async function loadKmsPublicKey(client: KmsClient, kmsKeyId: string): Promise<Uint8Array> {
  const response = await client.getPublicKey({ KeyId: kmsKeyId });
  const der = requireBytes(response.PublicKey, 'PublicKey');
  const point = der.slice(der.length - P256_POINT_LENGTH);
  if (point.length !== P256_POINT_LENGTH || point[0] !== UNCOMPRESSED_POINT_TAG) {
    throw new Error(`KMS key '${kmsKeyId}' is not an uncompressed P-256 public key`);
  }
  return point;
}

/** An `EventSigner` that signs via `kms:Sign`; the private key stays in KMS. */
export class AwsKmsSigner implements EventSigner {
  readonly #client: KmsClient;
  readonly #kmsKeyId: string;
  readonly #eventKeyId: string;
  readonly #signingAlgorithm: string;
  #nextSequence: number;

  /**
   * @param client An injected KMS client.
   * @param kmsKeyId The KMS key id/ARN used to sign.
   * @param options `eventKeyId` is the `key_id` stamped into events for the host to resolve (defaults
   *   to `kmsKeyId`); `signingAlgorithm` defaults to `ECDSA_SHA_256`; `startSequence` is the first
   *   per-key sequence value to emit.
   */
  constructor(
    client: KmsClient,
    kmsKeyId: string,
    options: { eventKeyId?: string; signingAlgorithm?: string; startSequence?: number } = {},
  ) {
    this.#client = client;
    this.#kmsKeyId = kmsKeyId;
    this.#eventKeyId = options.eventKeyId ?? kmsKeyId;
    this.#signingAlgorithm = options.signingAlgorithm ?? DEFAULT_SIGNING_ALGORITHM;
    this.#nextSequence = options.startSequence ?? 0;
  }

  async sign(event: Record<string, unknown>): Promise<Record<string, unknown>> {
    const signerSeq = this.#nextSequence;
    this.#nextSequence += 1;
    const signed = { ...event, [fields.KEY_ID]: this.#eventKeyId, [fields.SIGNER_SEQ]: signerSeq };
    const digest = sha256(signaturePayload(signed));
    const response = await this.#client.sign({
      KeyId: this.#kmsKeyId,
      Message: digest,
      MessageType: MESSAGE_TYPE_DIGEST,
      SigningAlgorithm: this.#signingAlgorithm,
    });
    // KMS returns an ASN.1/DER signature; the wire form is the fixed 64-byte IEEE P1363 r||s (§5.1).
    const raw = p256.Signature.fromBytes(requireBytes(response.Signature, 'Signature'), 'der').toBytes('compact');
    return { ...signed, [fields.SIGNATURE]: bytesToBase64(raw) };
  }
}

/**
 * A `KeyRegistryVerifier` whose ECDSA P-256 public keys are loaded from AWS KMS at onboarding.
 *
 * Verification (local ECDSA against the cached keys) is inherited; the KMS-specific part is only
 * fetching the public keys via `kms:GetPublicKey` and binding them as `ECDSA_P256_SHA256`.
 */
export class AwsKmsVerifier extends KeyRegistryVerifier {
  /** Build a verifier by fetching each key's public half from KMS at onboarding. */
  static async fromKms(client: KmsClient, keyMap: Record<string, string>): Promise<AwsKmsVerifier> {
    const registry = new KeyRegistry();
    for (const [eventKeyId, kmsKeyId] of Object.entries(keyMap)) {
      registry.register(eventKeyId, await loadKmsPublicKey(client, kmsKeyId), SignatureAlgorithm.ECDSA_P256_SHA256);
    }
    return new AwsKmsVerifier(registry);
  }
}
