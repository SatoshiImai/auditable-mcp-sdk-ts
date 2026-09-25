/**
 * AWS KMS signing/verification adapter (Level 2).
 *
 * The tool's private key never leaves KMS: `AwsKmsSigner` calls `kms:Sign` to produce a detached
 * signature over the §8.2 payload - ECDSA P-256 on an `ECC_NIST_P256` key, Ed25519 on an
 * `ECC_NIST_EDWARDS25519` key; `fromKms` reads which from the key. `AwsKmsVerifier` fetches the public
 * key once via `kms:GetPublicKey` and verifies locally — public keys are public, so per-event KMS calls
 * are unnecessary.
 *
 * This module never imports an AWS SDK; it takes an injected, duck-typed `KmsClient`, so it is fully
 * testable with a fake client and the `@aws-sdk/client-kms` peer dependency only has to be adapted to
 * this small interface by the integrator.
 */

import { p256 } from '@noble/curves/nist';
import { sha256 } from '@noble/hashes/sha2';
import { bytesToBase64url } from '../../crypto/base64';
import * as fields from '../../fields';
import type { EventSigner } from '../../session';
import { type Jwk, publicJwk } from '../jwk';
import { KeyRegistry, type KeyRole, type SignatureAlgorithm } from '../keys';
import { signaturePayload } from '../signing';
import { KeyRegistryVerifier } from '../verification';

// KMS asymmetric signing algorithm for an ECC_NIST_P256 key; the digest is SHA-256.
const DEFAULT_SIGNING_ALGORITHM = 'ECDSA_SHA_256';
// KMS request field value (AWS API surface, not the audit wire): the Message is a precomputed digest.
const MESSAGE_TYPE_DIGEST = 'DIGEST';
/**
 * Ed25519 signs the message itself, not a digest of it: the scheme hashes internally, and a verifier
 * built to §5.1 checks the signature against the canonical payload, never against a hash of it.
 */
const MESSAGE_TYPE_RAW = 'RAW';

/** KMS key specs, and the signing algorithm each takes for the two schemes §5.1 defines. */
export const KEY_SPEC_P256 = 'ECC_NIST_P256';
export const KEY_SPEC_ED25519 = 'ECC_NIST_EDWARDS25519';
export const SIGNING_ALGORITHM_ED25519 = 'ED25519_SHA_512';

/**
 * KMS signs at most this many bytes when the message is passed whole rather than as a digest. The
 * limit is stated here so a payload over it is refused by name instead of arriving as a KMS error
 * whose text says nothing about audit records.
 */
export const MAX_RAW_MESSAGE_BYTES = 4096;

/**
 * `ED25519_PH_SHA_512` is Ed25519ph, which pre-hashes: its signatures do not verify under an
 * ordinary Ed25519 verifier, so it is not a form this SDK can emit (§5.1).
 */
const BY_KEY_SPEC: Record<string, { algorithm: SignatureAlgorithm; signingAlgorithm: string; messageType: string }> = {
  [KEY_SPEC_P256]: {
    algorithm: 'ES256',
    signingAlgorithm: DEFAULT_SIGNING_ALGORITHM,
    messageType: MESSAGE_TYPE_DIGEST,
  },
  [KEY_SPEC_ED25519]: {
    algorithm: 'Ed25519',
    signingAlgorithm: SIGNING_ALGORITHM_ED25519,
    messageType: MESSAGE_TYPE_RAW,
  },
};

/** An Ed25519 SubjectPublicKeyInfo is a fixed 44-byte DER whose last 32 bytes are the key. */
const SPKI_ED25519_LENGTH = 44;
const ED25519_KEY_LENGTH = 32;
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
  getPublicKey(input: { KeyId: string }): Promise<{ PublicKey?: Uint8Array; KeySpec?: string }>;
}

/** A KMS key's public half and everything signing with it needs. */
interface KmsPublicHalf {
  publicKey: Uint8Array;
  algorithm: SignatureAlgorithm;
  signingAlgorithm: string;
  messageType: string;
}

/**
 * Fetch a KMS key's public half, reading its algorithm from KMS rather than from configuration.
 *
 * A key provisioned as one algorithm and configured as the other is refused here instead of failing
 * per signature with a KMS error that says nothing about audit records.
 */
async function kmsPublicHalf(client: KmsClient, kmsKeyId: string): Promise<KmsPublicHalf> {
  const response = await client.getPublicKey({ KeyId: kmsKeyId });
  const spec = BY_KEY_SPEC[response.KeySpec ?? ''];
  if (spec === undefined) {
    throw new Error(
      `KMS key '${kmsKeyId}' is ${response.KeySpec ?? 'of no stated spec'}, not an algorithm §5.1 defines`,
    );
  }
  const der = requireBytes(response.PublicKey, 'PublicKey');
  if (spec.algorithm === 'Ed25519') {
    if (der.length !== SPKI_ED25519_LENGTH) {
      throw new Error(`KMS key '${kmsKeyId}' did not return an Ed25519 SubjectPublicKeyInfo`);
    }
    return { ...spec, publicKey: der.slice(der.length - ED25519_KEY_LENGTH) };
  }
  const point = der.slice(der.length - P256_POINT_LENGTH);
  if (point.length !== P256_POINT_LENGTH || point[0] !== UNCOMPRESSED_POINT_TAG) {
    throw new Error(`KMS key '${kmsKeyId}' is not an uncompressed P-256 public key`);
  }
  return { ...spec, publicKey: point };
}

/**
 * Fetch a KMS key's public half and render the registry entry a peer is provisioned from.
 *
 * A key whose private half never leaves KMS is useless to a peer until its public half does. This is
 * the door: it returns the same JWK the local key path produces, so a deployment hands over one form
 * whether it signs locally or through KMS (§5.1).
 */
export async function kmsRegistryEntry(
  client: KmsClient,
  kmsKeyId: string,
  options: { keyId: string; role: KeyRole },
): Promise<Jwk> {
  const { publicKey, algorithm } = await kmsPublicHalf(client, kmsKeyId);
  return publicJwk(options.keyId, publicKey, algorithm, options.role);
}

/**
 * A `Countersigner` that signs a sealed record's host-assigned fields through `kms:Sign` (§5.2).
 *
 * The countersign says who sealed a record, and it says it by a key the verifier's registry binds to a
 * host. A key the signing process can read says only that something holding the key signed, which
 * the process can also do after it is compromised and off the box. This adapter is what moves the
 * private half out of reach; §10.2's limit - that a tool and a host in one party attest nothing
 * against that party - is not touched by it.
 */
export class AwsKmsCountersigner {
  readonly #client: KmsClient;
  readonly #kmsKeyId: string;
  readonly #signingAlgorithm: string;
  readonly #messageType: string;

  /** The `host_key_id` a verifier's registry binds to this key. */
  readonly keyId: string;

  /** Prefer `fromKms`, which learns the algorithm from the key. */
  constructor(client: KmsClient, kmsKeyId: string, keyId: string, signingAlgorithm: string, messageType: string) {
    this.#client = client;
    this.#kmsKeyId = kmsKeyId;
    this.keyId = keyId;
    this.#signingAlgorithm = signingAlgorithm;
    this.#messageType = messageType;
  }

  /** Build a signer, reading the key's algorithm from KMS at onboarding. */
  static async fromKms(
    client: KmsClient,
    kmsKeyId: string,
    options: { keyId?: string } = {},
  ): Promise<AwsKmsCountersigner> {
    const { signingAlgorithm, messageType } = await kmsPublicHalf(client, kmsKeyId);
    return new AwsKmsCountersigner(client, kmsKeyId, options.keyId ?? kmsKeyId, signingAlgorithm, messageType);
  }

  /**
   * Return the base64url detached signature over the already-canonical `payload`.
   *
   * @throws If the payload is longer than KMS signs whole (Ed25519 only).
   */
  async sign(payload: Uint8Array): Promise<string> {
    if (this.#messageType === MESSAGE_TYPE_RAW && payload.length > MAX_RAW_MESSAGE_BYTES) {
      throw new Error(
        `KMS signs at most ${MAX_RAW_MESSAGE_BYTES} bytes whole; this countersign payload is ${payload.length}`,
      );
    }
    const message = this.#messageType === MESSAGE_TYPE_DIGEST ? sha256(payload) : payload;
    const response = await this.#client.sign({
      KeyId: this.#kmsKeyId,
      Message: message,
      MessageType: this.#messageType,
      SigningAlgorithm: this.#signingAlgorithm,
    });
    const raw = requireBytes(response.Signature, 'Signature');
    if (this.#messageType !== MESSAGE_TYPE_DIGEST) {
      return bytesToBase64url(raw);
    }
    // KMS returns an ASN.1/DER ECDSA signature; the wire form is the fixed 64-byte P1363 (§5.1).
    return bytesToBase64url(p256.Signature.fromBytes(raw, 'der').toBytes('compact'));
  }
}

function requireBytes(value: Uint8Array | undefined, field: string): Uint8Array {
  if (value === undefined) {
    throw new Error(`KMS response is missing the bytes field '${field}'`);
  }
  return value;
}

/**
 * Fetch a KMS key's public half as raw bytes (onboarding step): the 65-byte uncompressed point of an
 * `ECC_NIST_P256` key, or the 32-byte key of an `ECC_NIST_EDWARDS25519` key.
 *
 * The bytes do not say which algorithm they are for, and a registry entry binds one (§5.1); prefer
 * `kmsRegistryEntry`, which returns the entry with its algorithm.
 *
 * @throws If the key's `KeySpec` is not one §5.1 defines, or the public half is malformed.
 */
export async function loadKmsPublicKey(client: KmsClient, kmsKeyId: string): Promise<Uint8Array> {
  return (await kmsPublicHalf(client, kmsKeyId)).publicKey;
}

/** An `EventSigner` that signs via `kms:Sign`; the private key stays in KMS. */
export class AwsKmsSigner implements EventSigner {
  readonly #client: KmsClient;
  readonly #kmsKeyId: string;
  readonly #signingAlgorithm: string;
  readonly #messageType: string;

  /** The `key_id` this signer stamps, which names the sequence it advances (§7.4). */
  readonly keyId: string;

  /**
   * Sign as ECDSA P-256 (`ECDSA_SHA_256` over a SHA-256 digest) unless `options` says otherwise; an
   * `ECC_NIST_EDWARDS25519` key needs `ED25519_SHA_512` over `RAW`. Prefer `fromKms`, which learns the
   * algorithm from the key.
   *
   * @param client An injected KMS client.
   * @param kmsKeyId The KMS key id/ARN used to sign.
   * @param options `eventKeyId` is the `key_id` stamped into events for the host to resolve (defaults
   *   to `kmsKeyId`); `signingAlgorithm` defaults to `ECDSA_SHA_256`; `messageType` is `DIGEST` for
   *   ECDSA and `RAW` for Ed25519, which hashes internally.
   */
  constructor(
    client: KmsClient,
    kmsKeyId: string,
    options: { eventKeyId?: string; signingAlgorithm?: string; messageType?: string } = {},
  ) {
    this.#client = client;
    this.#kmsKeyId = kmsKeyId;
    this.keyId = options.eventKeyId ?? kmsKeyId;
    this.#signingAlgorithm = options.signingAlgorithm ?? DEFAULT_SIGNING_ALGORITHM;
    this.#messageType = options.messageType ?? MESSAGE_TYPE_DIGEST;
  }

  /** Build a signer, reading the key's algorithm from KMS at onboarding. */
  static async fromKms(
    client: KmsClient,
    kmsKeyId: string,
    options: { eventKeyId?: string } = {},
  ): Promise<AwsKmsSigner> {
    const { signingAlgorithm, messageType } = await kmsPublicHalf(client, kmsKeyId);
    return new AwsKmsSigner(client, kmsKeyId, { ...options, signingAlgorithm, messageType });
  }

  /** @throws If the canonical event is longer than KMS signs whole (Ed25519 only). */
  async sign(event: Record<string, unknown>, signerSeq: number): Promise<Record<string, unknown>> {
    const signed = { ...event, [fields.KEY_ID]: this.keyId, [fields.SIGNER_SEQ]: signerSeq };
    const payload = signaturePayload(signed);
    if (this.#messageType === MESSAGE_TYPE_RAW && payload.length > MAX_RAW_MESSAGE_BYTES) {
      // The event carries an address and a verdict, not a document, so this is a configuration or a
      // disclosure that grew - either way the refusal has to name the bound (§4.3).
      throw new Error(
        `KMS signs at most ${MAX_RAW_MESSAGE_BYTES} bytes whole; this event canonicalizes to ${payload.length}`,
      );
    }
    const message = this.#messageType === MESSAGE_TYPE_DIGEST ? sha256(payload) : payload;
    const response = await this.#client.sign({
      KeyId: this.#kmsKeyId,
      Message: message,
      MessageType: this.#messageType,
      SigningAlgorithm: this.#signingAlgorithm,
    });
    const raw = requireBytes(response.Signature, 'Signature');
    if (this.#messageType !== MESSAGE_TYPE_DIGEST) {
      return { ...signed, [fields.SIGNATURE]: bytesToBase64url(raw) };
    }
    // KMS returns an ASN.1/DER signature; the wire form is the fixed 64-byte IEEE P1363 r||s (§5.1).
    return { ...signed, [fields.SIGNATURE]: bytesToBase64url(p256.Signature.fromBytes(raw, 'der').toBytes('compact')) };
  }
}

/**
 * A `KeyRegistryVerifier` whose public keys are loaded from AWS KMS at onboarding.
 *
 * Verification (local, against the cached keys) is inherited; the KMS-specific part is only fetching
 * each public half via `kms:GetPublicKey` and binding it under the algorithm its `KeySpec` names -
 * `ECC_NIST_P256` as `ES256`, `ECC_NIST_EDWARDS25519` as `Ed25519` (§5.1).
 */
export class AwsKmsVerifier extends KeyRegistryVerifier {
  /** Build a verifier by fetching each key's public half from KMS at onboarding. */
  static async fromKms(client: KmsClient, keyMap: Record<string, string>): Promise<AwsKmsVerifier> {
    const registry = new KeyRegistry();
    for (const [eventKeyId, kmsKeyId] of Object.entries(keyMap)) {
      const { publicKey, algorithm } = await kmsPublicHalf(client, kmsKeyId);
      registry.register(eventKeyId, publicKey, algorithm);
    }
    return new AwsKmsVerifier(registry);
  }
}
