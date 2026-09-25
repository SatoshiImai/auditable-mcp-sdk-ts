/**
 * Level-2 key material: Ed25519 tool keys and the host's public-key registry.
 *
 * A tool holds a private key and signs its self-attestations; the host verifies against a public key
 * registered out-of-band at onboarding (the trust anchor). The signature gives non-repudiation, not
 * real-time control (§5, §10.2). Keys are raw bytes (engine-neutral): a 32-byte Ed25519 key, or an
 * uncompressed EC point for ECDSA.
 *
 * §5.1 binds the signature algorithm to the `key_id` through this registry (the event carries no
 * algorithm), so one host verifies a heterogeneous fleet — Ed25519 tools alongside KMS ECDSA P-256
 * tools. §10.9 governs lifecycle: a `key_id` maps to exactly one key for life (re-registering it with
 * a different key is forbidden — rotation uses a fresh `key_id`), and revocation is forward-only.
 */

import { ed25519 } from '@noble/curves/ed25519';
import { p256 } from '@noble/curves/nist';
import type { Ed25519Engine } from '../crypto/engine';
import { nobleEd25519Engine } from '../crypto/noble';
import { type JwkSet, publicJwk, publicKeyOf } from './jwk';

/** The signature algorithms defined by this version (§5.1). */
export const SignatureAlgorithm = {
  ED25519: 'Ed25519',
  ES256: 'ES256',
} as const;
export type SignatureAlgorithm = (typeof SignatureAlgorithm)[keyof typeof SignatureAlgorithm];
const ALGORITHMS: readonly string[] = Object.values(SignatureAlgorithm);

/** A tool's Ed25519 key pair and its identity (raw bytes). */
export interface ToolKey {
  keyId: string;
  publicKey: Uint8Array;
  privateKey: Uint8Array;
}

/** A registered public key and the algorithm bound to its `key_id` (§5.1). */
export interface RegisteredKey {
  algorithm: SignatureAlgorithm;
  publicKey: Uint8Array;
}

/** Ed25519 public keys are 32 raw bytes [RFC-8032]. */
const ED25519_PUBLIC_KEY_BYTES = 32;
/** P-256 points are SEC1: 65 bytes uncompressed (0x04) or 33 compressed (0x02/0x03) [FIPS-186-5]. */
const P256_UNCOMPRESSED_BYTES = 65;
const P256_COMPRESSED_BYTES = 33;

/**
 * Whether `publicKey` is a key of `algorithm` (§5.1): an Ed25519 key is 32 bytes that decode to a curve
 * point, and a P-256 key is a SEC1 point on the curve.
 */
function isKeyOf(publicKey: Uint8Array, algorithm: SignatureAlgorithm): boolean {
  if (algorithm === SignatureAlgorithm.ED25519) {
    return publicKey.length === ED25519_PUBLIC_KEY_BYTES && ed25519.utils.isValidPublicKey(publicKey, false);
  }
  const tagged =
    (publicKey.length === P256_UNCOMPRESSED_BYTES && publicKey[0] === 0x04) ||
    (publicKey.length === P256_COMPRESSED_BYTES && (publicKey[0] === 0x02 || publicKey[0] === 0x03));
  if (!tagged) {
    return false;
  }
  try {
    p256.Point.fromBytes(publicKey).assertValidity();
    return true;
  } catch {
    return false;
  }
}

/** Generate a fresh Ed25519 tool key under `key_id` (using the injected engine; noble by default). */
export function generateToolKey(keyId: string, engine: Ed25519Engine = nobleEd25519Engine): ToolKey {
  const { publicKey, privateKey } = engine.generateKeyPair();
  return { keyId, publicKey, privateKey };
}

/**
 * An unencrypted PKCS#8 Ed25519 private key is one fixed 48-byte structure [RFC-8410 sec. 7]: this
 * 16-byte prefix, then the 32-byte seed. Spelling it out keeps a DER parser out of the dependency
 * list for a shape that has no variants.
 */
const PKCS8_ED25519_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);
const PKCS8_ED25519_BYTES = PKCS8_ED25519_PREFIX.length + ED25519_PUBLIC_KEY_BYTES;

/**
 * Render a tool key's private half as unencrypted PKCS#8 DER, for a deployment to store.
 *
 * The form is pinned so a deployment does not have to invent one: two implementations that each invent
 * one cannot hand a key to each other.
 *
 * This is for development and for a tool that signs in its own process. A deployment that has to
 * withstand a compromised worker keeps the private half where the worker cannot read it and signs
 * through a KMS adapter instead; there is no private half to render then.
 */
export function toolKeyPkcs8(toolKey: ToolKey): Uint8Array {
  const der = new Uint8Array(PKCS8_ED25519_BYTES);
  der.set(PKCS8_ED25519_PREFIX, 0);
  der.set(toolKey.privateKey.subarray(0, ED25519_PUBLIC_KEY_BYTES), PKCS8_ED25519_PREFIX.length);
  return der;
}

const PEM_PRIVATE_KEY = /-----BEGIN PRIVATE KEY-----([A-Za-z0-9+/=\s]+)-----END PRIVATE KEY-----/;

/** Unwrap a PEM `PRIVATE KEY` block to its DER bytes, or return DER input unchanged. */
function pemToDer(input: Uint8Array): Uint8Array {
  const text = new TextDecoder('utf-8', { fatal: false }).decode(input);
  const match = PEM_PRIVATE_KEY.exec(text);
  if (match?.[1] === undefined) {
    return input;
  }
  const binary = atob(match[1].replace(/\s+/g, ''));
  return Uint8Array.from(binary, (character) => character.charCodeAt(0));
}

/**
 * Read a tool key back from unencrypted PKCS#8, DER or PEM, under `key_id`.
 *
 * A tool that mints a key per process leaves every signature uncheckable once that process ends, and
 * binds one `key_id` to many keys against §10.9. Reading a stored key is how a tool keeps one.
 *
 * @throws If the bytes are not a PKCS#8 Ed25519 private key, or `key_id` is empty.
 */
export function loadToolKey(keyId: string, pkcs8: Uint8Array, engine: Ed25519Engine = nobleEd25519Engine): ToolKey {
  if (keyId.length === 0) {
    throw new Error('a tool key binds a non-empty key_id (§5.1)');
  }
  // A secret manager usually hands a key over as PEM; the Python port reads both, so this one does.
  const der = pemToDer(pkcs8);
  if (
    der.length !== PKCS8_ED25519_BYTES ||
    !bytesEqual(der.subarray(0, PKCS8_ED25519_PREFIX.length), PKCS8_ED25519_PREFIX)
  ) {
    throw new Error('the tool key is not an unencrypted PKCS#8 Ed25519 private key [RFC-8410]');
  }
  const privateKey = der.slice(PKCS8_ED25519_PREFIX.length);
  return { keyId, publicKey: engine.publicKeyOf(privateKey), privateKey };
}

/**
 * Whether two entries hold the same public key.
 *
 * Compared as keys, not as bytes: §5.1 admits both SEC1 forms of a P-256 point, so the compressed
 * and uncompressed encodings of one key are one key, and re-registering it is the idempotent case
 * §10.9 permits rather than the different-key case it forbids. The Python port compares the DER
 * form for the same reason.
 */
function sameKey(a: Uint8Array, b: Uint8Array, algorithm: SignatureAlgorithm): boolean {
  if (algorithm === SignatureAlgorithm.ED25519) {
    return bytesEqual(a, b);
  }
  try {
    return bytesEqual(p256.Point.fromBytes(a).toBytes(false), p256.Point.fromBytes(b).toBytes(false));
  } catch {
    // A point neither form parses is not a key this registry can hold; the §5.1 guard above refuses
    // it at registration, so reaching here means the stored entry predates that guard.
    return bytesEqual(a, b);
  }
}

function bytesEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) {
    return false;
  }
  for (let i = 0; i < a.length; i += 1) {
    if (a[i] !== b[i]) {
      return false;
    }
  }
  return true;
}

/**
 * Maps `key_id` to its bound algorithm and public key, established out-of-band at onboarding (§5.1).
 *
 * Public keys are raw bytes for both schemes — a 32-byte Ed25519 key or an uncompressed EC point for
 * ECDSA — so one registry serves the unified verifier.
 */
/**
 * Whose keys a registry holds (§5.1 for a tool's, §7.1 for a host's).
 *
 * §10.9 requires the two registries to share no entry, and the only way an SDK can hold that is to
 * make one registry serve one role. Without it a single registry serves both, a tool's own key
 * resolves as a `host_key_id`, and the tool manufactures the host-countersigned state §5.2 says it cannot
 * — defeating the axis rather than degrading it.
 */
export const KeyRole = {
  TOOL: 'tool',
  HOST: 'host',
} as const;
export type KeyRole = (typeof KeyRole)[keyof typeof KeyRole];

export class KeyRegistry {
  /** Whose keys this registry holds; the two roles never share an entry (§10.9). */
  readonly role: KeyRole;

  #keys = new Map<string, RegisteredKey>();
  #revoked = new Set<string>();

  constructor(role: KeyRole = KeyRole.TOOL) {
    this.role = role;
  }

  /**
   * Register a public key and its algorithm under `key_id`.
   *
   * @throws {Error} If `key_id` is already bound to a different key or algorithm (§10.9: rotation must
   *   use a fresh `key_id`). Re-registering the same key is idempotent.
   */
  register(keyId: string, publicKey: Uint8Array, algorithm: SignatureAlgorithm): void {
    if (keyId.length === 0) {
      throw new Error('a registry entry binds a non-empty key_id (§5.1)');
    }
    if (!ALGORITHMS.includes(algorithm)) {
      throw new Error(
        `algorithm ${JSON.stringify(algorithm)} is not a SignatureAlgorithm; use one of ${ALGORITHMS.map((name) => `'${name}'`).join(', ')} (§5.1)`,
      );
    }
    // §5.1: the public key MUST be a key of the entry's algorithm, and a disagreeing entry is refused
    // here rather than carried to verification time, where every event bound to it would be rejected
    // signature-invalid - a forged signature, which is not what went wrong.
    if (!isKeyOf(publicKey, algorithm)) {
      throw new Error(`a ${algorithm} entry does not bind a ${algorithm} key (${publicKey.length} bytes) (§5.1)`);
    }
    const existing = this.#keys.get(keyId);
    if (
      existing !== undefined &&
      (existing.algorithm !== algorithm || !sameKey(existing.publicKey, publicKey, algorithm))
    ) {
      throw new Error(`key_id '${keyId}' is already registered with a different key (§10.9)`);
    }
    this.#keys.set(keyId, { algorithm, publicKey });
  }

  /** Register the public half of a generated Ed25519 tool key. */
  registerToolKey(toolKey: ToolKey): void {
    this.register(toolKey.keyId, toolKey.publicKey, SignatureAlgorithm.ED25519);
  }

  /**
   * Render this registry as a JWK Set for provisioning a peer's registry (§5.1).
   *
   * Every key carries this registry's role, so a peer loading the set into a registry of the other
   * role is refused rather than silently holding a tool's key as a host's (§5.2, §10.9). A revoked entry
   * carries `amcp_revoked: true`, so a peer provisioned from the set holds it revoked as well.
   */
  toJwks(): JwkSet {
    return {
      keys: [...this.#keys.entries()]
        .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
        .map(([keyId, entry]) =>
          publicJwk(keyId, entry.publicKey, entry.algorithm, this.role, this.#revoked.has(keyId)),
        ),
    };
  }

  /**
   * Register every key in a JWK Set, adding to what this registry already holds (§5.1).
   *
   * Loading is additive because rotation mints a fresh `key_id` (§10.9) while the records the old one
   * signed still have to verify: dropping the old entry would break history rather than rotate it.
   * Re-registering an entry unchanged is idempotent, as `register` is. An entry marked `amcp_revoked` is
   * held revoked; revocation is forward-only, so an unrevoked copy of a key revoked here does not
   * unrevoke it (§10.9).
   *
   * @throws If the set is malformed, a key names a role other than this registry's, or a `key_id` is
   *   already bound to a different key (§10.9).
   */
  loadJwks(document: JwkSet): void {
    if (!Array.isArray(document?.keys)) {
      throw new Error('a JWK Set carries its keys under `keys` (RFC 7517)');
    }
    if (!document.keys.every((key) => typeof key === 'object' && key !== null && !Array.isArray(key))) {
      // Skipping what is not a key would load the rest of a set that is not what it claims to be.
      throw new Error("every member of a JWK Set's `keys` is a JWK object (RFC 7517)");
    }
    const entries = document.keys.map((key) => publicKeyOf(key));
    for (const entry of entries) {
      if (entry.role !== this.role) {
        throw new Error(
          `key_id "${entry.keyId}" is a ${entry.role} key; this registry holds ${this.role} keys (§10.9)`,
        );
      }
    }
    // Rehearse on a copy first: a `key_id` repeated within the set, or already bound here to another
    // key, is refused by `register` itself - and refused before anything lands, so a set with one bad
    // key leaves this registry as it was rather than half-provisioned.
    const rehearsal = new KeyRegistry(this.role);
    for (const [keyId, entry] of this.#keys) {
      rehearsal.register(keyId, entry.publicKey, entry.algorithm);
    }
    for (const entry of entries) {
      rehearsal.register(entry.keyId, entry.publicKey, entry.algorithm);
    }
    this.#keys = rehearsal.#keys;
    for (const entry of entries) {
      if (entry.revoked) {
        this.#revoked.add(entry.keyId);
      }
    }
  }

  /**
   * Revoke `key_id`, forward-only (§10.9).
   *
   * The entry is kept, marked revoked: a record sealed while the key was valid still verifies against it,
   * while a host refuses a new event under it as `unknown-key` and a tool aborts on an accept
   * countersigned under it. A revoked `key_id` stays bound to its key, so it cannot be re-registered with
   * another.
   *
   * @throws {Error} If `key_id` has no entry.
   */
  revoke(keyId: string): void {
    if (!this.#keys.has(keyId)) {
      throw new Error(`key_id '${keyId}' has no registry entry to revoke (§10.9)`);
    }
    this.#revoked.add(keyId);
  }

  /** True if `key_id` has an entry that has been revoked (§10.9). */
  isRevoked(keyId: string): boolean {
    return this.#revoked.has(keyId);
  }

  /** Return the registered key + algorithm for `key_id`, revoked or not, or undefined if never registered. */
  get(keyId: string): RegisteredKey | undefined {
    return this.#keys.get(keyId);
  }

  /** Every entry, revoked ones included. */
  entries(): [string, RegisteredKey][] {
    return [...this.#keys.entries()];
  }
}

/**
 * Refuse a tool registry and a host registry that hold one key between them (§10.9).
 *
 * A tool whose key a host registry also binds can countersign its own records and manufacture the state
 * §5.2 says it cannot. Each registry sees only its own entries, so the check needs both: a deployment
 * that provisions the two runs it wherever both are loaded - a ledger verifier given both registries, or
 * a host holding both the tool registry it verifies against and the host registry peers verify it by.
 * Keys are compared as keys, so the two SEC1 forms of one P-256 point are one key.
 *
 * @throws {Error} If the roles are not tool and host, or any key appears in both.
 */
export function assertRegistriesDisjoint(tool: KeyRegistry, host: KeyRegistry): void {
  if (tool.role !== KeyRole.TOOL || host.role !== KeyRole.HOST) {
    throw new Error('compare a tool-key registry with a host-key registry (§10.9)');
  }
  for (const [toolKeyId, toolEntry] of tool.entries()) {
    for (const [hostKeyId, hostEntry] of host.entries()) {
      if (
        toolEntry.algorithm === hostEntry.algorithm &&
        sameKey(toolEntry.publicKey, hostEntry.publicKey, toolEntry.algorithm)
      ) {
        throw new Error(`tool key '${toolKeyId}' and host key '${hostKeyId}' are one key (§10.9)`);
      }
    }
  }
}
