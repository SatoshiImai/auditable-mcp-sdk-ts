/**
 * The interchange form for registry entries: a JWK Set (RFC 7517), plus RFC 7638 thumbprints.
 *
 * Spec sec. 5.1 gives a registry entry its meaning - one `key_id`, one algorithm, one public key that
 * MUST be a key of that algorithm - and leaves provisioning to the deployment. It says nothing about
 * bytes, which is right for a specification and not enough for two implementations that have to hand
 * each other a key. Without a form in the SDK, every consumer invents one.
 *
 * The form is the standard one rather than a private invention. JWK already carries `kid`, the
 * algorithm and the key material in fixed-length members, so a wrong encoding is refused at
 * registration instead of surfacing later as `signature-invalid` - which names a forged signature and
 * sends an operator looking for the wrong thing.
 *
 * JWK encodes key material base64url without padding, and sec. 5.1 writes a signature the same way, so a
 * key file and a wire event share one encoding and one strict decoder (`crypto/base64`). The `alg`
 * member is the fully-specified JOSE name the registry binds (RFC 9864), which is also sec. 5.1's
 * algorithm identifier: `Ed25519`, not the deprecated polymorphic `EdDSA`.
 *
 * ## What this does not do
 *
 * It decides how to read the bytes, never whether the bytes are genuine. A substituted public key
 * verifies forged records perfectly. Authenticating the channel belongs to the deployment (its secret
 * store, its file permissions, its infrastructure-as-code); `jwkThumbprint` exists so a person can
 * compare a key out of band, not so the SDK can claim to have checked it.
 */

import { p256 } from '@noble/curves/nist';
import { sha256 } from '@noble/hashes/sha2';
import { base64urlToBytes, bytesToBase64url } from '../crypto/base64';
import type { KeyRole, SignatureAlgorithm } from './keys';

/** Each coordinate of a P-256 point, and an Ed25519 public key, are this many bytes. */
const P256_COORD_BYTES = 32;
const ED25519_KEY_BYTES = 32;
/** SEC1 uncompressed: `0x04 ‖ X ‖ Y`, which is how this port holds a P-256 public key. */
const SEC1_UNCOMPRESSED_TAG = 0x04;

/**
 * RFC 7517 sec. 4 asks a private member name to be collision-resistant, so the role does not ride on a
 * bare `role` that a future registered member could claim.
 */
export const ROLE_MEMBER = 'amcp_role';

/**
 * Marks an entry revoked (§10.9). Revocation is forward-only, so a peer provisioned from this set has to
 * learn it too; without the member, an exported set would carry a revoked key as live.
 */
export const REVOKED_MEMBER = 'amcp_revoked';

/** One JWK as it stands in a set. */
export type Jwk = Record<string, unknown>;

/** A JWK Set (RFC 7517). */
export interface JwkSet {
  keys: Jwk[];
}

/** RFC 8037 for the Ed25519 parameters; RFC 7518 for the P-256 ones. */
// Spelled as the literals the `SignatureAlgorithm` union is made of, not by reading its object: this
// module and `keys` depend on each other, and a module-level read runs before `keys` has initialized.
const PARAMETERS: Record<SignatureAlgorithm, { kty: string; crv: string; alg: string }> = {
  Ed25519: { kty: 'OKP', crv: 'Ed25519', alg: 'Ed25519' },
  ES256: { kty: 'EC', crv: 'P-256', alg: 'ES256' },
};

/** The two roles, as literals, for the same reason `PARAMETERS` spells its keys out. */
const ROLES: readonly KeyRole[] = ['tool', 'host'];

/** RFC 7638 hashes only the required members of a key, in lexicographic order. */
const THUMBPRINT_MEMBERS: Record<string, readonly string[]> = {
  OKP: ['crv', 'kty', 'x'],
  EC: ['crv', 'kty', 'x', 'y'],
};

function unb64url(value: unknown, member: string): Uint8Array {
  const raw = base64urlToBytes(value);
  if (raw === undefined) {
    throw new Error(`a JWK member "${member}" is not unpadded base64url (RFC 7517)`);
  }
  return raw;
}

function fixedLength(value: unknown, member: string, bytes: number, reference: string): Uint8Array {
  const raw = unb64url(value, member);
  if (raw.length !== bytes) {
    throw new Error(`a ${reference} "${member}" is ${bytes} bytes, not ${raw.length}`);
  }
  return raw;
}

/** One registry entry, as `publicKeyOf` reads it back. */
export interface JwkEntry {
  keyId: string;
  publicKey: Uint8Array;
  algorithm: SignatureAlgorithm;
  role: KeyRole;
  /** True when the JWK carries `amcp_revoked: true` (§10.9). */
  revoked: boolean;
}

/**
 * Render one registry entry as a JWK (RFC 7517, RFC 8037).
 *
 * @param keyId - The entry's `key_id`, carried as `kid`.
 * @param publicKey - The entry's public key: raw for Ed25519, SEC1 for P-256.
 * @param algorithm - The algorithm bound to the entry (sec. 5.1).
 * @param role - Whether the key belongs to a tool or a host (sec. 10.9); carried as `amcp_role`.
 * @param revoked - Whether the entry is revoked (sec. 10.9); carried as `amcp_revoked: true` when it is.
 * @throws If `publicKey` is not a key of `algorithm`.
 */
export function publicJwk(
  keyId: string,
  publicKey: Uint8Array,
  algorithm: SignatureAlgorithm,
  role: KeyRole,
  revoked = false,
): Jwk {
  const parameters = PARAMETERS[algorithm];
  const revocation = revoked ? { [REVOKED_MEMBER]: true } : {};
  if (algorithm === 'Ed25519') {
    if (publicKey.length !== ED25519_KEY_BYTES) {
      throw new Error(`an ${algorithm} entry binds a ${ED25519_KEY_BYTES}-byte key (§5.1)`);
    }
    return { kid: keyId, ...parameters, x: bytesToBase64url(publicKey), [ROLE_MEMBER]: role, ...revocation };
  }
  let affine: { x: bigint; y: bigint };
  try {
    affine = p256.Point.fromBytes(publicKey).toAffine();
  } catch {
    throw new Error(`a ${algorithm} entry binds a P-256 point (§5.1)`);
  }
  const coordinate = (value: bigint): Uint8Array =>
    Uint8Array.from(
      value
        .toString(16)
        .padStart(P256_COORD_BYTES * 2, '0')
        .match(/../g) ?? [],
      (pair) => Number.parseInt(pair, 16),
    );
  return {
    kid: keyId,
    ...parameters,
    x: bytesToBase64url(coordinate(affine.x)),
    y: bytesToBase64url(coordinate(affine.y)),
    [ROLE_MEMBER]: role,
    ...revocation,
  };
}

/**
 * Read one JWK back into the entry it describes.
 *
 * @throws If the JWK is malformed, names an algorithm this version does not define (sec. 12.1),
 *   carries key material of the wrong length, names no role, or carries `amcp_revoked` that is not a
 *   boolean.
 */
export function publicKeyOf(jwk: Jwk): JwkEntry {
  if ('d' in jwk) {
    // The private member of both key types (RFC 7518 sec. 6.2.2.1, RFC 8037 sec. 2). A registry is
    // provisioned with public keys only, so a file carrying `d` means a private key is travelling the
    // public channel; accepting it quietly would make that normal.
    throw new Error('this JWK carries a private key (`d`); a registry is provisioned with public keys only');
  }
  const keyId = jwk.kid;
  if (typeof keyId !== 'string' || keyId === '') {
    throw new Error('a JWK in this set carries no `kid`, which is the entry’s key_id (§5.1)');
  }
  const algorithm = (Object.keys(PARAMETERS) as SignatureAlgorithm[]).find(
    (candidate) => PARAMETERS[candidate].kty === jwk.kty && PARAMETERS[candidate].crv === jwk.crv,
  );
  if (algorithm === undefined) {
    throw new Error(`kty/crv ${String(jwk.kty)}/${String(jwk.crv)} is not an algorithm this version defines (§12.1)`);
  }
  // `alg` is optional in a JWK (RFC 7517 §4.4); when present it is a string naming the algorithm the key
  // is, by §5.1's identifier. The polymorphic `EdDSA` is not one (§5.1).
  if ('alg' in jwk && (typeof jwk.alg !== 'string' || jwk.alg !== PARAMETERS[algorithm].alg)) {
    throw new Error(
      `a ${String(jwk.kty)}/${String(jwk.crv)} key carries \`alg\` other than "${PARAMETERS[algorithm].alg}"`,
    );
  }
  const role = ROLES.find((candidate) => candidate === jwk[ROLE_MEMBER]);
  if (role === undefined) {
    // A set that does not say whose keys it holds can be loaded into the wrong registry, and a tool
    // key in a host registry lets a tool sign itself into the countersigned state (§5.2).
    throw new Error(`a JWK in this set carries no "${ROLE_MEMBER}"; the set does not say whose keys it holds`);
  }
  const revoked = jwk[REVOKED_MEMBER] ?? false;
  if (typeof revoked !== 'boolean') {
    throw new Error(`a JWK member "${REVOKED_MEMBER}" is a boolean`);
  }
  if (algorithm === 'Ed25519') {
    return { keyId, publicKey: fixedLength(jwk.x, 'x', ED25519_KEY_BYTES, 'Ed25519'), algorithm, role, revoked };
  }
  const x = fixedLength(jwk.x, 'x', P256_COORD_BYTES, 'P-256');
  const y = fixedLength(jwk.y, 'y', P256_COORD_BYTES, 'P-256');
  const point = new Uint8Array(1 + x.length + y.length);
  point[0] = SEC1_UNCOMPRESSED_TAG;
  point.set(x, 1);
  point.set(y, 1 + x.length);
  try {
    // Refuses a point that is not on the curve. Two coordinates of the right length are not yet a key,
    // and the Python port refuses the same input when it builds the key from them.
    p256.Point.fromBytes(point);
  } catch {
    throw new Error('the P-256 x and y do not name a point on the curve (RFC 7518)');
  }
  return { keyId, publicKey: point, algorithm, role, revoked };
}

/**
 * Return the RFC 7638 thumbprint of `jwk`, base64url without padding.
 *
 * The thumbprint covers only the members RFC 7638 requires, so it is the same for the same key
 * however the surrounding document was written. It is there for a person comparing a key over a
 * second channel; it authenticates nothing by itself.
 *
 * @throws If the JWK names a key type this version does not define.
 */
export function jwkThumbprint(jwk: Jwk): string {
  const members = THUMBPRINT_MEMBERS[String(jwk.kty)];
  if (members === undefined) {
    throw new Error(`kty ${String(jwk.kty)} is not a key type this version defines (§12.1)`);
  }
  const missing = members.filter((member) => typeof jwk[member] !== 'string');
  if (missing.length > 0) {
    // A thumbprint of an incomplete key is a value for something that is not a key, and a person
    // comparing it out of band would see a match where there is nothing to match.
    throw new Error(
      `a thumbprint needs every required member as a string; this JWK lacks ${missing.join(', ')} (RFC 7638)`,
    );
  }
  const canonical = `{${members.map((member) => `${JSON.stringify(member)}:${JSON.stringify(jwk[member])}`).join(',')}}`;
  return bytesToBase64url(sha256(new TextEncoder().encode(canonical)));
}
