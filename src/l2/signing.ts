/**
 * Signing: Level-2 events (tool side) and countersignatures (host side).
 *
 * The detached signature is computed over the RFC 8785 canonical form of the event with the
 * `signature` field removed (§8.2), so `key_id` and `sequence` are part of the signed payload and
 * tampering with any field invalidates the signature. `Ed25519Signer` implements the session's
 * `EventSigner` interface and owns the per-key monotonic sequence counter.
 *
 * `Ed25519Countersigner` is the host-side counterpart (§5.2, §7.1). It signs an already-canonical
 * payload built by the host (`countersignaturePayload`), carries no sequence of its own, and is bound to a
 * `host_key_id` a verifier's registry resolves separately from any tool key: the two registries have
 * the same shape and the same algorithm identifiers, and never share an entry.
 */

import { canonicalize } from '../canonical';
import { bytesToBase64url } from '../crypto/base64';
import type { Ed25519Engine } from '../crypto/engine';
import { nobleEd25519Engine } from '../crypto/noble';
import * as fields from '../fields';
import type { EventSigner } from '../session';
import type { ToolKey } from './keys';

/** Return the bytes to sign or verify: canonical(event without the `signature` field), UTF-8. */
export function signaturePayload(event: Record<string, unknown>): Uint8Array {
  const rest: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(event)) {
    if (key !== fields.SIGNATURE) {
      rest[key] = value;
    }
  }
  return new TextEncoder().encode(canonicalize(rest));
}

/** Return `event` stamped with `key_id`, `signer_seq`, and a base64url detached Ed25519 signature (§5.1). */
export function signEvent(
  event: Record<string, unknown>,
  keyId: string,
  signerSeq: number,
  privateKey: Uint8Array,
  engine: Ed25519Engine = nobleEd25519Engine,
): Record<string, unknown> {
  const signed = { ...event, [fields.KEY_ID]: keyId, [fields.SIGNER_SEQ]: signerSeq };
  const signature = bytesToBase64url(engine.sign(signaturePayload(signed), privateKey));
  return { ...signed, [fields.SIGNATURE]: signature };
}

/**
 * An `EventSigner` that stamps events with a detached Ed25519 signature.
 *
 * The sequence is not the signer's: a counter in a signer's memory cannot hold §7.4 across a restart
 * or across two processes sharing the key. It lives in a `SignerSeqStore` the session holds, and
 * arrives here per event.
 */
export class Ed25519Signer implements EventSigner {
  /** The `key_id` this signer stamps, which names the sequence it advances (§7.4). */
  readonly keyId: string;
  readonly #privateKey: Uint8Array;
  readonly #engine: Ed25519Engine;

  constructor(keyId: string, privateKey: Uint8Array, options: { engine?: Ed25519Engine } = {}) {
    this.keyId = keyId;
    this.#privateKey = privateKey;
    this.#engine = options.engine ?? nobleEd25519Engine;
  }

  /** Build a signer from a generated tool key. */
  static fromToolKey(toolKey: ToolKey, options: { engine?: Ed25519Engine } = {}): Ed25519Signer {
    return new Ed25519Signer(toolKey.keyId, toolKey.privateKey, options);
  }

  /** Stamp the event with `signerSeq` and a detached signature (local, no I/O). */
  async sign(event: Record<string, unknown>, signerSeq: number): Promise<Record<string, unknown>> {
    return signEvent(event, this.keyId, signerSeq, this.#privateKey, this.#engine);
  }
}

/** A `Countersigner` that signs the host-assigned fields of a record this host sealed (§7.1). */
export class Ed25519Countersigner {
  readonly #keyId: string;
  readonly #privateKey: Uint8Array;
  readonly #engine: Ed25519Engine;

  constructor(keyId: string, privateKey: Uint8Array, options: { engine?: Ed25519Engine } = {}) {
    this.#keyId = keyId;
    this.#privateKey = privateKey;
    this.#engine = options.engine ?? nobleEd25519Engine;
  }

  /** The `host_key_id` returned alongside every signature this host produces. */
  get keyId(): string {
    return this.#keyId;
  }

  /** Return the base64url detached signature over the canonical payload (local, no I/O). */
  async sign(payload: Uint8Array): Promise<string> {
    return bytesToBase64url(this.#engine.sign(payload, this.#privateKey));
  }
}
