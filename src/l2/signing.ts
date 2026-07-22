/**
 * Level-2 signing (tool side).
 *
 * The detached signature is computed over the RFC 8785 canonical form of the event with the
 * `signature` field removed (§8.2), so `key_id` and `sequence` are part of the signed payload and
 * tampering with any field invalidates the signature. `Ed25519Signer` implements the session's
 * `EventSigner` interface and owns the per-key monotonic sequence counter.
 */

import { canonicalize } from '../canonical';
import { bytesToBase64 } from '../crypto/base64';
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

/** Return `event` stamped with `key_id`, `sequence`, and a base64 detached Ed25519 signature. */
export function signEvent(
  event: Record<string, unknown>,
  keyId: string,
  sequence: number,
  privateKey: Uint8Array,
  engine: Ed25519Engine = nobleEd25519Engine,
): Record<string, unknown> {
  const signed = { ...event, [fields.KEY_ID]: keyId, [fields.SEQUENCE]: sequence };
  const signature = bytesToBase64(engine.sign(signaturePayload(signed), privateKey));
  return { ...signed, [fields.SIGNATURE]: signature };
}

/** A stateful `EventSigner` that stamps events with a monotonic per-key sequence (§7.4). */
export class Ed25519Signer implements EventSigner {
  readonly #keyId: string;
  readonly #privateKey: Uint8Array;
  readonly #engine: Ed25519Engine;
  #nextSequence: number;

  constructor(keyId: string, privateKey: Uint8Array, options: { engine?: Ed25519Engine; startSequence?: number } = {}) {
    this.#keyId = keyId;
    this.#privateKey = privateKey;
    this.#engine = options.engine ?? nobleEd25519Engine;
    this.#nextSequence = options.startSequence ?? 0;
  }

  /** Build a signer from a generated tool key. */
  static fromToolKey(
    toolKey: ToolKey,
    options: { engine?: Ed25519Engine; startSequence?: number } = {},
  ): Ed25519Signer {
    return new Ed25519Signer(toolKey.keyId, toolKey.privateKey, options);
  }

  /** Stamp the event with the next sequence and a detached signature (local, no I/O). */
  async sign(event: Record<string, unknown>): Promise<Record<string, unknown>> {
    const sequence = this.#nextSequence;
    this.#nextSequence += 1;
    return signEvent(event, this.#keyId, sequence, this.#privateKey, this.#engine);
  }
}
