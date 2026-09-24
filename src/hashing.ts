/**
 * The §8.2 record-hash preimage and chain constants.
 *
 * The record hash binds a tool-emitted event to the host-assigned ledger fields. The preimage is a
 * single JSON object — never a delimiter-joined string — so it cannot be forged by canonicalization
 * tricks (§8.2). Both the host (when sealing) and the tool (when performing Polluted Stop
 * verification, §7.2) construct it identically and locally; it is never transmitted on the wire.
 */

import { canonicalize, sha256Hex } from './canonical';

// §8.3: the first record in a partition chains from a genesis link of 64 zeros.
export const GENESIS_HASH = '0'.repeat(64);

/**
 * Return the bytes a witness signature covers: canonical host-assigned fields, UTF-8 (§7.1).
 *
 * These are the four fields an `accept` already returns. The payload carries no signature field, so
 * there is no self-reference, and it is not the §8.2 record-hash preimage: a record sealed with a
 * witness signature and the same record sealed without one have the same `record_hash` (§5.2).
 *
 * @param seq The partition-monotonic ledger sequence assigned by the host.
 * @param hostTs The authoritative host timestamp (ISO-8601).
 * @param previousHash The preceding record's `record_hash`.
 * @param recordHash This record's hash.
 * @returns The RFC 8785 canonical form of the four fields, UTF-8 encoded.
 */
export function witnessPayload(seq: number, hostTs: string, previousHash: string, recordHash: string): Uint8Array {
  const payload = { host_ts: hostTs, previous_hash: previousHash, record_hash: recordHash, seq };
  return new TextEncoder().encode(canonicalize(payload));
}

/**
 * Compute the bare-hex SHA-256 record hash over the §8.2 preimage.
 *
 * The preimage is `{event, host_ts, previous_hash, seq}` serialized via RFC 8785 (JCS) and hashed:
 * `sha256( JCS({event, host_ts, previous_hash, seq}) )`. The `event` must already have its absent
 * optional fields omitted, matching the exact bytes the tool emitted.
 *
 * @param event The audit event with absent optionals omitted.
 * @param seq The partition-monotonic ledger sequence assigned by the host.
 * @param hostTs The authoritative host timestamp (ISO-8601).
 * @param previousHash The preceding record's `record_hash` (genesis for the first record).
 * @returns The lowercase hex-encoded SHA-256 record hash.
 */
export function computeRecordHash(
  event: Record<string, unknown>,
  seq: number,
  hostTs: string,
  previousHash: string,
): string {
  const preimage = { event, host_ts: hostTs, previous_hash: previousHash, seq };
  return sha256Hex(canonicalize(preimage));
}
