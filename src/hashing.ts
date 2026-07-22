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
