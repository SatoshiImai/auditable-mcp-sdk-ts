/**
 * The §7.6 two-tier reason and anomaly vocabulary.
 *
 * Tier 1 (normative, fixed) codes are the only ones carried on the wire or sealed into the ledger.
 * They occupy three distinct code spaces — a host reject/unavailable `reason`, a tool abort `reason`,
 * and a ledger anomaly `kind` — disambiguated by the field they appear in (so `schema-invalid` and
 * `signature-invalid` legitimately appear in more than one space). Every reject, unavailable, abort,
 * and anomaly condition this SDK produces maps to exactly one Tier-1 code; finer causes are Tier-2
 * local diagnostics that MUST NOT reach the wire or ledger.
 */

// Host reject / unavailable reason codes (§7.6). The tool branches on these.
export const SCHEMA_INVALID = 'schema-invalid';
export const REPLAY_DETECTED = 'replay-detected';
export const SIGNATURE_INVALID = 'signature-invalid';
export const L2_UNSIGNED = 'l2-unsigned';
export const UNKNOWN_KEY = 'unknown-key';
export const INTERNAL_ERROR = 'internal-error';

// Tool abort reason codes, recorded on a fail-closed `aborted` outcome (§7.2, §7.6).
export const HASH_MISMATCH = 'hash-mismatch';
export const HOST_REJECTED = 'host-rejected';
export const HOST_UNAVAILABLE = 'host-unavailable';

// Ledger anomaly kinds a verifier reports (§7.6). SCHEMA_INVALID / SIGNATURE_INVALID above are reused
// here (a distinct code space, disambiguated by the anomaly `kind` field).
export const RECORD_HASH_MISMATCH = 'record-hash-mismatch';
export const DIGEST_MISMATCH = 'digest-mismatch';
// SDK-specific: defined by neither a-MCP §7.6 nor SEP-3004. SEP-3004 binds `principal_id` in its
// hashed core and detects tampering of it (§2.6 event_hash recompute), but never compares that identity
// against the principal a partition is expected to hold; a-MCP delegates identity to the envelope
// entirely. This kind flags that comparison - the detection half neither spec defines.
export const PRINCIPAL_MISMATCH = 'principal-mismatch';
export const SEQ_GAP = 'seq-gap';
export const SIGNER_SEQ_GAP = 'signer-seq-gap';
export const ORPHANED_OUTCOME = 'orphaned-outcome';
export const UNREPORTED_EGRESS = 'unreported-egress';

// Every Tier-1 code, across the three §7.6 spaces. The host's local anomaly `kind` is always one of
// these constants (never a free string), so the type catches a non-Tier-1 kind at compile time.
export type Tier1Code =
  | typeof SCHEMA_INVALID
  | typeof REPLAY_DETECTED
  | typeof SIGNATURE_INVALID
  | typeof L2_UNSIGNED
  | typeof UNKNOWN_KEY
  | typeof INTERNAL_ERROR
  | typeof HASH_MISMATCH
  | typeof HOST_REJECTED
  | typeof HOST_UNAVAILABLE
  | typeof RECORD_HASH_MISMATCH
  | typeof DIGEST_MISMATCH
  | typeof PRINCIPAL_MISMATCH
  | typeof SEQ_GAP
  | typeof SIGNER_SEQ_GAP
  | typeof ORPHANED_OUTCOME
  | typeof UNREPORTED_EGRESS;
