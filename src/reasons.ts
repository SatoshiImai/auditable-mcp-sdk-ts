/**
 * Reason and anomaly codes shared across modules or carried on the wire (§7.1, §7.2, §7.4).
 *
 * Codes local to a single module are defined in that module.
 */

// Terminal-outcome reasons a tool emits on abort (§7.2 RECOMMENDED).
export const HASH_MISMATCH = 'hash-mismatch';
export const HOST_REJECTED = 'host-rejected';
export const HOST_UNAVAILABLE = 'host-unavailable';

// Host reject reasons and anomaly kinds (§7.1, §7.4).
export const SCHEMA_INVALID = 'schema-invalid';
export const ATTEMPT_MUST_BE_ATTEMPTED = 'attempt-must-be-attempted';
export const NUMERIC_DOMAIN = 'numeric-domain';
export const L2_UNSIGNED = 'l2-unsigned';
export const ATTEMPT_REPLAY = 'attempt-replay';
export const PERSISTENCE_FAILURE = 'persistence-failure';
export const SIGNER_SEQUENCE_REPLAY = 'signer-sequence-replay';
export const SIGNER_SEQUENCE_GAP = 'signer-sequence-gap';
export const UNKNOWN_KEY = 'unknown-key';
export const SIGNATURE_INVALID = 'signature-invalid';
export const OUTCOME_AFTER_REJECT = 'outcome-after-reject';
export const OUTCOME_WITHOUT_ATTEMPT = 'outcome-without-attempt';
