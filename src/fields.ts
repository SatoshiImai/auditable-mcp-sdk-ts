/**
 * Wire field names for the Auditable MCP contracts.
 *
 * The complete registry of object keys across the four wire contracts (§4 event and target_resource,
 * §6.1 capability, §7.1 attempt response), so protocol keys are referenced by name instead of
 * repeated string literals. Values are the exact keys defined by `spec/schema/`.
 */

// Audit event (§4).
export const ID = 'id';
export const SPEC_VERSION = 'spec_version';
export const TS = 'ts';
export const CALL_ID = 'call_id';
export const TRACEPARENT = 'traceparent';
export const ACTION_TYPE = 'action_type';
export const MUTATES = 'mutates';
export const EGRESS = 'egress';
export const TARGET_RESOURCE = 'target_resource';
export const OUTCOME = 'outcome';
export const REASON = 'reason';
export const ACTION_CONTEXT = 'action_context';
export const ACTION_CONTEXT_HASH = 'action_context_hash';
export const SEQUENCE = 'sequence';
export const KEY_ID = 'key_id';
export const SIGNATURE = 'signature';

// target_resource (§4).
export const KIND = 'kind';
export const REF = 'ref';
export const SCOPE_HINT = 'scope_hint';

// Attempt response (§7.1). `reason` is shared with the event above.
export const STATUS = 'status';
export const SEQ = 'seq';
export const RECORD_HASH = 'record_hash';
export const HOST_TS = 'host_ts';
export const PREVIOUS_HASH = 'previous_hash';
export const RETRYABLE = 'retryable';

// Audit capability (§6.1).
export const LEVEL = 'level';
export const ATTEMPT = 'attempt';
