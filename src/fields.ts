/**
 * Wire field names for the Auditable MCP contracts.
 *
 * The complete registry of object keys across the wire contracts (§4 event and target_resource, §6.1
 * capability, §7.1 attempt response, §6.4 `_meta` objects), so protocol keys are referenced by name
 * instead of repeated string literals. Values are the exact keys defined by `spec/schema/`.
 */

// Audit event (§4).
export const ID = 'id';
export const SPEC_VERSION = 'spec_version';
export const TS = 'ts';
export const SESSION_ID = 'session_id';
export const TRACEPARENT = 'traceparent';
export const ACTION_TYPE = 'action_type';
export const MUTATES = 'mutates';
export const EGRESS = 'egress';
export const TARGET_RESOURCE = 'target_resource';
export const OUTCOME = 'outcome';
export const REASON = 'reason';
export const ACTION_CONTEXT = 'action_context';
export const ACTION_CONTEXT_HASH = 'action_context_hash';
export const SIGNER_SEQ = 'signer_seq';
export const KEY_ID = 'key_id';
export const SIGNATURE = 'signature';
// The call an event sealed before v0.3 named, in place of `session_id`; read by the verifier only.
export const CALL_ID = 'call_id';

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
export const HOST_SIGNATURE = 'host_signature';
export const HOST_KEY_ID = 'host_key_id';
export const LOG_ID = 'log_id';

// Audit capability (§6.1).
export const LEVEL = 'level';
export const ATTEMPT = 'attempt';
export const COUNTERSIGN = 'countersign';

// The `_meta` objects of the 2026-07-28 binding (§6.4). `session_id` is shared with the event above.
export const RESPONSES = 'responses';
export const EVENTS = 'events';
