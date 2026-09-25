/**
 * Drift guard: the Zod schema's acceptance must match the normative JSON Schema.
 *
 * The pattern constants in `models.ts` are hand-copied from `spec/schema/`. This test locks that copy
 * to the vendored schema over a set of valid and deliberately-invalid samples: the Zod verdict and
 * the JSON Schema verdict must agree, and both must match the expected outcome. If the spec changes a
 * pattern (e.g. `ts` becomes a Unix timestamp) and the copied constant is not updated, the verdicts
 * diverge here and the build fails.
 *
 * Only pattern / range / required / enum / closed-shape cases are covered — not the places where the
 * schema is intentionally stricter than JSON Schema (Zod forbids silent coercion such as `1` for a
 * bool), which are exercised in `tests/models.test.ts`.
 */

import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { Ajv2020 } from 'ajv/dist/2020.js';
import { describe, expect, it } from 'vitest';
import {
  attemptResponseSchema,
  auditCapabilitySchema,
  auditRequestMetaSchema,
  auditResultMetaSchema,
  firstSealedValidationError,
  firstValidationError,
  SPEC_VERSION,
} from '../../src/models';
import { SESSION } from '../helpers';

const SCHEMA_DIR = join(dirname(fileURLToPath(import.meta.url)), '..', '..', 'spec', 'schema');

function loadSchema(file: string): Record<string, unknown> {
  return JSON.parse(readFileSync(join(SCHEMA_DIR, file), 'utf-8'));
}

const eventSchema = loadSchema('audit-event.schema.json');
// `strict: false` makes `format` an annotation only (not asserted), matching Python jsonschema's
// default; the schema's explicit `pattern` constraints do the real validation, exactly as in `models.ts`.
const validateSchema = new Ajv2020({ strict: false }).compile(eventSchema);

const validBase: Record<string, unknown> = {
  id: '00000000-0000-4000-8000-000000000001',
  spec_version: SPEC_VERSION,
  ts: '2026-07-15T00:00:01.000Z',
  session_id: SESSION,
  action_type: 'db.read',
  mutates: false,
  egress: false,
  target_resource: { kind: 'table', ref: 'customers' },
  outcome: 'attempted',
};

const fullValid: Record<string, unknown> = {
  ...validBase,
  traceparent: '00-abc-def-01',
  target_resource: { kind: 'table', ref: 'customers', scope_hint: 'row:x=1' },
  action_context: { dialect: 'postgres' },
  action_context_hash: `sha256:${'a'.repeat(64)}`,
  signer_seq: 0,
  key_id: 'k1',
  signature: 'c2ln',
};

const withoutTargetResource = Object.fromEntries(
  Object.entries(validBase).filter(([key]) => key !== 'target_resource'),
);

// [name, event, expectedValid]
const samples: [string, Record<string, unknown>, boolean][] = [
  ['minimal-valid', validBase, true],
  ['full-valid', fullValid, true],
  ['uppercase-uuid', { ...validBase, id: 'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA' }, false],
  ['uppercase-session', { ...validBase, session_id: SESSION.toUpperCase() }, false],
  ['nil-session', { ...validBase, session_id: '00000000-0000-0000-0000-000000000000' }, false],
  ['level2-without-signer-seq', { ...validBase, key_id: 'k1', signature: 'c2ln' }, false],
  ['level2-without-signature', { ...validBase, key_id: 'k1', signer_seq: 0 }, false],
  ['level2-signer-seq-alone', { ...validBase, signer_seq: 0 }, false],
  ['nil-uuid', { ...validBase, id: '00000000-0000-0000-0000-000000000000' }, true],
  ['bad-uuid', { ...validBase, id: 'not-a-uuid' }, false],
  ['uuid-bad-version', { ...validBase, id: '00000000-0000-9000-8000-000000000001' }, false],
  ['stale-spec-version', { ...validBase, spec_version: 'auditable-mcp/0.1' }, false],
  ['ts-garbage', { ...validBase, ts: 'yesterday' }, false],
  ['ts-bad-month', { ...validBase, ts: '2026-13-01T00:00:00Z' }, false],
  ['ts-feb-30', { ...validBase, ts: '2026-02-30T00:00:00Z' }, false],
  ['ts-offset-not-z', { ...validBase, ts: '2026-07-15T00:00:01+09:00' }, false],
  ['ach-bad', { ...validBase, action_context_hash: 'sha256:XYZ' }, false],
  ['ach-valid', { ...validBase, action_context_hash: `sha256:${'a'.repeat(64)}` }, true],
  ['signer-seq-negative', { ...validBase, signer_seq: -1 }, false],
  ['signer-seq-too-large', { ...validBase, signer_seq: 2 ** 53 }, false],
  ['empty-key-id', { ...fullValid, key_id: '' }, false],
  ['signature-not-base64', { ...fullValid, signature: 'not base64!' }, false],
  ['signature-base64url', { ...fullValid, signature: 'c2ln_-A' }, true],
  ['signature-standard-base64-padded', { ...fullValid, signature: 'c2lnbg==' }, false],
  ['signature-standard-base64-alphabet', { ...fullValid, signature: 'c2l+/g' }, false],
  ['session-not-uuid', { ...validBase, session_id: 'call_abc' }, false],
  ['aborted-without-reason', { ...validBase, outcome: 'aborted' }, false],
  ['aborted-with-reason', { ...validBase, outcome: 'aborted', reason: 'host-rejected' }, true],
  ['aborted-bad-reason', { ...validBase, outcome: 'aborted', reason: 'because' }, false],
  ['extra-property', { ...validBase, surprise: 'boom' }, false],
  ['missing-required', withoutTargetResource, false],
  ['bad-outcome', { ...validBase, outcome: 'weird' }, false],
  ['empty-action-type', { ...validBase, action_type: '' }, false],
];

describe('Zod schema acceptance matches the vendored JSON Schema', () => {
  for (const [name, event, expected] of samples) {
    it(`${name}: Zod and JSON Schema agree, expected=${expected}`, () => {
      const schemaOk = validateSchema(event);
      const zodOk = firstValidationError(event) === null;
      expect(schemaOk, `schema disagreed on ${name}`).toBe(expected);
      expect(zodOk, `zod disagreed on ${name}`).toBe(expected);
      expect(zodOk, `zod/schema drift on ${name}`).toBe(schemaOk);
    });
  }
});

const capabilitySchema = loadSchema('audit-capability.schema.json');
const validateCapabilitySchema = new Ajv2020({ strict: false }).compile(capabilitySchema);

const capValid: Record<string, unknown> = {
  spec_version: SPEC_VERSION,
  level: 'L1',
  attempt: 'request',
  countersign: 'none',
};

// All four fields REQUIRED (§6.1): a missing one is rejected, not defaulted, so a peer cannot bypass
// version or countersign negotiation by omission.
const capSamples: [string, Record<string, unknown>, boolean][] = [
  ['cap-valid', capValid, true],
  ['cap-l2', { ...capValid, level: 'L2' }, true],
  ['cap-missing-spec-version', { level: 'L1', attempt: 'request', countersign: 'none' }, false],
  ['cap-missing-level', { spec_version: capValid.spec_version, attempt: 'request', countersign: 'none' }, false],
  ['cap-missing-attempt', { spec_version: capValid.spec_version, level: 'L1', countersign: 'none' }, false],
  ['cap-countersign-host', { ...capValid, countersign: 'host' }, true],
  ['cap-missing-countersign', { spec_version: capValid.spec_version, level: 'L1', attempt: 'request' }, false],
  ['cap-bad-countersign', { ...capValid, countersign: 'self' }, false],
  ['cap-bad-level', { ...capValid, level: 'L3' }, false],
  ['cap-bad-attempt', { ...capValid, attempt: 'response' }, false],
  ['cap-extra-property', { ...capValid, surprise: 'boom' }, false],
];

describe('auditCapabilitySchema acceptance matches the vendored capability JSON Schema', () => {
  for (const [name, cap, expected] of capSamples) {
    it(`${name}: Zod and JSON Schema agree, expected=${expected}`, () => {
      const schemaOk = validateCapabilitySchema(cap);
      const zodOk = auditCapabilitySchema.safeParse(cap).success;
      expect(schemaOk, `schema disagreed on ${name}`).toBe(expected);
      expect(zodOk, `zod disagreed on ${name}`).toBe(expected);
      expect(zodOk, `zod/schema drift on ${name}`).toBe(schemaOk);
    });
  }
});

const ACCEPT: Record<string, unknown> = {
  status: 'accept',
  seq: 0,
  record_hash: 'a'.repeat(64),
  host_ts: '2026-07-15T00:00:01.000Z',
  previous_hash: '0'.repeat(64),
};
const TRIPLE: Record<string, unknown> = { host_signature: 'c2ln', host_key_id: 'host-key', log_id: 'tenant-a' };

// The countersignature triple travels whole (§7.1), and `unavailable` carries nothing but its reason.
const responseSamples: [string, Record<string, unknown>, boolean][] = [
  ['accept', ACCEPT, true],
  ['accept-countersigned', { ...ACCEPT, ...TRIPLE }, true],
  ['accept-without-log-id', { ...ACCEPT, host_signature: 'c2ln', host_key_id: 'host-key' }, false],
  ['accept-log-id-alone', { ...ACCEPT, log_id: 'tenant-a' }, false],
  ['accept-standard-base64', { ...ACCEPT, ...TRIPLE, host_signature: 'c2lnbg==' }, false],
  ['reject', { status: 'reject', reason: 'replay-detected' }, true],
  ['unavailable', { status: 'unavailable', reason: 'internal-error' }, true],
  ['unavailable-retryable-is-not-a-field', { status: 'unavailable', reason: 'internal-error', retryable: true }, false],
];

describe('attemptResponseSchema acceptance matches the vendored response JSON Schema', () => {
  const validate = new Ajv2020({ strict: false }).compile(loadSchema('audit-attempt-response.schema.json'));
  for (const [name, response, expected] of responseSamples) {
    it(`${name}: Zod and JSON Schema agree, expected=${expected}`, () => {
      expect(validate(response), `schema disagreed on ${name}`).toBe(expected);
      expect(attemptResponseSchema.safeParse(response).success, `zod disagreed on ${name}`).toBe(expected);
    });
  }
});

// The `_meta` objects of the §6.4 binding.
const metaSamples: [string, { safeParse(value: unknown): { success: boolean } }, string, unknown, boolean][] = [
  ['audit-request-meta.schema.json', auditRequestMetaSchema, 'session-only', { session_id: SESSION }, true],
  [
    'audit-request-meta.schema.json',
    auditRequestMetaSchema,
    'with-responses',
    { session_id: SESSION, responses: { '00000000-0000-4000-8000-000000000001': ACCEPT } },
    true,
  ],
  ['audit-request-meta.schema.json', auditRequestMetaSchema, 'session-not-uuid', { session_id: 'call-1' }, false],
  [
    'audit-request-meta.schema.json',
    auditRequestMetaSchema,
    'responses-key-not-uuid',
    { session_id: SESSION, responses: { 'not-a-uuid': ACCEPT } },
    false,
  ],
  [
    'audit-request-meta.schema.json',
    auditRequestMetaSchema,
    'responses-key-uppercase',
    { session_id: SESSION, responses: { '00000000-0000-4000-8000-00000000000A': ACCEPT } },
    false,
  ],
  [
    'audit-request-meta.schema.json',
    auditRequestMetaSchema,
    'nil-session',
    { session_id: '00000000-0000-0000-0000-000000000000' },
    false,
  ],
  ['audit-request-meta.schema.json', auditRequestMetaSchema, 'extra', { session_id: SESSION, x: 1 }, false],
  [
    'audit-result-meta.schema.json',
    auditResultMetaSchema,
    'one-event',
    { session_id: SESSION, events: [validBase] },
    true,
  ],
  ['audit-result-meta.schema.json', auditResultMetaSchema, 'no-events', { session_id: SESSION, events: [] }, false],
  // Each item is validated as an event on its own (§6.4); the envelope asks only that it be an object.
  [
    'audit-result-meta.schema.json',
    auditResultMetaSchema,
    'invalid-event-object',
    { session_id: SESSION, events: [{ id: 5 }] },
    true,
  ],
  [
    'audit-result-meta.schema.json',
    auditResultMetaSchema,
    'non-object-item',
    { session_id: SESSION, events: [5] },
    false,
  ],
  ['audit-result-meta.schema.json', auditResultMetaSchema, 'array-item', { session_id: SESSION, events: [[]] }, false],
];

describe('the §6.4 `_meta` schemas match their vendored JSON Schemas', () => {
  for (const [file, schema, name, value, expected] of metaSamples) {
    it(`${file}:${name}: Zod and JSON Schema agree, expected=${expected}`, () => {
      const validate = new Ajv2020({ strict: false }).compile(loadSchema(file));
      expect(validate(value), `schema disagreed on ${name}`).toBe(expected);
      expect(schema.safeParse(value).success, `zod disagreed on ${name}`).toBe(expected);
    });
  }
});

// Records sealed before v0.3 are validated against the vendored schema of their own version (§11.4).
const earlierBase: Record<string, unknown> = {
  id: 'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA',
  ts: '2026-07-15T00:00:01.000Z',
  call_id: 'call-1',
  action_type: 'db.read',
  mutates: false,
  egress: false,
  target_resource: { kind: 'table', ref: 'customers' },
  outcome: 'attempted',
};

const earlierSamples: [string, string, Record<string, unknown>, boolean][] = [
  ['0.1', 'minimal', {}, true],
  ['0.1', 'sequence', { sequence: 3, key_id: '', signature: 'anything' }, true],
  ['0.1', 'free-reason', { outcome: 'aborted', reason: 'because' }, true],
  ['0.1', 'aborted-without-reason', { outcome: 'aborted' }, true],
  ['0.1', 'signer-seq', { signer_seq: 0 }, false],
  ['0.1', 'session-id', { session_id: SESSION }, false],
  ['0.1.1', 'minimal', {}, true],
  ['0.1.1', 'signed', { signer_seq: 0, key_id: 'k1', signature: 'c2lnbg==' }, true],
  ['0.1.1', 'base64url-signature', { signature: 'c2ln_-A' }, false],
  ['0.1.1', 'sequence', { sequence: 3 }, false],
  ['0.1.1', 'aborted-without-reason', { outcome: 'aborted' }, false],
  ['0.2', 'minimal', {}, true],
  ['0.2', 'v0.3-reason', { outcome: 'aborted', reason: 'host-uncountersigned' }, false],
  ['0.2', 'no-call-id', { call_id: undefined }, false],
];

describe('earlier-version events match their vendored JSON Schemas', () => {
  for (const [version, name, overrides, expected] of earlierSamples) {
    it(`${version}:${name}: Zod and JSON Schema agree, expected=${expected}`, () => {
      const validate = new Ajv2020({ strict: false }).compile(loadSchema(`earlier/${version}/audit-event.schema.json`));
      const event = JSON.parse(
        JSON.stringify({ ...earlierBase, spec_version: `auditable-mcp/${version}`, ...overrides }),
      ) as Record<string, unknown>;
      expect(validate(event), `schema disagreed on ${version}:${name}`).toBe(expected);
      expect(firstSealedValidationError(event) === null, `zod disagreed on ${version}:${name}`).toBe(expected);
    });
  }
});
