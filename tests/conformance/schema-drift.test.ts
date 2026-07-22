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
import { firstValidationError } from '../../src/models';

const SCHEMA_PATH = join(
  dirname(fileURLToPath(import.meta.url)),
  '..',
  '..',
  'spec',
  'schema',
  'audit-event.schema.json',
);
const eventSchema = JSON.parse(readFileSync(SCHEMA_PATH, 'utf-8'));
// `strict: false` makes `format` an annotation only (not asserted), matching Python jsonschema's
// default; the schema's explicit `pattern` constraints do the real validation, exactly as in `models.ts`.
const validateSchema = new Ajv2020({ strict: false }).compile(eventSchema);

const validBase: Record<string, unknown> = {
  id: '00000000-0000-4000-8000-000000000001',
  spec_version: 'auditable-mcp/0.1',
  ts: '2026-07-15T00:00:01.000Z',
  call_id: 'call_abc',
  action_type: 'db.read',
  mutates: false,
  egress: false,
  target_resource: { kind: 'table', ref: 'customers' },
  outcome: 'attempted',
};

const fullValid: Record<string, unknown> = {
  ...validBase,
  traceparent: '00-abc-def-01',
  reason: 'context',
  target_resource: { kind: 'table', ref: 'customers', scope_hint: 'row:x=1' },
  action_context: { dialect: 'postgres' },
  action_context_hash: `sha256:${'a'.repeat(64)}`,
  sequence: 0,
  key_id: 'k1',
  signature: 'sig',
};

const withoutTargetResource = Object.fromEntries(
  Object.entries(validBase).filter(([key]) => key !== 'target_resource'),
);

// [name, event, expectedValid]
const samples: [string, Record<string, unknown>, boolean][] = [
  ['minimal-valid', validBase, true],
  ['full-valid', fullValid, true],
  ['uppercase-uuid', { ...validBase, id: 'AAAAAAAA-AAAA-4AAA-8AAA-AAAAAAAAAAAA' }, true],
  ['nil-uuid', { ...validBase, id: '00000000-0000-0000-0000-000000000000' }, true],
  ['bad-uuid', { ...validBase, id: 'not-a-uuid' }, false],
  ['uuid-bad-version', { ...validBase, id: '00000000-0000-9000-8000-000000000001' }, false],
  ['ts-garbage', { ...validBase, ts: 'yesterday' }, false],
  ['ts-bad-month', { ...validBase, ts: '2026-13-01T00:00:00Z' }, false],
  ['ts-feb-30', { ...validBase, ts: '2026-02-30T00:00:00Z' }, false],
  ['ts-offset-not-z', { ...validBase, ts: '2026-07-15T00:00:01+09:00' }, false],
  ['ach-bad', { ...validBase, action_context_hash: 'sha256:XYZ' }, false],
  ['ach-valid', { ...validBase, action_context_hash: `sha256:${'a'.repeat(64)}` }, true],
  ['sequence-negative', { ...validBase, sequence: -1 }, false],
  ['sequence-too-large', { ...validBase, sequence: 2 ** 53 }, false],
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
