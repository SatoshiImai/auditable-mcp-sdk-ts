import { describe, expect, it } from 'vitest';
import {
  attemptResponseSchema,
  auditCapabilitySchema,
  auditEventSchema,
  firstValidationError,
  Level,
  Outcome,
  Status,
} from '../src/models';
import { eventVectors } from './vectors';

describe('auditEventSchema accepts every golden event vector', () => {
  for (const vector of eventVectors) {
    it(`accepts ${vector.name}`, () => {
      expect(auditEventSchema.safeParse(vector.event).success).toBe(true);
    });
  }
});

describe('auditEventSchema forbids silent coercion and unknown keys', () => {
  const base = {
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

  it('rejects 1 for a boolean field', () => {
    expect(auditEventSchema.safeParse({ ...base, mutates: 1 }).success).toBe(false);
  });

  it('rejects an unknown key (closed shape)', () => {
    expect(auditEventSchema.safeParse({ ...base, surprise: 'boom' }).success).toBe(false);
  });

  it('firstValidationError returns null when valid and a path-prefixed message when not', () => {
    expect(firstValidationError(base)).toBeNull();
    const message = firstValidationError({ ...base, outcome: 'weird' });
    expect(message).not.toBeNull();
    expect(message).toContain('outcome');
  });
});

describe('auditCapabilitySchema fills defaults', () => {
  it('defaults to L1 / request from an empty object', () => {
    const parsed = auditCapabilitySchema.parse({});
    expect(parsed.level).toBe(Level.L1);
    expect(parsed.attempt).toBe('request');
  });
});

describe('attemptResponseSchema discriminates on status', () => {
  it('accepts accept / reject / unavailable by discriminator', () => {
    expect(
      attemptResponseSchema.safeParse({
        status: Status.ACCEPT,
        seq: 0,
        record_hash: '0'.repeat(64),
        host_ts: '2026-07-15T00:00:01.000Z',
        previous_hash: '0'.repeat(64),
      }).success,
    ).toBe(true);
    expect(attemptResponseSchema.safeParse({ status: Status.REJECT, reason: 'schema-invalid' }).success).toBe(true);
    expect(
      attemptResponseSchema.safeParse({ status: Status.UNAVAILABLE, reason: 'persistence-failure', retryable: true })
        .success,
    ).toBe(true);
  });

  it('rejects unavailable with retryable=false', () => {
    expect(attemptResponseSchema.safeParse({ status: Status.UNAVAILABLE, reason: 'x', retryable: false }).success).toBe(
      false,
    );
  });
});

describe('Outcome / Level / Status values equal the wire strings', () => {
  it('enum values are the spec strings', () => {
    expect(Outcome.ATTEMPTED).toBe('attempted');
    expect(Level.L2).toBe('L2');
    expect(Status.ACCEPT).toBe('accept');
  });
});
