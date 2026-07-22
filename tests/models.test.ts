import { describe, expect, it } from 'vitest';
import {
  attemptResponseSchema,
  auditCapabilitySchema,
  auditEventSchema,
  firstValidationError,
  Level,
  Outcome,
  SPEC_VERSION,
  Status,
} from '../src/models';
import { eventVectors } from './vectors';

const base = {
  id: '00000000-0000-4000-8000-000000000001',
  spec_version: SPEC_VERSION,
  ts: '2026-07-15T00:00:01.000Z',
  call_id: 'call_abc',
  action_type: 'db.read',
  mutates: false,
  egress: false,
  target_resource: { kind: 'table', ref: 'customers' },
  outcome: 'attempted',
};

describe('auditEventSchema accepts every golden event vector', () => {
  for (const vector of eventVectors) {
    it(`accepts ${vector.name}`, () => {
      expect(auditEventSchema.safeParse(vector.event).success).toBe(true);
    });
  }
});

describe('auditEventSchema forbids silent coercion and unknown keys', () => {
  it('rejects 1 for a boolean field', () => {
    expect(auditEventSchema.safeParse({ ...base, mutates: 1 }).success).toBe(false);
  });

  it('rejects an unknown key (closed shape)', () => {
    expect(auditEventSchema.safeParse({ ...base, surprise: 'boom' }).success).toBe(false);
  });

  it('rejects a stale spec_version', () => {
    expect(auditEventSchema.safeParse({ ...base, spec_version: 'auditable-mcp/0.1' }).success).toBe(false);
  });

  it('firstValidationError returns null when valid and a path-prefixed message when not', () => {
    expect(firstValidationError(base)).toBeNull();
    const message = firstValidationError({ ...base, outcome: 'weird' });
    expect(message).not.toBeNull();
    expect(message).toContain('outcome');
  });
});

describe('auditEventSchema pins reason to the abort codes and requires it for aborted (§7.6)', () => {
  it('requires a reason when outcome is aborted', () => {
    expect(auditEventSchema.safeParse({ ...base, outcome: 'aborted' }).success).toBe(false);
    expect(auditEventSchema.safeParse({ ...base, outcome: 'aborted', reason: 'host-rejected' }).success).toBe(true);
  });

  it('rejects a non-Tier-1 abort reason', () => {
    expect(auditEventSchema.safeParse({ ...base, outcome: 'aborted', reason: 'because' }).success).toBe(false);
  });
});

describe('auditCapabilitySchema requires all three fields with no defaulting (§6.1)', () => {
  it('rejects a capability that omits spec_version', () => {
    expect(auditCapabilitySchema.safeParse({ level: Level.L2, attempt: 'request' }).success).toBe(false);
  });

  it('rejects a capability that omits level or attempt (no silent coercion)', () => {
    expect(auditCapabilitySchema.safeParse({ spec_version: SPEC_VERSION, attempt: 'request' }).success).toBe(false);
    expect(auditCapabilitySchema.safeParse({ spec_version: SPEC_VERSION, level: Level.L1 }).success).toBe(false);
    expect(auditCapabilitySchema.safeParse({ spec_version: SPEC_VERSION }).success).toBe(false);
  });

  it('accepts a fully specified capability', () => {
    const parsed = auditCapabilitySchema.parse({ spec_version: SPEC_VERSION, level: Level.L2, attempt: 'request' });
    expect(parsed.level).toBe(Level.L2);
    expect(parsed.attempt).toBe('request');
  });
});

describe('attemptResponseSchema discriminates on status and pins Tier-1 reasons', () => {
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
    expect(attemptResponseSchema.safeParse({ status: Status.REJECT, reason: 'replay-detected' }).success).toBe(true);
    expect(
      attemptResponseSchema.safeParse({ status: Status.UNAVAILABLE, reason: 'internal-error', retryable: true })
        .success,
    ).toBe(true);
  });

  it('rejects a non-Tier-1 reject reason', () => {
    expect(attemptResponseSchema.safeParse({ status: Status.REJECT, reason: 'nope' }).success).toBe(false);
  });

  it('rejects unavailable with retryable=false', () => {
    expect(
      attemptResponseSchema.safeParse({ status: Status.UNAVAILABLE, reason: 'internal-error', retryable: false })
        .success,
    ).toBe(false);
  });
});

describe('Outcome / Level / Status values equal the wire strings', () => {
  it('enum values are the spec strings', () => {
    expect(Outcome.ATTEMPTED).toBe('attempted');
    expect(Level.L2).toBe('L2');
    expect(Status.ACCEPT).toBe('accept');
    expect(SPEC_VERSION).toBe('auditable-mcp/0.1.1');
  });
});
