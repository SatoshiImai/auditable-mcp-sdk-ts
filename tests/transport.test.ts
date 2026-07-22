import { describe, expect, it } from 'vitest';
import { capabilitySatisfies, negotiate } from '../src/capability';
import { AuditHost } from '../src/host';
import { InProcessTransport } from '../src/in-process';
import { type AuditCapability, Level, SPEC_VERSION } from '../src/models';
import { accept, reject, unavailable } from '../src/transport';
import { makeAttempt } from './helpers';

const L1: AuditCapability = { spec_version: SPEC_VERSION, level: Level.L1, attempt: 'request' };
const L2: AuditCapability = { spec_version: SPEC_VERSION, level: Level.L2, attempt: 'request' };

describe('capability negotiation (§6.1)', () => {
  it('an L2 offer satisfies an L1 requirement (safe downgrade)', () => {
    expect(capabilitySatisfies(L2, L1)).toBe(true);
  });

  it('an L1 offer does not satisfy an L2 requirement', () => {
    expect(capabilitySatisfies(L1, L2)).toBe(false);
    expect(negotiate(L2, L1).satisfied).toBe(false);
  });

  it('flags a spec_version mismatch and withholds satisfaction', () => {
    const older: AuditCapability = { spec_version: 'auditable-mcp/0.1', level: Level.L1, attempt: 'request' };
    const result = negotiate(L1, older);
    expect(result.versionMatch).toBe(false);
    expect(result.satisfied).toBe(false);
  });

  it('negotiate returns the requirement, the offer, and the fit', () => {
    const result = negotiate(L1, L2);
    expect(result.required).toEqual(L1);
    expect(result.offered).toEqual(L2);
    expect(result.satisfied).toBe(true);
    expect(result.versionMatch).toBe(true);
  });
});

describe('response builders', () => {
  it('accept / reject / unavailable produce the wire shape', () => {
    expect(accept(0, '0'.repeat(64), '2026-07-15T00:00:01.000Z', '0'.repeat(64))).toEqual({
      status: 'accept',
      seq: 0,
      record_hash: '0'.repeat(64),
      host_ts: '2026-07-15T00:00:01.000Z',
      previous_hash: '0'.repeat(64),
    });
    expect(reject('schema-invalid')).toEqual({ status: 'reject', reason: 'schema-invalid' });
    expect(unavailable()).toEqual({ status: 'unavailable', reason: 'internal-error', retryable: true });
  });
});

describe('InProcessTransport forwards to the endpoint', () => {
  it('negotiate compares against the endpoint requirement', () => {
    const transport = new InProcessTransport(new AuditHost('tenant-a'));
    expect(transport.negotiate(L1).satisfied).toBe(true);
  });

  it('forwards sendAttempt and sendOutcome to the endpoint', async () => {
    const host = new AuditHost('tenant-a');
    const transport = new InProcessTransport(host);
    const attempt = makeAttempt('00000000-0000-4000-8000-000000000001');
    const response = await transport.sendAttempt(attempt);
    expect(response.status).toBe('accept');
    await transport.sendOutcome({ ...attempt, outcome: 'success' });
    expect(host.records()).toHaveLength(2);
  });
});
