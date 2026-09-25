import { describe, expect, it } from 'vitest';
import { countersignSatisfies, levelSatisfies, NegotiationOutcome, negotiate } from '../src/capability';
import { AuditHost } from '../src/host';
import { InProcessTransport } from '../src/in-process';
import { type AuditCapability, Countersign, Level, SPEC_VERSION } from '../src/models';
import { accept, reject, unavailable } from '../src/transport';
import { makeAttempt, SESSION } from './helpers';

const L1: AuditCapability = {
  spec_version: SPEC_VERSION,
  level: Level.L1,
  attempt: 'request',
  countersign: Countersign.NONE,
};
const L2: AuditCapability = {
  spec_version: SPEC_VERSION,
  level: Level.L2,
  attempt: 'request',
  countersign: Countersign.NONE,
};

const countersigning: AuditCapability = { ...L1, countersign: Countersign.HOST };

describe('capability negotiation (§6.1)', () => {
  it('an L2 offer satisfies an L1 requirement (safe downgrade)', () => {
    expect(levelSatisfies(L2, L1)).toBe(true);
  });

  it('an L1 offer does not satisfy an L2 requirement', () => {
    expect(levelSatisfies(L1, L2)).toBe(false);
    expect(negotiate(L2, L1).negotiated).toBe(false);
  });

  it('flags a spec_version mismatch and withholds the fit', () => {
    const older: AuditCapability = {
      spec_version: 'auditable-mcp/0.1',
      level: Level.L1,
      attempt: 'request',
      countersign: Countersign.NONE,
    };
    const result = negotiate(L1, older);
    expect(result.versionMatch).toBe(false);
    expect(result.negotiated).toBe(false);
  });

  it('negotiate returns both declarations and the fit', () => {
    const result = negotiate(L1, L2);
    expect(result.host).toEqual(L1);
    expect(result.tool).toEqual(L2);
    expect(result.negotiated).toBe(true);
    expect(result.versionMatch).toBe(true);
  });

  it('a signing host satisfies a tool that requires a countersign (§5.2)', () => {
    expect(countersignSatisfies(countersigning, countersigning)).toBe(true);
    expect(negotiate(countersigning, countersigning).negotiated).toBe(true);
  });

  it('a non-signing host cannot satisfy a tool that requires a countersign', () => {
    const result = negotiate(L1, countersigning);
    expect(result.outcome).toBe(NegotiationOutcome.MISMATCH);
    expect(result.countersignFit).toBe(false);
    expect(result.levelFit).toBe(true);
  });

  it('the axes run in opposite directions (§6.1)', () => {
    // Level: the tool produces, so a tool surplus is safe and a host surplus is not.
    expect(negotiate(L1, L2).negotiated).toBe(true);
    expect(negotiate(L2, L1).negotiated).toBe(false);
    // Countersign: the host produces, so the surplus that is safe sits on the other side.
    expect(negotiate(countersigning, L1).negotiated).toBe(true);
    expect(negotiate(L1, countersigning).negotiated).toBe(false);
  });

  it('a host that declared nothing is not a mismatch (§6.2)', () => {
    const result = negotiate(undefined, L1);
    expect(result.outcome).toBe(NegotiationOutcome.UNDECLARED);
    expect(result.negotiated).toBe(false);
    expect(result.host).toBeUndefined();
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
    expect(unavailable()).toEqual({ status: 'unavailable', reason: 'internal-error' });
  });
});

describe('InProcessTransport forwards to the endpoint', () => {
  it('negotiate compares against the endpoint requirement', () => {
    const transport = new InProcessTransport(new AuditHost('tenant-a'));
    expect(transport.negotiate(L1).negotiated).toBe(true);
  });

  it('forwards sendAttempt and sendOutcome to the endpoint', async () => {
    const host = new AuditHost('tenant-a');
    host.openSession(SESSION);
    const transport = new InProcessTransport(host);
    const attempt = makeAttempt('00000000-0000-4000-8000-000000000001');
    const response = await transport.sendAttempt(attempt);
    expect(response.status).toBe('accept');
    await transport.sendOutcome({ ...attempt, outcome: 'success' });
    expect(host.records()).toHaveLength(2);
  });
});
