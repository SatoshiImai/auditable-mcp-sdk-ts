/** Tests for the §6.2 degradation postures, mirroring the Python SDK's suite. */

import { describe, expect, it } from 'vitest';
import { NegotiationOutcome, negotiate } from '../src/capability';
import { Posture, transportFor, UnnegotiatedSessionError } from '../src/degradation';
import { AuditHost } from '../src/host';
import { InProcessTransport } from '../src/in-process';
import { type AuditCapability, Level, SPEC_VERSION, Witness } from '../src/models';
import { AmcpSession } from '../src/session';
import { verifyLedger } from '../src/verify';
import { FixedDeps, MonotonicClock } from './helpers';

const L1: AuditCapability = { spec_version: SPEC_VERSION, level: Level.L1, attempt: 'request', witness: Witness.NONE };

function transport(partition: string): InProcessTransport {
  return new InProcessTransport(new AuditHost(partition, L1, { clock: new MonotonicClock() }));
}

describe('degradation postures (§6.2)', () => {
  it('a negotiated session uses the host', () => {
    const wire = transport('tenant-a');
    expect(transportFor(negotiate(L1, L1), { negotiated: wire, fallback: transport('tool-local') })).toBe(wire);
  });

  it('an undeclared host degrades to the tool’s own', () => {
    const fallback = transport('tool-local');
    const result = negotiate(undefined, L1);
    expect(result.outcome).toBe(NegotiationOutcome.UNDECLARED);
    expect(transportFor(result, { negotiated: transport('tenant-a'), fallback })).toBe(fallback);
  });

  it('a mismatched host degrades the same way', () => {
    const fallback = transport('tool-local');
    const older: AuditCapability = { ...L1, spec_version: 'auditable-mcp/0.1' };
    const result = negotiate(older, L1);
    expect(result.outcome).toBe(NegotiationOutcome.MISMATCH);
    expect(transportFor(result, { negotiated: transport('tenant-a'), fallback })).toBe(fallback);
  });

  it('the mandatory posture declines to serve', () => {
    expect(() =>
      transportFor(negotiate(undefined, L1), {
        negotiated: transport('tenant-a'),
        fallback: transport('tool-local'),
        posture: Posture.MANDATORY,
      }),
    ).toThrow(UnnegotiatedSessionError);
  });

  it('the third posture is not available', () => {
    expect(() => transportFor(negotiate(undefined, L1), { negotiated: transport('tenant-a') })).toThrow(/fallback/);
  });

  it('a mandatory tool never needs a fallback', () => {
    expect(() =>
      transportFor(negotiate(undefined, L1), { negotiated: transport('tenant-a'), posture: Posture.MANDATORY }),
    ).toThrow(UnnegotiatedSessionError);
  });

  it('a degraded session keeps recording, and the chain is unwitnessed (§5.2)', async () => {
    const host = new AuditHost('tool-local', L1, { clock: new MonotonicClock() });
    const fallback = new InProcessTransport(host);
    const chosen = transportFor(negotiate(undefined, L1), { negotiated: transport('tenant-a'), fallback });
    const session = new AmcpSession(chosen, 'call-1', { deps: new FixedDeps() });
    await using _action = await session.action(
      'db.read',
      { kind: 'table', ref: 'customers' },
      {
        mutates: false,
        egress: false,
      },
    );
    const records = host.records();
    expect(records.length).toBeGreaterThan(0);
    expect(records.every((record) => record.host_signature === undefined)).toBe(true);
    expect(verifyLedger(records).complete).toBe(true);
  });
});
