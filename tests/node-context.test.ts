/** Tests for the Node entry point's ambient session, the counterpart of the Python decorator. */

import { describe, expect, it } from 'vitest';
import { AuditHost } from '../src/host';
import { InProcessTransport } from '../src/in-process';
import { audited, currentSession, runWithSession } from '../src/node/context';
import { AmcpSession } from '../src/session';
import { FixedDeps, MonotonicClock, SESSION } from './helpers';

const SPEC = {
  actionType: 'db.read',
  targetResource: { kind: 'table', ref: 'customers' },
  mutates: false,
  egress: false,
} as const;

function pair(): { host: AuditHost; session: AmcpSession } {
  const host = new AuditHost('tenant-a', undefined, { clock: new MonotonicClock() });
  host.openSession(SESSION);
  return { host, session: new AmcpSession(new InProcessTransport(host), SESSION, { deps: new FixedDeps() }) };
}

describe('the ambient session', () => {
  it('binds a session for the whole async subtree', async () => {
    const { host, session } = pair();
    const rows = await runWithSession(session, async () => {
      expect(currentSession()).toBe(session);
      return audited(SPEC, async () => 7);
    });
    expect(rows).toBe(7);
    expect(host.records().map((record) => record.event.outcome)).toEqual(['attempted', 'success']);
  });

  it('refuses to guess when no session is bound', () => {
    // Auditing against a session the caller did not choose would record the operation in the wrong
    // ledger, which is worse than failing to record it.
    expect(() => currentSession()).toThrow('no AmcpSession is bound');
  });

  it('records a failed outcome when the handler throws', async () => {
    const { host, session } = pair();
    await expect(
      runWithSession(session, () =>
        audited(SPEC, () => {
          throw new Error('the domain operation failed');
        }),
      ),
    ).rejects.toThrow('the domain operation failed');
    expect(host.records().map((record) => record.event.outcome)).toEqual(['attempted', 'failed']);
  });
});
