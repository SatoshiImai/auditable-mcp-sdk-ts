/**
 * Two host surfaces for a binding whose sessions are not a-MCP's calls: a session that outlives a
 * restart (`AuditHost.resume`'s `openSessions`), and an outcome whose fate the binding acknowledges
 * (`recordOutcome`). Neither changes how a host serving a-MCP's own bindings behaves.
 */

import { describe, expect, it } from 'vitest';
import { AuditHost, OutcomeDisposition } from '../src/host';
import { InProcessTransport } from '../src/in-process';
import { AmcpSession, SessionNumbering } from '../src/session';
import { InMemoryLedgerRepository } from '../src/storage';
import {
  eventIdAt,
  FailingRepository,
  FixedDeps,
  L2_CAPABILITY,
  MonotonicClock,
  makeAttempt,
  OkVerifier,
  SESSION,
  StubSigner,
  signed,
} from './helpers';

describe('recordOutcome reports what became of an outcome (§7.2)', () => {
  it('sealed, then repeat for the byte-identical copy', async () => {
    const host = new AuditHost('tenant-a', undefined, { clock: new MonotonicClock() });
    host.openSession(SESSION);
    const attempt = makeAttempt(eventIdAt(1));
    await host.handleAttempt(attempt);
    const outcome = { ...attempt, outcome: 'success' };
    expect(await host.recordOutcome(outcome)).toBe(OutcomeDisposition.SEALED);
    expect(await host.recordOutcome(outcome)).toBe(OutcomeDisposition.REPEAT);
  });

  it('refused, with the anomaly recorded, for an outcome with no accepted attempt', async () => {
    const host = new AuditHost('tenant-a', undefined, { clock: new MonotonicClock() });
    host.openSession(SESSION);
    expect(await host.recordOutcome(makeAttempt(eventIdAt(1), { outcome: 'success' }))).toBe(
      OutcomeDisposition.REFUSED,
    );
    expect(host.anomalies().map((anomaly) => anomaly.kind)).toEqual(['orphaned-outcome']);
  });

  it('not-recorded when persistence fails, which handleOutcome only logs', async () => {
    const host = new AuditHost('tenant-a', undefined, { clock: new MonotonicClock() });
    host.openSession(SESSION);
    const attempt = makeAttempt(eventIdAt(1));
    await host.handleAttempt(attempt);
    host.persistenceAvailable = false;
    expect(await host.recordOutcome({ ...attempt, outcome: 'success' })).toBe(OutcomeDisposition.NOT_RECORDED);
    expect(host.anomalies()).toEqual([]);
  });

  it('not-recorded when the store refuses the append', async () => {
    const host = new AuditHost('tenant-a', undefined, {
      clock: new MonotonicClock(),
      repository: new FailingRepository(),
    });
    host.openSession(SESSION);
    expect(
      await host.recordOutcome(makeAttempt(eventIdAt(1), { outcome: 'aborted', reason: 'host-unavailable' })),
    ).toBe(OutcomeDisposition.NOT_RECORDED);
  });
});

describe('AuditHost.resume with openSessions', () => {
  async function beforeRestart() {
    const repo = new InMemoryLedgerRepository();
    const host = new AuditHost('tenant-a', L2_CAPABILITY, {
      clock: new MonotonicClock(),
      repository: repo,
      verifier: new OkVerifier(),
    });
    host.openSession(SESSION);
    const resolved = signed(makeAttempt(eventIdAt(1)), 0);
    const pending = signed(makeAttempt(eventIdAt(2)), 2);
    const first = await host.handleAttempt(resolved);
    await host.handleOutcome(signed({ ...makeAttempt(eventIdAt(1)), outcome: 'success' }, 1));
    const second = await host.handleAttempt(pending);
    return { repo, first, second, pending };
  }

  function resume(repo: InMemoryLedgerRepository, openSessions?: string[]) {
    return AuditHost.resume('tenant-a', L2_CAPABILITY, {
      clock: new MonotonicClock(),
      repository: repo,
      verifier: new OkVerifier(),
      ...(openSessions === undefined ? {} : { openSessions }),
    });
  }

  it('keeps the named session open: a pending attempt is not unresolved, and its outcome seals', async () => {
    const { repo } = await beforeRestart();
    const host = await resume(repo, [SESSION]);
    expect(host.anomalies()).toEqual([]);
    expect(await host.recordOutcome(signed({ ...makeAttempt(eventIdAt(2)), outcome: 'success' }, 3))).toBe(
      OutcomeDisposition.SEALED,
    );
    expect((await host.handleAttempt(signed(makeAttempt(eventIdAt(3)), 4))).status).toBe('accept');
  });

  it('answers a byte-identical resend from the ledger, as before the restart (§7.1)', async () => {
    const { repo, second, pending } = await beforeRestart();
    const host = await resume(repo, [SESSION]);
    expect(await host.handleAttempt(pending)).toEqual(second);
  });

  it('refuses a signer_seq the session decided before the restart (§7.4)', async () => {
    const { repo } = await beforeRestart();
    const host = await resume(repo, [SESSION]);
    const reused = await host.handleAttempt(signed(makeAttempt(eventIdAt(4)), 1));
    expect(reused).toEqual({ status: 'reject', reason: 'replay-detected' });
  });

  it('refuses a second outcome for an operation sealed before the restart (§7.2)', async () => {
    const { repo } = await beforeRestart();
    const host = await resume(repo, [SESSION]);
    const differing = signed({ ...makeAttempt(eventIdAt(1)), outcome: 'failed' }, 3);
    expect(await host.recordOutcome(differing)).toBe(OutcomeDisposition.REFUSED);
    expect(host.anomalies().map((anomaly) => anomaly.kind)).toEqual(['replay-detected']);
  });

  it('without openSessions, ends every session as a-MCP does (§6.3)', async () => {
    const { repo } = await beforeRestart();
    const host = await resume(repo);
    expect(host.anomalies().map((anomaly) => anomaly.kind)).toEqual(['unresolved-attempt']);
    expect((await host.handleAttempt(signed(makeAttempt(eventIdAt(3)), 3))).status).toBe('reject');
  });
});

describe('SessionNumbering resumes a session at a given value (§7.4)', () => {
  it('numbers the next signed event from the start it was given', async () => {
    const host = new AuditHost('tenant-a', L2_CAPABILITY, { clock: new MonotonicClock(), verifier: new OkVerifier() });
    host.openSession(SESSION);
    const transport = Object.assign(new InProcessTransport(host), { numbering: new SessionNumbering(3) });
    const session = new AmcpSession(transport, SESSION, { signer: new StubSigner(), deps: new FixedDeps() });
    await (async () => {
      await using action = await session.action(
        'db.read',
        { kind: 'table', ref: 'customers' },
        { mutates: false, egress: false },
      );
      action.succeeded();
    })();
    expect(host.records().map((record) => record.event.signer_seq)).toEqual([3, 4]);
  });

  it('names, on the action, the id its attempt and outcome carry', async () => {
    const host = new AuditHost('tenant-a', undefined, { clock: new MonotonicClock() });
    host.openSession(SESSION);
    const session = new AmcpSession(new InProcessTransport(host), SESSION, { deps: new FixedDeps() });
    let id = '';
    await (async () => {
      await using action = await session.action(
        'db.read',
        { kind: 'table', ref: 'customers' },
        { mutates: false, egress: false },
      );
      id = action.id;
      action.succeeded();
    })();
    expect(host.records().map((record) => record.event.id)).toEqual([id, id]);
  });

  it('refuses a start that is not a non-negative integer', () => {
    expect(() => new SessionNumbering(-1)).toThrow(/§7.4/);
    expect(() => new SessionNumbering(1.5)).toThrow(/§7.4/);
  });
});
