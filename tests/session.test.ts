import { describe, expect, it } from 'vitest';
import { AuditHost } from '../src/host';
import { InProcessTransport } from '../src/in-process';
import { type AuditCapability, Level } from '../src/models';
import { AmcpAbortedError, AmcpSession } from '../src/session';
import type { AuditTransport } from '../src/transport';
import { verifyLedger } from '../src/verify';
import { withAudit } from '../src/with-audit';
import { FixedDeps, MonotonicClock, OkVerifier, StubSigner } from './helpers';

const L2: AuditCapability = { level: Level.L2, attempt: 'request' };
const TABLE = { kind: 'table', ref: 'orders' };

function l1Pair(): { host: AuditHost; session: AmcpSession } {
  const host = new AuditHost('tenant-a', undefined, { clock: new MonotonicClock() });
  const session = new AmcpSession(new InProcessTransport(host), 'call-1', { deps: new FixedDeps() });
  return { host, session };
}

function lastOutcome(host: AuditHost): unknown {
  const records = host.records();
  return records[records.length - 1]?.event.outcome;
}

describe('withAudit maps the handler result to the terminal outcome', () => {
  it('seals attempt + success and returns the handler value', async () => {
    const { host, session } = l1Pair();
    const result = await withAudit(
      session,
      { actionType: 'db.query', targetResource: TABLE, mutates: false, egress: true },
      () => 42,
    );
    expect(result).toBe(42);
    expect(host.records()).toHaveLength(2);
    expect(lastOutcome(host)).toBe('success');
    expect(verifyLedger(host.records(), host.digest()).ok).toBe(true);
  });

  it('seals a failed outcome and rethrows when the handler throws', async () => {
    const { host, session } = l1Pair();
    await expect(
      withAudit(session, { actionType: 'db.write', targetResource: TABLE, mutates: true, egress: false }, () => {
        throw new Error('boom');
      }),
    ).rejects.toThrow('boom');
    expect(host.records()).toHaveLength(2);
    expect(lastOutcome(host)).toBe('failed');
  });

  it('throws AmcpAbortedError and does not run the handler when the host refuses', async () => {
    // An L2 host with an unsigned session: the attempt is rejected as l2-unsigned.
    const host = new AuditHost('tenant-a', L2, { verifier: new OkVerifier(), clock: new MonotonicClock() });
    const session = new AmcpSession(new InProcessTransport(host), 'call-1', { deps: new FixedDeps() });
    let ran = false;
    await expect(
      withAudit(session, { actionType: 'db.write', targetResource: TABLE, mutates: true, egress: false }, () => {
        ran = true;
      }),
    ).rejects.toBeInstanceOf(AmcpAbortedError);
    expect(ran).toBe(false);
    expect(host.records()).toHaveLength(0);
  });
});

describe('await using is the fail-closed primitive', () => {
  it('records success only when succeeded() is called', async () => {
    const { host, session } = l1Pair();
    await (async () => {
      await using action = await session.action('db.query', TABLE, { mutates: false, egress: true });
      expect(action.accept?.seq).toBe(0);
      action.succeeded();
    })();
    expect(lastOutcome(host)).toBe('success');
  });

  it('fails closed to failed when succeeded() is forgotten', async () => {
    const { host, session } = l1Pair();
    await (async () => {
      await using _action = await session.action('db.query', TABLE, { mutates: false, egress: true });
      // deliberately do not call succeeded()
    })();
    expect(lastOutcome(host)).toBe('failed');
  });

  it('fails closed to failed and does not suppress an exception in the block', async () => {
    const { host, session } = l1Pair();
    await expect(
      (async () => {
        await using _action = await session.action('db.write', TABLE, { mutates: true, egress: false });
        throw new Error('boom');
      })(),
    ).rejects.toThrow('boom');
    expect(lastOutcome(host)).toBe('failed');
  });
});

describe('Polluted Stop (§7.2)', () => {
  it('aborts with hash-mismatch when the accept record_hash is tampered', async () => {
    const host = new AuditHost('tenant-a', undefined, { clock: new MonotonicClock() });
    const tampering: AuditTransport = {
      negotiate: (offered) => new InProcessTransport(host).negotiate(offered),
      sendAttempt: async (event) => {
        const response = await host.handleAttempt(event);
        return response.status === 'accept' ? { ...response, record_hash: 'f'.repeat(64) } : response;
      },
      sendOutcome: (event) => host.handleOutcome(event),
    };
    // pollutedStop opted in under L1 to exercise the check without a signer.
    const session = new AmcpSession(tampering, 'call-1', { deps: new FixedDeps(), pollutedStop: true });

    let error: unknown;
    try {
      await withAudit(session, { actionType: 'db.write', targetResource: TABLE, mutates: true, egress: false }, () => {
        throw new Error('handler should not run');
      });
    } catch (caught) {
      error = caught;
    }
    expect(error).toBeInstanceOf(AmcpAbortedError);
    expect((error as AmcpAbortedError).reason).toBe('hash-mismatch');
  });
});

describe('Level 2 session end-to-end', () => {
  it('signs, passes Polluted Stop, and seals a verifiable chain', async () => {
    const host = new AuditHost('tenant-a', L2, { verifier: new OkVerifier(), clock: new MonotonicClock() });
    const session = new AmcpSession(new InProcessTransport(host), 'call-1', {
      deps: new FixedDeps(),
      signer: new StubSigner(),
    });
    const result = await withAudit(
      session,
      {
        actionType: 'db.query',
        targetResource: TABLE,
        mutates: false,
        egress: true,
        disclose: { dialect: 'postgres' },
      },
      () => 'ok',
    );
    expect(result).toBe('ok');
    expect(host.records()).toHaveLength(2);
    expect(verifyLedger(host.records(), host.digest()).ok).toBe(true);
  });
});
