import { describe, expect, it, vi } from 'vitest';
import { AuditHost } from '../src/host';
import { InMemoryLedgerRepository } from '../src/storage';
import { verifyLedger } from '../src/verify';
import {
  BadVerifier,
  eventIdAt,
  FailingRepository,
  FlakyRepository,
  L2_CAPABILITY,
  MonotonicClock,
  makeAttempt,
  OkVerifier,
  SESSION,
  signed,
} from './helpers';

function l1Host(): AuditHost {
  const host = new AuditHost('tenant-a', undefined, { clock: new MonotonicClock() });
  host.openSession(SESSION);
  return host;
}

describe('AuditHost attempt validation (§7.1)', () => {
  it('seals a well-formed attempt and answers with a Verifiable Accept', async () => {
    const host = l1Host();
    const response = await host.handleAttempt(makeAttempt(eventIdAt(1)));
    expect(response.status).toBe('accept');
    if (response.status === 'accept') {
      expect(response.seq).toBe(0);
    }
    expect(host.records()).toHaveLength(1);
  });

  it('rejects and flags a malformed attempt as schema-invalid', async () => {
    const host = l1Host();
    const bad = makeAttempt(eventIdAt(1));
    delete bad.target_resource;
    const response = await host.handleAttempt(bad);
    expect(response.status).toBe('reject');
    if (response.status === 'reject') {
      expect(response.reason).toBe('schema-invalid');
    }
    expect(host.anomalies().some((a) => a.kind === 'schema-invalid')).toBe(true);
  });

  it('rejects a non-attempted outcome on an attempt as schema-invalid', async () => {
    const host = l1Host();
    const response = await host.handleAttempt(makeAttempt(eventIdAt(1), { outcome: 'success' }));
    expect(response.status).toBe('reject');
    if (response.status === 'reject') {
      expect(response.reason).toBe('schema-invalid');
    }
  });

  it('rejects a number outside the §8.1 domain as schema-invalid', async () => {
    const host = l1Host();
    const response = await host.handleAttempt(makeAttempt(eventIdAt(1), { action_context: { n: 2 ** 53 } }));
    expect(response.status).toBe('reject');
    if (response.status === 'reject') {
      expect(response.reason).toBe('schema-invalid');
    }
  });

  it('answers a byte-identical repeat of a sealed attempt with the original accept (§7.1)', async () => {
    const host = l1Host();
    const event = makeAttempt(eventIdAt(1));
    const first = await host.handleAttempt(event);
    expect(await host.handleAttempt({ ...event })).toEqual(first);
    expect(host.records()).toHaveLength(1);
    expect(host.anomalies()).toHaveLength(0);
  });

  it('rejects an attempt id already sealed with a different event as replay-detected', async () => {
    const host = l1Host();
    await host.handleAttempt(makeAttempt(eventIdAt(1)));
    const response = await host.handleAttempt(
      makeAttempt(eventIdAt(1), { target_resource: { kind: 'table', ref: 'salaries' } }),
    );
    expect(response).toEqual({ status: 'reject', reason: 'replay-detected' });
    expect(host.records()).toHaveLength(1);
  });

  it("rejects an event outside the call's audit session (§6.3)", async () => {
    const host = l1Host();
    const other = '0198f3a2-5c1e-7000-8000-00000000ffff';
    expect(await host.handleAttempt(makeAttempt(eventIdAt(1), { session_id: other }))).toEqual({
      status: 'reject',
      reason: 'replay-detected',
    });
    host.openSession(other);
    expect((await host.handleAttempt(makeAttempt(eventIdAt(1), { session_id: other }), SESSION)).status).toBe('reject');
    await host.closeSession(SESSION);
    expect((await host.handleAttempt(makeAttempt(eventIdAt(2)))).status).toBe('reject');
    expect(host.records()).toHaveLength(0);
  });

  it('records an attempt left unresolved when the call ends (§6.3)', async () => {
    const host = l1Host();
    await host.handleAttempt(makeAttempt(eventIdAt(1)));
    await host.closeSession(SESSION);
    expect(host.anomalies().map((a) => a.kind)).toEqual(['unresolved-attempt']);
  });

  it('issues a session once (§6.3)', () => {
    const host = l1Host();
    expect(() => host.openSession(SESSION)).toThrow(/already issued/);
  });
});

describe('AuditHost fail-closed persistence (§7.1)', () => {
  it('returns unavailable/internal-error when persistence is flagged down', async () => {
    const host = l1Host();
    host.persistenceAvailable = false;
    const response = await host.handleAttempt(makeAttempt(eventIdAt(1)));
    expect(response.status).toBe('unavailable');
    if (response.status === 'unavailable') {
      expect(response.reason).toBe('internal-error');
    }
  });

  it('returns unavailable when the repository append fails', async () => {
    const host = new AuditHost('tenant-a', undefined, {
      clock: new MonotonicClock(),
      repository: new FailingRepository(),
    });
    host.openSession(SESSION);
    const response = await host.handleAttempt(makeAttempt(eventIdAt(1)));
    expect(response.status).toBe('unavailable');
    expect(host.records()).toHaveLength(0);
  });
});

describe('AuditHost outcome handling (§7.2)', () => {
  it('seals a correlated outcome after its accepted attempt', async () => {
    const host = l1Host();
    const attempt = makeAttempt(eventIdAt(1));
    await host.handleAttempt(attempt);
    await host.handleOutcome({ ...attempt, outcome: 'success' });
    expect(host.records()).toHaveLength(2);
    expect(verifyLedger(host.records(), host.digest()).ok).toBe(true);
  });

  it('drops an attempted outcome on the audit/outcome channel and flags schema-invalid (§6)', async () => {
    const host = l1Host();
    const attempt = makeAttempt(eventIdAt(1));
    await host.handleAttempt(attempt);
    await host.handleOutcome({ ...attempt, outcome: 'attempted' });
    expect(host.records()).toHaveLength(1);
    expect(host.anomalies().some((a) => a.kind === 'schema-invalid')).toBe(true);
  });

  it('flags an outcome that never had an accepted attempt as orphaned-outcome', async () => {
    const host = l1Host();
    await host.handleOutcome(makeAttempt(eventIdAt(1), { outcome: 'success' }));
    expect(host.records()).toHaveLength(0);
    const orphan = host.anomalies().find((a) => a.kind === 'orphaned-outcome');
    expect(orphan?.detail).toContain('without an accepted attempt');
  });

  it('seals an aborted outcome for a never-accepted attempt as a refusal, not an anomaly (§7.2, §10.4)', async () => {
    const host = l1Host();
    await host.handleOutcome(makeAttempt(eventIdAt(1), { outcome: 'aborted', reason: 'host-rejected' }));
    expect(host.records().map((record) => record.event.outcome)).toEqual(['aborted']);
    expect(host.anomalies()).toHaveLength(0);
  });
});

describe('AuditHost Level 2 (§7.1, §7.4)', () => {
  it('requires a verifier at construction time', () => {
    expect(() => new AuditHost('tenant-a', L2_CAPABILITY)).toThrow(/SignatureVerifier/);
  });

  it('accepts a valid signed attempt', async () => {
    const host = new AuditHost('tenant-a', L2_CAPABILITY, { verifier: new OkVerifier(), clock: new MonotonicClock() });
    host.openSession(SESSION);
    const response = await host.handleAttempt(signed(makeAttempt(eventIdAt(1)), 1));
    expect(response.status).toBe('accept');
  });

  it('rejects a forged signature as signature-invalid', async () => {
    const host = new AuditHost('tenant-a', L2_CAPABILITY, { verifier: new BadVerifier(), clock: new MonotonicClock() });
    host.openSession(SESSION);
    const response = await host.handleAttempt(signed(makeAttempt(eventIdAt(1)), 1));
    expect(response.status).toBe('reject');
    if (response.status === 'reject') {
      expect(response.reason).toBe('signature-invalid');
    }
  });

  it('rejects an unsigned attempt under L2 as l2-unsigned', async () => {
    const host = new AuditHost('tenant-a', L2_CAPABILITY, { verifier: new OkVerifier(), clock: new MonotonicClock() });
    host.openSession(SESSION);
    const response = await host.handleAttempt(makeAttempt(eventIdAt(1)));
    expect(response.status).toBe('reject');
    if (response.status === 'reject') {
      expect(response.reason).toBe('l2-unsigned');
    }
  });

  it('rejects a replayed signer_seq as replay-detected', async () => {
    const host = new AuditHost('tenant-a', L2_CAPABILITY, { verifier: new OkVerifier(), clock: new MonotonicClock() });
    host.openSession(SESSION);
    await host.handleAttempt(signed(makeAttempt(eventIdAt(1)), 5));
    const response = await host.handleAttempt(signed(makeAttempt(eventIdAt(2)), 5));
    expect(response.status).toBe('reject');
    if (response.status === 'reject') {
      expect(response.reason).toBe('replay-detected');
    }
  });

  it('accepts but flags a forward signer_seq gap as signer-seq-gap', async () => {
    const host = new AuditHost('tenant-a', L2_CAPABILITY, { verifier: new OkVerifier(), clock: new MonotonicClock() });
    host.openSession(SESSION);
    await host.handleAttempt(signed(makeAttempt(eventIdAt(1)), 1));
    const response = await host.handleAttempt(signed(makeAttempt(eventIdAt(2)), 3));
    expect(response.status).toBe('accept');
    expect(host.anomalies().some((a) => a.kind === 'signer-seq-gap')).toBe(true);
  });

  it('flags a first signer_seq other than 0 in a session as a gap, and accepts it (§7.4)', async () => {
    const host = new AuditHost('tenant-a', L2_CAPABILITY, { verifier: new OkVerifier(), clock: new MonotonicClock() });
    host.openSession(SESSION);
    const response = await host.handleAttempt(signed(makeAttempt(eventIdAt(1)), 42));
    expect(response.status).toBe('accept');
    expect(host.anomalies().map((a) => a.kind)).toEqual(['signer-seq-gap']);
  });

  it('does not move the replay bound on unavailable: the identical attempt is accepted (§7.1, §7.4)', async () => {
    const host = new AuditHost('tenant-a', L2_CAPABILITY, { verifier: new OkVerifier(), clock: new MonotonicClock() });
    host.openSession(SESSION);
    host.persistenceAvailable = false;
    const attempt = signed(makeAttempt(eventIdAt(1)), 0);
    expect((await host.handleAttempt(attempt)).status).toBe('unavailable');
    host.persistenceAvailable = true;
    expect((await host.handleAttempt(attempt)).status).toBe('accept');
    expect(host.anomalies()).toHaveLength(0);
  });

  it('seals the refusal of an unavailable attempt without a gap (§7.2, §7.4)', async () => {
    const host = new AuditHost('tenant-a', L2_CAPABILITY, { verifier: new OkVerifier(), clock: new MonotonicClock() });
    host.openSession(SESSION);
    host.persistenceAvailable = false;
    expect((await host.handleAttempt(signed(makeAttempt(eventIdAt(1)), 0))).status).toBe('unavailable');
    host.persistenceAvailable = true;
    await host.handleOutcome(signed(makeAttempt(eventIdAt(1), { outcome: 'aborted', reason: 'host-unavailable' }), 1));
    expect(host.anomalies()).toHaveLength(0);
    expect(host.records()).toHaveLength(1);
  });
});

describe('AuditHost.resume (§8.3)', () => {
  it('continues the persisted chain, seq, and replay state after a restart', async () => {
    const repo = new InMemoryLedgerRepository();
    const host = new AuditHost('tenant-a', undefined, { clock: new MonotonicClock(), repository: repo });
    host.openSession(SESSION);
    const attempt = makeAttempt(eventIdAt(1));
    await host.handleAttempt(attempt);
    await host.handleOutcome({ ...attempt, outcome: 'success' });

    const original = host.records()[0];
    const resumed = await AuditHost.resume('tenant-a', undefined, { clock: new MonotonicClock(), repository: repo });
    expect(resumed.digest()).toBe(host.digest());

    // The call in flight across the restart has ended as far as the new host knows (§6.3), and its
    // session, read back from the ledger, is never issued again.
    expect((await resumed.handleAttempt(attempt)).status).toBe('reject');
    expect(() => resumed.openSession(SESSION)).toThrow(/already issued/);
    expect(original?.seq).toBe(0);

    const next = await resumed.handleAttempt(makeAttempt(eventIdAt(2), { session_id: resumed.openSession() }));
    expect(next.status).toBe('accept');
    if (next.status === 'accept') {
      expect(next.seq).toBe(2);
    }
    expect(verifyLedger(await repo.readAll('tenant-a'), resumed.digest()).ok).toBe(true);
  });
});

describe('AuditHost.resume and the calls a restart ended (§6.3)', () => {
  it('records every attempt left without a terminal outcome as unresolved, and reopens no session', async () => {
    const repo = new InMemoryLedgerRepository();
    const host = new AuditHost('tenant-a', undefined, { clock: new MonotonicClock(), repository: repo });
    host.openSession(SESSION);
    const resolved = makeAttempt(eventIdAt(1));
    const pending = makeAttempt(eventIdAt(2));
    await host.handleAttempt(resolved);
    await host.handleOutcome({ ...resolved, outcome: 'success' });
    await host.handleAttempt(pending);
    expect(host.anomalies()).toEqual([]);

    const resumed = await AuditHost.resume('tenant-a', undefined, { clock: new MonotonicClock(), repository: repo });
    expect(resumed.anomalies()).toEqual([
      {
        id: eventIdAt(2),
        kind: 'unresolved-attempt',
        detail: `host restarted with attempt ${eventIdAt(2)} unresolved`,
      },
    ]);
    // The session is not open: its outcome arriving now is not sealed.
    const before = resumed.records().length;
    await resumed.handleOutcome({ ...pending, outcome: 'success' });
    expect(resumed.records()).toHaveLength(before);
  });
});

describe('an outcome that fails Level-2 validation (§6, §8.3)', () => {
  it('a forged outcome is not sealed and is flagged', async () => {
    // §6: the host cannot reject a notification, so the anomaly set is where the failure goes.
    let forged = false;
    const host = new AuditHost('tenant-a', L2_CAPABILITY, {
      verifier: { verify: async () => (forged ? 'signature-invalid' : null) },
      clock: new MonotonicClock(),
    });
    host.openSession(SESSION);
    const attempt = signed(makeAttempt(eventIdAt(1)), 0);
    await host.handleAttempt(attempt);
    forged = true;
    const before = host.records().length;
    await host.handleOutcome(signed({ ...attempt, outcome: 'success' }, 1));
    expect(host.records()).toHaveLength(before);
    expect(host.anomalies().map((a) => a.kind)).toEqual(['signature-invalid']);
  });

  it('a replayed outcome sequence is not sealed and is flagged', async () => {
    const host = new AuditHost('tenant-a', L2_CAPABILITY, {
      verifier: new OkVerifier(),
      clock: new MonotonicClock(),
    });
    host.openSession(SESSION);
    const attempt = signed(makeAttempt(eventIdAt(1)), 0);
    await host.handleAttempt(attempt);
    const before = host.records().length;
    await host.handleOutcome(signed({ ...attempt, outcome: 'success' }, 0));
    expect(host.records()).toHaveLength(before);
    expect(host.anomalies().some((a) => a.kind === 'replay-detected')).toBe(true);
  });
});

describe('the outcome channel’s remaining paths (§6, §10.8)', () => {
  it('an outcome with an uncanonicalizable number is dropped and flagged', async () => {
    // §8.1 applies on both channels, and §6 leaves the anomaly set as the only place to say so.
    const host = new AuditHost('tenant-a', undefined, { clock: new MonotonicClock() });
    host.openSession(SESSION);
    const attempt = makeAttempt(eventIdAt(1));
    await host.handleAttempt(attempt);
    const before = host.records().length;
    await host.handleOutcome({ ...attempt, outcome: 'success', action_context: { rows: 2 ** 53 } });
    expect(host.records()).toHaveLength(before);
    expect(host.anomalies().some((a) => a.kind === 'schema-invalid')).toBe(true);
  });

  it('a correlated outcome that cannot be persisted is lost, not flagged as tampering', async () => {
    // §10.8: a lost outcome is a completeness gap, and `internal-error` is not an anomaly kind.
    // The attempt must be sealed first, or the outcome lands on the orphan path instead and the
    // persistence failure is never reached.
    const repository = new FlakyRepository();
    const host = new AuditHost('tenant-a', undefined, { clock: new MonotonicClock(), repository });
    host.openSession(SESSION);
    const attempt = makeAttempt(eventIdAt(1));
    expect((await host.handleAttempt(attempt)).status).toBe('accept');
    repository.fail = true;
    const logged: unknown[] = [];
    const spy = vi.spyOn(console, 'error').mockImplementation((...args) => void logged.push(args[0]));
    await host.handleOutcome({ ...attempt, outcome: 'success' });
    spy.mockRestore();
    expect(host.records()).toHaveLength(1);
    expect(host.anomalies()).toHaveLength(0);
    expect(logged.join(' ')).toContain('could not persist');
  });

  it('does not advance the signer_seq tracker for an outcome it could not seal (§7.4)', async () => {
    // A lost outcome was received but not sealed, so the next value is neither a gap nor a replay.
    const repository = new FlakyRepository();
    const host = new AuditHost('tenant-a', L2_CAPABILITY, {
      verifier: new OkVerifier(),
      clock: new MonotonicClock(),
      repository,
    });
    host.openSession(SESSION);
    expect((await host.handleAttempt(signed(makeAttempt(eventIdAt(1)), 0))).status).toBe('accept');
    repository.fail = true;
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    await host.handleOutcome(signed({ ...makeAttempt(eventIdAt(1)), outcome: 'success' }, 1));
    spy.mockRestore();
    repository.fail = false;
    expect((await host.handleAttempt(signed(makeAttempt(eventIdAt(2)), 2))).status).toBe('accept');
    expect(host.anomalies()).toHaveLength(0);
  });

  it('an outcome after its attempt was rejected is an orphan (§7.2)', async () => {
    // The attempt is refused and the outcome is well-formed, which is the post-reject orphan the
    // never-accepted one rolls up with (§7.6): the finer distinction is a local detail.
    const verifier = {
      async verify(event: Record<string, unknown>) {
        return event.signature === 'forged' ? ('signature-invalid' as const) : null;
      },
    };
    const host = new AuditHost('tenant-a', L2_CAPABILITY, { verifier, clock: new MonotonicClock() });
    host.openSession(SESSION);
    const attempt = { ...signed(makeAttempt(eventIdAt(1)), 1), signature: 'forged' };
    expect((await host.handleAttempt(attempt)).status).toBe('reject');
    await host.handleOutcome(signed({ ...makeAttempt(eventIdAt(1)), outcome: 'success' }, 2));
    const orphan = host.anomalies().find((a) => a.kind === 'orphaned-outcome');
    expect(orphan).toBeDefined();
    expect(orphan?.detail).toContain('rejected id');
  });
});
