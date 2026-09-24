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
  signed,
} from './helpers';

function l1Host(): AuditHost {
  return new AuditHost('tenant-a', undefined, { clock: new MonotonicClock() });
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

  it('rejects a duplicate attempt id as replay-detected', async () => {
    const host = l1Host();
    const event = makeAttempt(eventIdAt(1));
    await host.handleAttempt(event);
    const response = await host.handleAttempt(event);
    expect(response.status).toBe('reject');
    if (response.status === 'reject') {
      expect(response.reason).toBe('replay-detected');
    }
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
      expect(response.retryable).toBe(true);
    }
  });

  it('returns retryable unavailable when the repository append fails', async () => {
    const host = new AuditHost('tenant-a', undefined, {
      clock: new MonotonicClock(),
      repository: new FailingRepository(),
    });
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
    expect(orphan?.detail).toContain('without accepted attempt');
  });

  it('exempts an aborted outcome for a never-accepted attempt (§10.4)', async () => {
    const host = l1Host();
    await host.handleOutcome(makeAttempt(eventIdAt(1), { outcome: 'aborted', reason: 'host-rejected' }));
    expect(host.records()).toHaveLength(0);
    expect(host.anomalies()).toHaveLength(0);
  });
});

describe('AuditHost Level 2 (§7.1, §7.4)', () => {
  it('requires a verifier at construction time', () => {
    expect(() => new AuditHost('tenant-a', L2_CAPABILITY)).toThrow(/SignatureVerifier/);
  });

  it('accepts a valid signed attempt', async () => {
    const host = new AuditHost('tenant-a', L2_CAPABILITY, { verifier: new OkVerifier(), clock: new MonotonicClock() });
    const response = await host.handleAttempt(signed(makeAttempt(eventIdAt(1)), 1));
    expect(response.status).toBe('accept');
  });

  it('rejects a forged signature as signature-invalid', async () => {
    const host = new AuditHost('tenant-a', L2_CAPABILITY, { verifier: new BadVerifier(), clock: new MonotonicClock() });
    const response = await host.handleAttempt(signed(makeAttempt(eventIdAt(1)), 1));
    expect(response.status).toBe('reject');
    if (response.status === 'reject') {
      expect(response.reason).toBe('signature-invalid');
    }
  });

  it('rejects an unsigned attempt under L2 as l2-unsigned', async () => {
    const host = new AuditHost('tenant-a', L2_CAPABILITY, { verifier: new OkVerifier(), clock: new MonotonicClock() });
    const response = await host.handleAttempt(makeAttempt(eventIdAt(1)));
    expect(response.status).toBe('reject');
    if (response.status === 'reject') {
      expect(response.reason).toBe('l2-unsigned');
    }
  });

  it('rejects a replayed signer_seq as replay-detected', async () => {
    const host = new AuditHost('tenant-a', L2_CAPABILITY, { verifier: new OkVerifier(), clock: new MonotonicClock() });
    await host.handleAttempt(signed(makeAttempt(eventIdAt(1)), 5));
    const response = await host.handleAttempt(signed(makeAttempt(eventIdAt(2)), 5));
    expect(response.status).toBe('reject');
    if (response.status === 'reject') {
      expect(response.reason).toBe('replay-detected');
    }
  });

  it('accepts but flags a forward signer_seq gap as signer-seq-gap', async () => {
    const host = new AuditHost('tenant-a', L2_CAPABILITY, { verifier: new OkVerifier(), clock: new MonotonicClock() });
    await host.handleAttempt(signed(makeAttempt(eventIdAt(1)), 1));
    const response = await host.handleAttempt(signed(makeAttempt(eventIdAt(2)), 3));
    expect(response.status).toBe('accept');
    expect(host.anomalies().some((a) => a.kind === 'signer-seq-gap')).toBe(true);
  });

  it('does not flag the first signer_seq observed as a gap (baseline)', async () => {
    const host = new AuditHost('tenant-a', L2_CAPABILITY, { verifier: new OkVerifier(), clock: new MonotonicClock() });
    const response = await host.handleAttempt(signed(makeAttempt(eventIdAt(1)), 42));
    expect(response.status).toBe('accept');
    expect(host.anomalies()).toHaveLength(0);
  });
});

describe('AuditHost.resume (§8.3)', () => {
  it('continues the persisted chain, seq, and replay state after a restart', async () => {
    const repo = new InMemoryLedgerRepository();
    const host = new AuditHost('tenant-a', undefined, { clock: new MonotonicClock(), repository: repo });
    const attempt = makeAttempt(eventIdAt(1));
    await host.handleAttempt(attempt);
    await host.handleOutcome({ ...attempt, outcome: 'success' });

    const resumed = await AuditHost.resume('tenant-a', undefined, { clock: new MonotonicClock(), repository: repo });
    expect(resumed.digest()).toBe(host.digest());

    // A replay of the pre-restart id is still caught.
    const replay = await resumed.handleAttempt(attempt);
    expect(replay.status).toBe('reject');

    const next = await resumed.handleAttempt(makeAttempt(eventIdAt(2)));
    expect(next.status).toBe('accept');
    if (next.status === 'accept') {
      expect(next.seq).toBe(2);
    }
    expect(verifyLedger(await repo.readAll('tenant-a'), resumed.digest()).ok).toBe(true);
  });
});

describe('an outcome that fails Level-2 validation (§6, §8.3)', () => {
  it('a forged outcome is not sealed and is flagged', async () => {
    // §6: the host cannot reject a notification, so the anomaly set is where the failure goes.
    const host = new AuditHost('tenant-a', L2_CAPABILITY, {
      verifier: new BadVerifier(),
      clock: new MonotonicClock(),
    });
    const attempt = signed(makeAttempt(eventIdAt(1)), 1);
    // The attempt is correlated by a host that accepted it, so the outcome has something to match.
    const accepting = new AuditHost('tenant-a', L2_CAPABILITY, {
      verifier: new OkVerifier(),
      clock: new MonotonicClock(),
    });
    await accepting.handleAttempt(attempt);
    await host.handleAttempt(attempt);
    const before = host.records().length;
    await host.handleOutcome(signed({ ...attempt, outcome: 'success' }, 2));
    expect(host.records()).toHaveLength(before);
    expect(host.anomalies().every((a) => a.kind === 'signature-invalid')).toBe(true);
  });

  it('a replayed outcome sequence is not sealed and is flagged', async () => {
    const host = new AuditHost('tenant-a', L2_CAPABILITY, {
      verifier: new OkVerifier(),
      clock: new MonotonicClock(),
    });
    const attempt = signed(makeAttempt(eventIdAt(1)), 5);
    await host.handleAttempt(attempt);
    const before = host.records().length;
    await host.handleOutcome(signed({ ...attempt, outcome: 'success' }, 5));
    expect(host.records()).toHaveLength(before);
    expect(host.anomalies().some((a) => a.kind === 'replay-detected')).toBe(true);
  });
});

describe('the outcome channel’s remaining paths (§6, §10.8)', () => {
  it('an outcome with an uncanonicalizable number is dropped and flagged', async () => {
    // §8.1 applies on both channels, and §6 leaves the anomaly set as the only place to say so.
    const host = new AuditHost('tenant-a', undefined, { clock: new MonotonicClock() });
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
    // A lost outcome was never sealed, so the per-key counter must still point at the last sealed
    // value; advancing it would make the tool's next honest signer_seq read as a replay.
    const repository = new FlakyRepository();
    const host = new AuditHost('tenant-a', L2_CAPABILITY, {
      verifier: new OkVerifier(),
      clock: new MonotonicClock(),
      repository,
    });
    expect((await host.handleAttempt(signed(makeAttempt(eventIdAt(1)), 1))).status).toBe('accept');
    repository.fail = true;
    const spy = vi.spyOn(console, 'error').mockImplementation(() => {});
    await host.handleOutcome(signed({ ...makeAttempt(eventIdAt(1)), outcome: 'success' }, 2));
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
    const attempt = { ...signed(makeAttempt(eventIdAt(1)), 1), signature: 'forged' };
    expect((await host.handleAttempt(attempt)).status).toBe('reject');
    await host.handleOutcome(signed({ ...makeAttempt(eventIdAt(1)), outcome: 'success' }, 2));
    const orphan = host.anomalies().find((a) => a.kind === 'orphaned-outcome');
    expect(orphan).toBeDefined();
    expect(orphan?.detail).toContain('rejected id');
  });
});
