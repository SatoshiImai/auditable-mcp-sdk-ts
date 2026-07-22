import { describe, expect, it } from 'vitest';
import { AuditHost } from '../src/host';
import { InMemoryLedgerRepository } from '../src/storage';
import { verifyLedger } from '../src/verify';
import {
  BadVerifier,
  eventIdAt,
  FailingRepository,
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
    expect(host.anomalies().some((a) => a.kind === 'orphaned-outcome')).toBe(true);
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
