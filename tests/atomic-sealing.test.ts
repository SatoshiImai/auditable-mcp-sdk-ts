/** Tests for §7.1 atomic sealing, mirroring the Python SDK's suite. */

import { describe, expect, it } from 'vitest';
import { AuditHost } from '../src/host';
import type { SealedRecord } from '../src/ledger';
import { type AuditCapability, Level, SPEC_VERSION, Witness } from '../src/models';
import { verifyLedger } from '../src/verify';

const CAPABILITY: AuditCapability = {
  spec_version: SPEC_VERSION,
  level: Level.L1,
  attempt: 'request',
  witness: Witness.NONE,
};
const WITNESSING: AuditCapability = { ...CAPABILITY, witness: Witness.HOST };
const CONCURRENT = 5;

/** A store that yields to the event loop before it writes, as any real one does. */
class SlowRepository {
  rows: SealedRecord[] = [];
  async append(_partition: string, record: SealedRecord): Promise<void> {
    await Promise.resolve();
    this.rows.push(record);
  }
  async loadTail(): Promise<SealedRecord | null> {
    return null;
  }
  async readAll(): Promise<SealedRecord[]> {
    return [...this.rows];
  }
}

/** A witness signer that yields to the event loop, as an HSM or KMS client does. */
class SlowSigner {
  readonly keyId = 'host-key-1';
  async sign(): Promise<string> {
    await Promise.resolve();
    return 'AAAA';
  }
}

function attempt(n: number): Record<string, unknown> {
  return {
    id: `00000000-0000-4000-8000-${n.toString(16).padStart(12, '0')}`,
    spec_version: SPEC_VERSION,
    ts: '2026-07-15T00:00:01.000Z',
    call_id: 'call_abc',
    action_type: 'db.read',
    mutates: false,
    egress: false,
    target_resource: { kind: 'table', ref: 'customers' },
    outcome: 'attempted',
  };
}

async function sealConcurrently(host: AuditHost, count = CONCURRENT): Promise<SealedRecord[]> {
  await Promise.all(Array.from({ length: count }, (_, i) => host.handleAttempt(attempt(i + 1))));
  return host.records();
}

/** Every §7.1 consequence of atomic sealing, read off the ledger. */
function expectChainHolds(records: SealedRecord[]): void {
  expect(records).toHaveLength(CONCURRENT);
  const seqs = records.map((record) => record.seq);
  expect(seqs).toEqual([...seqs].sort((a, b) => a - b));
  expect(new Set(seqs).size).toBe(CONCURRENT);
  expect(new Set(records.map((record) => record.previous_hash)).size).toBe(CONCURRENT);
  expect(verifyLedger(records).ok).toBe(true);
}

describe('atomic sealing (§7.1)', () => {
  it('a durable host seals concurrent attempts atomically', async () => {
    const host = new AuditHost('tenant-a', CAPABILITY, { repository: new SlowRepository() });
    expectChainHolds(await sealConcurrently(host));
  });

  it('a witnessing host seals concurrent attempts atomically', async () => {
    const host = new AuditHost('tenant-a', WITNESSING, { witnessSigner: new SlowSigner() });
    expectChainHolds(await sealConcurrently(host));
  });

  it('an in-memory host seals concurrent attempts atomically', async () => {
    expectChainHolds(await sealConcurrently(new AuditHost('tenant-a', CAPABILITY)));
  });

  it('concurrent duplicates do not both pass the uniqueness check', async () => {
    const host = new AuditHost('tenant-a', CAPABILITY, { repository: new SlowRepository() });
    const event = attempt(1);
    const responses = await Promise.all(Array.from({ length: CONCURRENT }, () => host.handleAttempt({ ...event })));
    expect(responses.filter((response) => response.status === 'accept')).toHaveLength(1);
    expect(
      responses
        .filter((response) => response.status === 'reject')
        .every((response) => response.reason === 'replay-detected'),
    ).toBe(true);
    expect(host.records()).toHaveLength(1);
  });

  it('partitions are not serialized against each other', async () => {
    const hosts = [0, 1, 2].map((n) => new AuditHost(`tenant-${n}`, CAPABILITY, { repository: new SlowRepository() }));
    await Promise.all(hosts.map((host) => sealConcurrently(host)));
    for (const host of hosts) {
      expectChainHolds(host.records());
    }
  });

  it.each(['success', 'failed'])('outcomes seal into the same chain atomically (%s)', async (outcome) => {
    const host = new AuditHost('tenant-a', CAPABILITY, { repository: new SlowRepository() });
    await sealConcurrently(host);
    await Promise.all(Array.from({ length: CONCURRENT }, (_, i) => host.handleOutcome({ ...attempt(i + 1), outcome })));
    const records = host.records();
    expect(records).toHaveLength(CONCURRENT * 2);
    expect(new Set(records.map((record) => record.seq)).size).toBe(CONCURRENT * 2);
    expect(verifyLedger(records).ok).toBe(true);
  });
});
