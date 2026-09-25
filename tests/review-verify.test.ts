/** Ledger verification revised in v0.3's adversarial review (§7.6, §10.10, §11.4). */

import { describe, expect, it } from 'vitest';
import { AuditHost } from '../src/host';
import {
  CountersignatureRegistryVerifier,
  Ed25519Countersigner,
  generateToolKey,
  KeyRegistry,
  KeyRole,
  SignatureAlgorithm,
} from '../src/l2';
import { Ledger, type SealedRecord } from '../src/ledger';
import { Countersign, Level, SPEC_VERSION } from '../src/models';
import { unaccountedSignerSeq, verifyLedger } from '../src/verify';
import { eventIdAt, MonotonicClock, makeAttempt, SESSION, signed } from './helpers';

const OTHER_SESSION = '0198f3a2-5c1e-7000-8000-00000000abc1';

function chain(events: Record<string, unknown>[]): SealedRecord[] {
  const ledger = new Ledger('tenant-a');
  const clock = new MonotonicClock();
  return events.map((event) => ledger.append(event, clock.now()));
}

function kinds(
  records: SealedRecord[],
  ...rest: Parameters<typeof verifyLedger> extends [unknown, ...infer R] ? R : never
): string[] {
  return verifyLedger(records, ...rest).issues.map((issue) => issue.kind);
}

describe('a malformed sealed record is a finding, never a throw (§11.4)', () => {
  it('an out-of-domain number is schema-invalid and the chain is checked on either side', () => {
    const records = chain([makeAttempt(eventIdAt(1)), makeAttempt(eventIdAt(2)), makeAttempt(eventIdAt(3))]);
    const poisoned = records.map((record, index) =>
      index === 1 ? { ...record, event: { ...record.event, action_context: { n: 2 ** 60 } } } : record,
    );
    const tampered = poisoned.map((record, index) =>
      index === 2 ? { ...record, event: { ...record.event, action_type: 'db.drop' } } : record,
    );
    expect(() => verifyLedger(tampered)).not.toThrow();
    const issues = verifyLedger(tampered).issues;
    expect(issues.filter((issue) => issue.kind === 'schema-invalid').map((issue) => issue.seq)).toEqual([1]);
    expect(issues.filter((issue) => issue.kind === 'record-hash-mismatch').map((issue) => issue.seq)).toEqual([2]);
  });

  it('a lone surrogate is schema-invalid', () => {
    const [record] = chain([makeAttempt(eventIdAt(1))]);
    const broken = { ...(record as SealedRecord), event: { ...(record as SealedRecord).event, action_type: '\uD800' } };
    expect(() => verifyLedger([broken])).not.toThrow();
    expect(kinds([broken])).toEqual(['schema-invalid']);
  });
});

describe('a record of an earlier version is read in its own shape (§11.4)', () => {
  it('a 0.2 record with call_id and a standard-base64 signature is not schema-invalid', () => {
    const { session_id: _session, ...rest } = makeAttempt(eventIdAt(1));
    const earlier = {
      ...rest,
      spec_version: 'auditable-mcp/0.2',
      call_id: 'call-1',
      key_id: 'k1',
      signer_seq: 0,
      signature: 'c2lnbg==',
    };
    expect(kinds(chain([earlier]), undefined, undefined, undefined, undefined, () => true)).toEqual([]);
    expect(kinds(chain([{ ...earlier, spec_version: SPEC_VERSION }]))).toContain('schema-invalid');
  });
});

describe('Level-2 findings keyed by key and session (§11.4)', () => {
  it('two sealed records sharing one signer_seq are replay-detected', () => {
    const records = chain([
      signed(makeAttempt(eventIdAt(1)), 0),
      signed(makeAttempt(eventIdAt(2)), 0),
      signed(makeAttempt(eventIdAt(3), { session_id: OTHER_SESSION }), 0),
    ]);
    const report = verifyLedger(records, undefined, undefined, undefined, undefined, () => true);
    expect(report.issues.filter((issue) => issue.kind === 'replay-detected').map((issue) => issue.seq)).toEqual([1]);
  });

  it('a refusal is not accounted away by an attempt of another session with the same id', () => {
    const events = [
      signed(makeAttempt(eventIdAt(1), { session_id: OTHER_SESSION }), 0),
      // Session SESSION: signer_seq 0 was a rejected attempt of operation 1, refused at 1.
      signed(makeAttempt(eventIdAt(1), { outcome: 'aborted', reason: 'host-rejected' }), 1),
    ];
    expect(unaccountedSignerSeq(events)).toEqual([]);
    expect(kinds(chain(events), undefined, undefined, undefined, undefined, () => true)).toEqual([]);
  });

  it('an outcome correlates only to an attempt of its own session', () => {
    const records = chain([
      makeAttempt(eventIdAt(1), { session_id: OTHER_SESSION }),
      makeAttempt(eventIdAt(1), { outcome: 'success' }),
    ]);
    expect(kinds(records)).toEqual(['orphaned-outcome']);
  });
});

describe('identity bound by the countersignature log_id (§10.10)', () => {
  async function countersigned(logId: string): Promise<{ records: SealedRecord[]; registry: KeyRegistry }> {
    const hostKey = generateToolKey('host-1');
    const registry = new KeyRegistry(KeyRole.HOST);
    registry.register(hostKey.keyId, hostKey.publicKey, SignatureAlgorithm.ED25519);
    const host = new AuditHost(
      'tenant-a',
      { spec_version: SPEC_VERSION, level: Level.L1, attempt: 'request', countersign: Countersign.HOST },
      {
        clock: new MonotonicClock(),
        logId,
        countersigner: new Ed25519Countersigner(hostKey.keyId, hostKey.privateKey),
      },
    );
    host.openSession(SESSION);
    await host.handleAttempt(makeAttempt(eventIdAt(1)));
    return { records: host.records(), registry };
  }

  const identity = (logId: string, ...hostKeyIds: string[]) => ({
    expectedIdentity: { logId, hostKeyIds: new Set(hostKeyIds) },
  });

  it('a record under the expected log_id and key passes; another log_id is principal-mismatch', async () => {
    const { records, registry } = await countersigned('tenant-a');
    const check = new CountersignatureRegistryVerifier(registry).check;
    expect(kinds(records, undefined, undefined, undefined, check, undefined, identity('tenant-a', 'host-1'))).toEqual(
      [],
    );
    expect(kinds(records, undefined, undefined, undefined, check, undefined, identity('tenant-b', 'host-1'))).toEqual([
      'principal-mismatch',
    ]);
  });

  it('the same log_id under a key the partition does not countersign under is principal-mismatch', async () => {
    const { records, registry } = await countersigned('tenant-a');
    const check = new CountersignatureRegistryVerifier(registry).check;
    expect(kinds(records, undefined, undefined, undefined, check, undefined, identity('tenant-a', 'host-2'))).toEqual([
      'principal-mismatch',
    ]);
  });

  it('an uncountersigned record is principal-mismatch; a failing countersignature is host-signature-invalid', async () => {
    const { records, registry } = await countersigned('tenant-a');
    const check = new CountersignatureRegistryVerifier(registry).check;
    const bare = chain([makeAttempt(eventIdAt(1))]);
    expect(kinds(bare, undefined, undefined, undefined, check, undefined, identity('tenant-a', 'host-1'))).toEqual([
      'principal-mismatch',
    ]);
    const forged = records.map((record) => ({ ...record, host_signature: 'AAAA' }));
    expect(kinds(forged, undefined, undefined, undefined, check, undefined, identity('tenant-a', 'host-1'))).toEqual([
      'host-signature-invalid',
    ]);
  });

  it('a record that cannot be canonicalized is still compared against the identity', async () => {
    const { records, registry } = await countersigned('tenant-a');
    const check = new CountersignatureRegistryVerifier(registry).check;
    const broken = records.map((record) => ({ ...record, event: { ...record.event, action_type: '\uD800' } }));
    expect(
      kinds(broken, undefined, undefined, undefined, check, undefined, identity('tenant-b', 'host-1')).sort(),
    ).toEqual(['principal-mismatch', 'schema-invalid']);
  });
});

describe('a countersignature required out-of-band (§11.4)', () => {
  it('an uncountersigned record is host-signature-invalid only when the chain must be countersigned', () => {
    const bare = chain([makeAttempt(eventIdAt(1)), makeAttempt(eventIdAt(1), { outcome: 'success' })]);
    expect(kinds(bare)).toEqual([]);
    expect(
      kinds(bare, undefined, undefined, undefined, undefined, undefined, { countersignatureRequired: true }),
    ).toEqual(['host-signature-invalid', 'host-signature-invalid']);
  });
});

describe('a chain whose versions go backwards (§11.4)', () => {
  it('a 0.2 record sealed after a 0.3 record is schema-invalid; the other way round is not', () => {
    const { session_id: _session, ...rest } = makeAttempt(eventIdAt(2));
    const earlier = { ...rest, spec_version: 'auditable-mcp/0.2', call_id: 'call-1' };
    const current = makeAttempt(eventIdAt(1));
    const regressed = verifyLedger(chain([current, earlier])).issues;
    expect(regressed.map((issue) => [issue.seq, issue.kind])).toEqual([[1, 'schema-invalid']]);
    expect(kinds(chain([earlier, current]))).toEqual([]);
  });
});

describe('correlation counts only attempts sealed before the outcome (§7.2, §11.4)', () => {
  it('a success sealed before its attempt is orphaned-outcome', () => {
    const records = chain([makeAttempt(eventIdAt(1), { outcome: 'success' }), makeAttempt(eventIdAt(1))]);
    expect(kinds(records)).toEqual(['orphaned-outcome']);
  });

  it('a refusal sealed before an attempt with its id still accounts for a missing value', () => {
    const events = [
      signed(makeAttempt(eventIdAt(2)), 0),
      signed(makeAttempt(eventIdAt(1), { outcome: 'aborted', reason: 'host-rejected' }), 2),
      signed(makeAttempt(eventIdAt(1)), 3),
    ];
    expect(unaccountedSignerSeq(events)).toEqual([]);
  });
});

describe('records sealed before v0.3 keep their own correlation (§11.4)', () => {
  function earlier(id: number, callId: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
    const { session_id: _session, ...rest } = makeAttempt(eventIdAt(id));
    return { ...rest, spec_version: 'auditable-mcp/0.2', call_id: callId, ...extra };
  }

  it('an outcome correlates to the attempt of its call_id', () => {
    const paired = chain([earlier(1, 'call-1'), earlier(1, 'call-1', { outcome: 'success' })]);
    expect(kinds(paired)).toEqual([]);
    const crossed = chain([earlier(1, 'call-1'), earlier(1, 'call-2', { outcome: 'success' })]);
    expect(kinds(crossed)).toEqual(['orphaned-outcome']);
  });

  it('is left out of the per-session replay and accounting checks', () => {
    const numbered = { key_id: 'k1', signature: 'c2lnbg==' };
    const records = chain([
      earlier(1, 'call-1', { ...numbered, signer_seq: 0 }),
      earlier(2, 'call-2', { ...numbered, signer_seq: 0 }),
      earlier(3, 'call-3', { ...numbered, signer_seq: 5 }),
    ]);
    expect(kinds(records, undefined, undefined, undefined, undefined, () => true)).toEqual([]);
    expect(unaccountedSignerSeq(records.map((record) => record.event))).toEqual([]);
  });
});
